//! `SQLCipher` at-rest decryption → a plaintext `SQLite` byte stream the reader
//! ([`crate::Database::open`]) consumes unchanged.
//!
//! # What `SQLCipher` does (and how we undo it)
//!
//! A `SQLCipher` database is an ordinary page-structured `SQLite` file whose every
//! page is encrypted with **AES-256-CBC** and authenticated with a per-page
//! **HMAC**. The first 16 bytes of the file are a random **salt** (in place of
//! the `SQLite format 3\0` magic). Key material is derived with **`PBKDF2`**:
//!
//! - encryption key: `PBKDF2(passphrase, salt, kdf_iter, 32)` — or a raw 32-byte
//!   key used directly (`PRAGMA key = "x'<64 hex>'"`);
//! - HMAC key: `PBKDF2(encryption_key, salt ^ 0x3a, 2, 32)`.
//!
//! Each page's tail holds `[ IV(16) | HMAC | padding ]` occupying `reserve`
//! bytes. The HMAC authenticates `ciphertext || IV || page_no_le32`. Page 1's
//! first 16 bytes (the salt) are not encrypted; on decrypt we prepend the
//! standard magic to reconstruct a valid plaintext page 1. The plaintext header
//! carries `SQLCipher`'s own reserved-space byte, so the reader computes the
//! correct usable size with no further help.
//!
//! # Version detection
//!
//! The two shipped profiles are the `SQLCipher` v4 and v3 defaults; they differ in
//! `PBKDF2`/HMAC digest (SHA-512 vs SHA-1), iteration count, default page size, and
//! reserve. Because nothing in the header is readable before decryption, the
//! version is detected by **HMAC verification on page 1**: the first profile whose
//! page-1 tag matches the derived key is the correct one. A wrong key/parameters
//! matches no profile and fails loud ([`DecryptError::KeyOrParametersMismatch`]) —
//! never a silent wrong-output.
//!
//! # Crypto provenance
//!
//! Every primitive is an audited `RustCrypto` crate (`pbkdf2`, `hmac`, `sha1`,
//! `sha2`, `aes`, `cbc`). Nothing here is hand-rolled.

use aes::Aes256;
use cipher::block_padding::NoPadding;
use cipher::{BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha512;

/// Per-file random salt length, and the length of page 1's plaintext magic.
const SALT_LEN: usize = 16;
/// AES-CBC initialization-vector length (one block).
const IV_LEN: usize = 16;
/// AES-256 key length.
const KEY_LEN: usize = 32;
/// XOR mask applied to the salt to derive the HMAC-key salt (`SQLCipher`
/// `HMAC_SALT_MASK`).
const HMAC_SALT_MASK: u8 = 0x3a;
/// `PBKDF2` iterations for the HMAC-key derivation (`SQLCipher` `FAST_PBKDF2`).
const HMAC_KDF_ITER: u32 = 2;
/// The 16-byte header every plaintext `SQLite` file begins with.
const SQLITE_MAGIC: &[u8; SALT_LEN] = b"SQLite format 3\x00";

type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// The key supplied by the caller.
///
/// Secure-by-design: the two shapes are distinct types, so a raw key can never be
/// mistaken for a passphrase (which would silently `PBKDF2`-stretch 32 random bytes
/// and fail to decrypt).
#[derive(Clone)]
pub enum SqlCipherKey {
    /// A user passphrase (`PRAGMA key = 'passphrase'`); the encryption key is
    /// `PBKDF2`-derived from it and the database's per-file salt.
    Passphrase(Vec<u8>),
    /// A raw 32-byte key (`PRAGMA key = "x'<64 hex>'"`), used directly as the
    /// AES-256 key. The salt for HMAC-key derivation still comes from the file.
    RawKey([u8; KEY_LEN]),
}

/// The `SQLCipher` default profile detected for a database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlCipherVersion {
    /// `SQLCipher` 4 defaults: `PBKDF2`/HMAC-SHA512, 256 000 iterations, 4096-byte
    /// pages, 80-byte reserve.
    V4,
    /// `SQLCipher` 3 defaults (or `cipher_compatibility = 3`): `PBKDF2`/HMAC-SHA1,
    /// 64 000 iterations, 1024-byte pages, 48-byte reserve.
    V3,
}

/// Why decryption could not proceed. Every variant is a loud, recoverable
/// failure — decryption never panics and never emits plausible-but-wrong bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptError {
    /// The input is smaller than the 16-byte salt — not a `SQLCipher` file.
    TooSmall,
    /// No shipped profile's page-1 HMAC verified: the key is wrong, or the
    /// database uses non-default cipher parameters this decryptor does not model.
    KeyOrParametersMismatch,
    /// A page past page 1 failed HMAC authentication after page 1 verified —
    /// consistent with tampering or corruption of an otherwise-valid database.
    /// Carries the 1-based page number (show-the-offending-value).
    PageAuthFailed(u32),
    /// The file holds more pages than a 32-bit page number can address.
    TooLarge,
}

/// A decrypted database: the reconstructed plaintext bytes plus the profile that
/// decrypted them.
pub struct Decrypted {
    /// A valid, standalone plaintext `SQLite` file — feed straight to
    /// [`crate::Database::open`].
    pub plaintext: Vec<u8>,
    /// The `SQLCipher` profile that authenticated the pages.
    pub version: SqlCipherVersion,
    /// Logical page size in bytes.
    pub page_size: u32,
}

/// The `PBKDF2`/HMAC digest a profile uses.
#[derive(Clone, Copy)]
enum Prf {
    Sha1,
    Sha512,
}

/// A fully-specified `SQLCipher` cipher configuration.
struct Profile {
    version: SqlCipherVersion,
    page_size: usize,
    kdf_iter: u32,
    prf: Prf,
    /// Bytes reserved at the end of each page for `IV || HMAC || padding`.
    reserve: usize,
    /// HMAC tag length (SHA-1 → 20, SHA-512 → 64).
    hmac_len: usize,
}

/// The shipped default profiles, tried in order. v4 first (the modern default).
const PROFILES: [Profile; 2] = [
    Profile {
        version: SqlCipherVersion::V4,
        page_size: 4096,
        kdf_iter: 256_000,
        prf: Prf::Sha512,
        reserve: 80,
        hmac_len: 64,
    },
    Profile {
        version: SqlCipherVersion::V3,
        page_size: 1024,
        kdf_iter: 64_000,
        prf: Prf::Sha1,
        reserve: 48,
        hmac_len: 20,
    },
];

/// `PBKDF2` into `out`, selecting the PRF digest. Infallible; `out` is any length.
fn pbkdf2(prf: Prf, password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) {
    match prf {
        Prf::Sha1 => pbkdf2::pbkdf2_hmac::<Sha1>(password, salt, rounds, out),
        Prf::Sha512 => pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, rounds, out),
    }
}

/// Constant-time HMAC check of `data_a || data_b` against `tag`. Returns `false`
/// (never panics) on any key/length issue.
fn hmac_ok(prf: Prf, key: &[u8], data_a: &[u8], data_b: &[u8], tag: &[u8]) -> bool {
    match prf {
        Prf::Sha1 => {
            let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(key) else {
                return false; // cov:unreachable: HMAC accepts any key length
            };
            mac.update(data_a);
            mac.update(data_b);
            mac.verify_slice(tag).is_ok()
        }
        Prf::Sha512 => {
            let Ok(mut mac) = Hmac::<Sha512>::new_from_slice(key) else {
                return false; // cov:unreachable: HMAC accepts any key length
            };
            mac.update(data_a);
            mac.update(data_b);
            mac.verify_slice(tag).is_ok()
        }
    }
}

/// The encryption key and HMAC key for one profile + supplied key + file salt.
fn derive_keys(
    profile: &Profile,
    key: &SqlCipherKey,
    salt: &[u8],
) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let mut enc = [0u8; KEY_LEN];
    match key {
        SqlCipherKey::Passphrase(pw) => pbkdf2(profile.prf, pw, salt, profile.kdf_iter, &mut enc),
        SqlCipherKey::RawKey(k) => enc.copy_from_slice(k),
    }
    let mut hmac_salt = [0u8; SALT_LEN];
    for (dst, &s) in hmac_salt.iter_mut().zip(salt.iter()) {
        *dst = s ^ HMAC_SALT_MASK;
    }
    let mut hmac_key = [0u8; KEY_LEN];
    pbkdf2(profile.prf, &enc, &hmac_salt, HMAC_KDF_ITER, &mut hmac_key);
    (enc, hmac_key)
}

/// Byte spans within one on-disk page for a given profile and page number.
/// `None` when the page is too short for its own reserve (crafted / truncated).
struct PageLayout {
    /// Where the encrypted region starts (16 on page 1 to skip the salt, else 0).
    start: usize,
    /// Where the IV starts (`page_size - reserve`).
    iv_start: usize,
}

impl PageLayout {
    fn for_page(profile: &Profile, pgno: u32) -> Option<Self> {
        let iv_start = profile.page_size.checked_sub(profile.reserve)?;
        let start = if pgno == 1 { SALT_LEN } else { 0 };
        // Room for at least the ciphertext, the IV, and the HMAC tag.
        if iv_start < start || iv_start.checked_add(IV_LEN + profile.hmac_len)? > profile.page_size
        {
            return None;
        }
        Some(Self { start, iv_start })
    }
}

/// Verify one page's HMAC without decrypting it (used for version detection).
fn page_hmac_ok(profile: &Profile, hmac_key: &[u8], page: &[u8], pgno: u32) -> bool {
    let Some(layout) = PageLayout::for_page(profile, pgno) else {
        return false;
    };
    let (Some(auth_region), Some(tag)) = (
        page.get(layout.start..layout.iv_start + IV_LEN),
        page.get(layout.iv_start + IV_LEN..layout.iv_start + IV_LEN + profile.hmac_len),
    ) else {
        return false; // cov:unreachable: PageLayout bounds already guarantee these
    };
    hmac_ok(profile.prf, hmac_key, auth_region, &pgno.to_le_bytes(), tag)
}

/// Authenticate and decrypt one page, returning the reconstructed plaintext page.
/// `None` on any authentication or bounds failure (panic-free).
fn decrypt_page(
    profile: &Profile,
    enc_key: &[u8; KEY_LEN],
    hmac_key: &[u8],
    page: &[u8],
    pgno: u32,
) -> Option<Vec<u8>> {
    let layout = PageLayout::for_page(profile, pgno)?;
    let iv = page.get(layout.iv_start..layout.iv_start + IV_LEN)?;
    let ciphertext = page.get(layout.start..layout.iv_start)?;
    let auth_region = page.get(layout.start..layout.iv_start + IV_LEN)?;
    let tag = page.get(layout.iv_start + IV_LEN..layout.iv_start + IV_LEN + profile.hmac_len)?;
    let tail = page.get(layout.iv_start..profile.page_size)?;

    if !hmac_ok(profile.prf, hmac_key, auth_region, &pgno.to_le_bytes(), tag) {
        return None;
    }
    if ciphertext.len() % IV_LEN != 0 {
        return None; // cov:unreachable: a valid SQLCipher page is block-aligned
    }

    let dec = Aes256CbcDec::new_from_slices(enc_key, iv).ok()?;
    let mut buf = ciphertext.to_vec();
    let plain = dec.decrypt_padded_mut::<NoPadding>(&mut buf).ok()?;

    let mut out = Vec::with_capacity(profile.page_size);
    if pgno == 1 {
        out.extend_from_slice(SQLITE_MAGIC);
    }
    out.extend_from_slice(plain);
    out.extend_from_slice(tail);
    Some(out)
}

/// Decrypt every page under an already-selected profile.
fn decrypt_all(
    profile: &Profile,
    enc_key: &[u8; KEY_LEN],
    hmac_key: &[u8],
    ciphertext: &[u8],
) -> Result<Decrypted, DecryptError> {
    let page_count = ciphertext.len() / profile.page_size;
    let mut out = Vec::with_capacity(page_count * profile.page_size);
    for i in 0..page_count {
        let pgno = u32::try_from(i + 1).map_err(|_| DecryptError::TooLarge)?;
        let start = i * profile.page_size;
        let end = start + profile.page_size;
        let page = ciphertext
            .get(start..end)
            .ok_or(DecryptError::PageAuthFailed(pgno))?;
        let plain = decrypt_page(profile, enc_key, hmac_key, page, pgno)
            .ok_or(DecryptError::PageAuthFailed(pgno))?;
        out.extend_from_slice(&plain);
    }
    Ok(Decrypted {
        plaintext: out,
        version: profile.version,
        page_size: u32::try_from(profile.page_size).unwrap_or(u32::MAX),
    })
}

/// Decrypt a `SQLCipher` database into a plaintext `SQLite` byte stream, detecting
/// the cipher version by page-1 HMAC verification.
///
/// Returns [`DecryptError::KeyOrParametersMismatch`] if the key is wrong or the
/// database uses cipher parameters outside the shipped v4/v3 defaults — a loud
/// failure, never a silent wrong plaintext.
pub fn decrypt(ciphertext: &[u8], key: &SqlCipherKey) -> Result<Decrypted, DecryptError> {
    if ciphertext.len() < SALT_LEN {
        return Err(DecryptError::TooSmall);
    }
    let salt = &ciphertext[..SALT_LEN];
    for profile in &PROFILES {
        if ciphertext.len() < profile.page_size || ciphertext.len() % profile.page_size != 0 {
            continue;
        }
        let (enc_key, hmac_key) = derive_keys(profile, key, salt);
        let Some(page1) = ciphertext.get(..profile.page_size) else {
            continue; // cov:unreachable: length checked above
        };
        if page_hmac_ok(profile, &hmac_key, page1, 1) {
            return decrypt_all(profile, &enc_key, &hmac_key, ciphertext);
        }
    }
    Err(DecryptError::KeyOrParametersMismatch)
}
