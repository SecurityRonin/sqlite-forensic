# 10. SQLCipher decryption as a reader capability

Date: 2026-07-28
Status: Accepted (supersedes the "decryption out of scope" consequence of ADR 0009)

## Context

ADR 0009 detected and *named* SQLCipher/SEE/checksum-VFS reserved space but left
encrypted databases unreadable. The DLEAPP workflow supplies a key (a passphrase,
or a raw 32-byte key extracted from a keychain), so the missing piece is turning
ciphertext + key into the plaintext byte stream the existing reader already
consumes — not a new parser.

A SQLCipher file is an ordinary page-structured SQLite database whose every page
is AES-256-CBC encrypted and per-page HMAC-authenticated, with a random 16-byte
salt in place of the `SQLite format 3\0` magic and PBKDF2-derived keys. Undoing
that is a decrypt-to-stream (container-level) concern, not anomaly analysis.

## Decision

- **Home: `sqlite-core` (the reader), module `sqlcipher`.** Decryption produces a
  standalone plaintext SQLite `Vec<u8>` that `Database::open` reads unchanged; the
  idiomatic, secure-by-default seam is one call, `Database::open_encrypted(bytes,
  key)`. A third-party consumer of the reader gets encrypted-DB support without the
  analyzer. The decrypted plaintext carries SQLCipher's own reserved-space header
  byte, so the reader computes usable size with no extra plumbing.
- **RustCrypto only, never hand-rolled** (`pbkdf2`/`hmac`/`sha1`/`sha2`/`aes`/`cbc`
  + `cipher`), per the fleet crypto law. These are low-MSRV, keeping `sqlite-core`
  on `rust-version = 1.80`.
- **Two typed key shapes** (`SqlCipherKey::Passphrase` / `RawKey`) so a raw key can
  never be silently PBKDF2-stretched as a passphrase (secure-by-design).
- **Version by page-1 HMAC verification.** The shipped v4 and v3 default profiles
  differ in PBKDF2/HMAC digest, iterations, page size, and reserve. Nothing in the
  header is readable pre-decryption, so the correct profile is the one whose page-1
  HMAC tag verifies against the derived key — the same auto-detect real tools use.
- **Fail loud, never misread.** A wrong key / unsupported parameters matches no
  profile and returns `DecryptError::KeyOrParametersMismatch`; a later page failing
  authentication after page 1 verified returns `PageAuthFailed(pgno)`. No path emits
  plausible-but-wrong plaintext, and the decryptor is panic-free on crafted input.

## Consequences

- Encrypted evidence databases are now readable end-to-end; the reserved-space
  *naming* from ADR 0009 stays as the detection front door.
- Validation is Tier-2: the fixtures under `tests/data/sqlcipher/` are minted by the
  independent SQLCipher 4.17 CLI, and `core/tests/sqlcipher_oracle.rs` requires our
  RustCrypto output to reproduce that engine's plaintext, read back to known rows.
- Scope is the common v4 defaults + v3 compatibility. Non-default cipher settings
  (custom `cipher_page_size`, `kdf_iter`, HMAC algorithm, or plaintext-header bytes)
  are a loud mismatch, not a silent miss — an additive profile list extends coverage
  without touching the seam.
