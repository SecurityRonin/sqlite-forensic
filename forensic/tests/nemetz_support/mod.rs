//! Support for `nemetz_metrics.rs`: a dependency-free reader for the committed
//! Nemetz ground-truth manifest plus the row-normalization used to match a
//! carved record against the answer key.
//!
//! The workspace deliberately carries no serde/JSON dependency (it is a lean,
//! fleet-internal parser crate), so this module includes a minimal JSON-subset
//! parser sufficient for the manifest `gen_ground_truth.py` emits. The manifest
//! is ASCII-escaped-free UTF-8 with only `\"`, `\\`, `\n`, `\t`, `\r` and `\uXXXX`
//! escapes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic, dead_code)]

use std::sync::OnceLock;

// --- normalization -----------------------------------------------------------

/// Join a row's already-stringified cells into a single comparison key.
///
/// The separator is a control byte that cannot occur in the corpus's decimal /
/// text content, so distinct column boundaries never collide. This is the single
/// choke point both the answer-key rows and the carved rows pass through, so any
/// future normalization (trimming, case, encoding) stays symmetric by
/// construction.
#[must_use]
pub fn normalize_row(cells: &[String]) -> String {
    // The answer-key row content and the carved row's decoded values both pass
    // through here, so the comparison is symmetric by construction: the carver
    // side stringifies a `Value` to the same shape the corpus's CSV/XML export
    // uses (integers in decimal, reals at 5 dp, text verbatim, NULL as empty),
    // and this join supplies the only column-boundary delimiter both sides share.
    // The unit separator (U+001F) cannot occur in the corpus's decimal/text
    // content, so distinct column boundaries never collide into a false match.
    cells.join("\u{1f}")
}

// --- manifest model ----------------------------------------------------------

pub struct Manifest {
    databases: Vec<DbEntry>,
}

struct DbEntry {
    nid: String,
    category: String,
    elements: Vec<Element>,
}

pub struct Element {
    deleted: Vec<DeletedRow>,
    alive: Vec<Vec<String>>,
}

pub struct DeletedRow {
    cells: Vec<String>,
    substrate_recoverable: bool,
    fragment_recoverable: bool,
}

impl DeletedRow {
    #[must_use]
    pub fn cells(&self) -> &[String] {
        &self.cells
    }
    #[must_use]
    pub fn substrate_recoverable(&self) -> bool {
        self.substrate_recoverable
    }
    /// Whether the row is Tier-2 fragment-recoverable: its full identity is
    /// destroyed (`!substrate_recoverable`) but at least one distinctive cell
    /// (TEXT >= 4 UTF-8 bytes, or REAL) survives contiguously in the .db bytes.
    #[must_use]
    pub fn fragment_recoverable(&self) -> bool {
        self.fragment_recoverable
    }
}

impl Element {
    #[must_use]
    pub fn deleted(&self) -> &[DeletedRow] {
        &self.deleted
    }
    #[must_use]
    pub fn alive(&self) -> &[Vec<String>] {
        &self.alive
    }
}

pub struct DbView<'a> {
    elements: &'a [Element],
}

impl<'a> DbView<'a> {
    #[must_use]
    pub fn elements(&self) -> &'a [Element] {
        self.elements
    }
}

impl Manifest {
    /// `(nid, category)` for every database, in manifest order.
    #[must_use]
    pub fn databases(&self) -> Vec<(String, String)> {
        self.databases
            .iter()
            .map(|d| (d.nid.clone(), d.category.clone()))
            .collect()
    }

    /// The element list for one database id.
    #[must_use]
    pub fn db(&self, nid: &str) -> DbView<'_> {
        let entry = self
            .databases
            .iter()
            .find(|d| d.nid == nid)
            .unwrap_or_else(|| panic!("manifest missing db {nid}"));
        DbView {
            elements: &entry.elements,
        }
    }
}

/// The parsed manifest, loaded once.
pub fn manifest() -> &'static Manifest {
    static M: OnceLock<Manifest> = OnceLock::new();
    M.get_or_init(|| {
        let path = format!(
            "{}/../tests/data/nemetz/nemetz_ground_truth.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = std::fs::read_to_string(&path).expect("ground-truth manifest");
        parse_manifest(&raw)
    })
}

fn parse_manifest(raw: &str) -> Manifest {
    let json = json::parse(raw);
    let obj = json.as_obj();
    let mut databases = Vec::new();
    for (nid, dbj) in obj {
        let category = dbj.get("category").as_str().to_string();
        let mut elements = Vec::new();
        for elj in dbj.get("elements").as_arr() {
            let mut deleted = Vec::new();
            for dr in elj.get("deleted").as_arr() {
                deleted.push(DeletedRow {
                    cells: dr
                        .get("cells")
                        .as_arr()
                        .iter()
                        .map(|c| c.as_str().to_string())
                        .collect(),
                    substrate_recoverable: dr.get("substrate_recoverable").as_bool(),
                    fragment_recoverable: dr.get("fragment_recoverable").as_bool(),
                });
            }
            let alive = elj
                .get("alive")
                .as_arr()
                .iter()
                .map(|row| {
                    row.as_arr()
                        .iter()
                        .map(|c| c.as_str().to_string())
                        .collect()
                })
                .collect();
            elements.push(Element { deleted, alive });
        }
        databases.push(DbEntry {
            nid: nid.clone(),
            category,
            elements,
        });
    }
    databases.sort_by(|a, b| a.nid.cmp(&b.nid));
    Manifest { databases }
}

// --- minimal JSON-subset parser ---------------------------------------------

mod json {
    #[derive(Debug)]
    pub enum J {
        Null,
        Bool(bool),
        Num(f64),
        Str(String),
        Arr(Vec<J>),
        Obj(Vec<(String, J)>),
    }

    impl J {
        pub fn get(&self, key: &str) -> &J {
            match self {
                J::Obj(o) => o
                    .iter()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| v)
                    .unwrap_or(&J::Null),
                _ => &J::Null,
            }
        }
        pub fn as_obj(&self) -> &[(String, J)] {
            match self {
                J::Obj(o) => o,
                _ => &[],
            }
        }
        pub fn as_arr(&self) -> &[J] {
            match self {
                J::Arr(a) => a,
                _ => &[],
            }
        }
        pub fn as_str(&self) -> &str {
            match self {
                J::Str(s) => s,
                _ => "",
            }
        }
        pub fn as_bool(&self) -> bool {
            matches!(self, J::Bool(true))
        }
    }

    pub fn parse(s: &str) -> J {
        let bytes = s.as_bytes();
        let mut i = 0;
        value(bytes, &mut i)
    }

    fn skip_ws(b: &[u8], i: &mut usize) {
        while *i < b.len() && matches!(b[*i], b' ' | b'\t' | b'\n' | b'\r') {
            *i += 1;
        }
    }

    fn value(b: &[u8], i: &mut usize) -> J {
        skip_ws(b, i);
        match b[*i] {
            b'{' => object(b, i),
            b'[' => array(b, i),
            b'"' => J::Str(string(b, i)),
            b't' => {
                *i += 4;
                J::Bool(true)
            }
            b'f' => {
                *i += 5;
                J::Bool(false)
            }
            b'n' => {
                *i += 4;
                J::Null
            }
            _ => number(b, i),
        }
    }

    fn object(b: &[u8], i: &mut usize) -> J {
        *i += 1; // {
        let mut out = Vec::new();
        skip_ws(b, i);
        if b[*i] == b'}' {
            *i += 1;
            return J::Obj(out);
        }
        loop {
            skip_ws(b, i);
            let key = string(b, i);
            skip_ws(b, i);
            *i += 1; // :
            let val = value(b, i);
            out.push((key, val));
            skip_ws(b, i);
            if b[*i] == b',' {
                *i += 1;
            } else {
                *i += 1; // }
                break;
            }
        }
        J::Obj(out)
    }

    fn array(b: &[u8], i: &mut usize) -> J {
        *i += 1; // [
        let mut out = Vec::new();
        skip_ws(b, i);
        if b[*i] == b']' {
            *i += 1;
            return J::Arr(out);
        }
        loop {
            out.push(value(b, i));
            skip_ws(b, i);
            if b[*i] == b',' {
                *i += 1;
            } else {
                *i += 1; // ]
                break;
            }
        }
        J::Arr(out)
    }

    fn string(b: &[u8], i: &mut usize) -> String {
        *i += 1; // opening quote
        let mut out: Vec<u8> = Vec::new();
        while b[*i] != b'"' {
            if b[*i] == b'\\' {
                *i += 1;
                match b[*i] {
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'r' => out.push(b'\r'),
                    b'u' => {
                        let hex = std::str::from_utf8(&b[*i + 1..*i + 5]).unwrap();
                        let cp = u32::from_str_radix(hex, 16).unwrap_or(0);
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(
                            char::from_u32(cp)
                                .unwrap_or('\u{fffd}')
                                .encode_utf8(&mut buf)
                                .as_bytes(),
                        );
                        *i += 4;
                    }
                    other => out.push(other), // \" \\ \/
                }
                *i += 1;
            } else {
                out.push(b[*i]);
                *i += 1;
            }
        }
        *i += 1; // closing quote
        String::from_utf8(out).unwrap_or_default()
    }

    fn number(b: &[u8], i: &mut usize) -> J {
        let start = *i;
        while *i < b.len() && matches!(b[*i], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E') {
            *i += 1;
        }
        J::Num(
            std::str::from_utf8(&b[start..*i])
                .unwrap()
                .parse()
                .unwrap_or(0.0),
        )
    }
}
