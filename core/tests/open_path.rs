//! `Database::open_path` — a bounded-memory, paged read path (roadmap §3.1).
//!
//! Opening from a path streams pages on demand through a small cache instead of
//! loading the whole file into a `Vec<u8>`. Behaviour must be observationally
//! identical to the in-memory `Database::open`: same header, same page count, and
//! byte-for-byte the same page images for every page.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite_core::Database;

fn fixture() -> String {
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/data/deleted_places.db"
    )
    .to_string()
}

#[test]
fn open_path_reads_identical_pages_to_open() {
    let path = fixture();
    let bytes = std::fs::read(&path).unwrap();

    let mem = Database::open(bytes).expect("in-memory open");
    let paged = Database::open_path(&path).expect("paged open");

    assert_eq!(
        mem.page_count(),
        paged.page_count(),
        "page count must match between in-memory and paged opens"
    );
    assert!(mem.page_count() > 1, "fixture should span multiple pages");

    for page in 1..=mem.page_count() {
        let a = mem.raw_page(page).map(|p| p.to_vec());
        let b = paged.raw_page(page).map(|p| p.to_vec());
        assert_eq!(
            a, b,
            "page {page} differs between in-memory and paged reads"
        );
    }

    // Out-of-range and page 0 behave identically (both None).
    assert!(paged.raw_page(0).is_none());
    assert!(paged.raw_page(mem.page_count() + 1).is_none());
}
