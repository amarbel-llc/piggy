//! `piggy pass ls --recipients` — render the store tree with each
//! ebox leaf annotated by the recipients it's encrypted to.
//!
//! This is an **opt-in** alternative to the default `pass ls` view
//! (which shells to `tree(1)` in `show.rs::print_tree`). When `-r` /
//! `--recipients` is passed, `show.rs` routes here instead. The default
//! `tree(1)` path is left untouched.
//!
//! Recipients are read **offline** from each ebox's wire header
//! (`Ebox::from_bytes` → `configs[].parts[].piv_box.recipient_pubkey`),
//! rendered as `piggy-recipient-v1@pivy_ecdh_p256_pub-…` markl IDs.
//! No card, no PIN, no decrypt. Each ID is truncated to its
//! shortest-unique prefix computed over the whole listing (so the same
//! recipient renders identically everywhere, and prefixes are only as
//! long as needed to disambiguate).
//!
//! A future `--resolve-cards` flag will append GUID/CN labels for
//! currently-attached cards. It is deferred until the card-enumeration
//! seam can live at the right layer (see the dagnabit-rust work) rather
//! than round-tripping through `piggy-ids` NDJSON.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use piggy_box::ebox::Ebox;
use piggy_markl::{FormatId, Id as MarklId, PurposeId};

use crate::store_tree::{UnreadableSubdir, ebox_paths, render_tree, walk_tree};

/// Minimum number of body characters shown past a recipient's constant
/// `purpose@format-` lead, for a recipient whose prefix is otherwise
/// unambiguous at a shorter length. Every piggy key shares that lead, so
/// a floor counted from the start of the ID would show nothing that
/// identifies a lone recipient (piggy#263).
const MIN_BODY: usize = 8;

/// Where the blech32 body starts in a rendered markl ID: just past the
/// `-` that follows the format, or 0 when the string has no such `-`.
fn body_start(id: &str) -> usize {
    let format_start = id.find('@').map_or(0, |at| at + 1);
    id[format_start..]
        .find('-')
        .map_or(0, |dash| format_start + dash + 1)
}

/// The recipients of one ebox: either the rendered full markl wire
/// strings (possibly empty), or a marker that the file didn't parse.
enum RecipientCell {
    Ids(Vec<String>),
    Unparseable,
}

/// Entry point from `show.rs`. Prints `banner` (the "Password Store" /
/// subpath line), then the annotated tree. Returns a process exit code.
pub(crate) fn print_tree_with_recipients(banner: &str, dir_target: &Path) -> i32 {
    // An unreadable subdirectory lists empty rather than aborting the tree.
    let tree = match walk_tree(dir_target, UnreadableSubdir::ShowEmpty) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("piggy pass show: walk {}: {err}", dir_target.display());
            return 1;
        }
    };
    print!(
        "{banner}\n{}",
        render_with_recipients(&tree, extract_recipients)
    );
    0
}

/// The glyphed tree with each ebox annotated by `recipients_of` its path.
/// Every recipient's shortest-unique prefix is computed once over the
/// whole listing, so a recipient renders identically on every line.
fn render_with_recipients(
    tree: &[crate::store_tree::StoreTree],
    recipients_of: impl Fn(&Path) -> RecipientCell,
) -> String {
    let cells: HashMap<PathBuf, RecipientCell> = ebox_paths(tree)
        .into_iter()
        .map(|path| {
            let cell = recipients_of(&path);
            (path, cell)
        })
        .collect();
    let distinct = distinct_recipients(cells.values());
    let prefixes = shortest_unique_prefixes(&distinct);
    render_tree(tree, true, |name, path| {
        format!("{name}  {}", format_annotation(&cells[path], &prefixes))
    })
}

/// Read an ebox and render every recipient pubkey (across all configs'
/// parts) as a full markl wire string, de-duplicated. Any read/parse
/// failure → [`RecipientCell::Unparseable`]. A pubkey that won't render
/// as a markl ID becomes the sentinel `"?"` (shown as `[?]`, never
/// entered into the trie).
fn extract_recipients(path: &Path) -> RecipientCell {
    let Ok(bytes) = std::fs::read(path) else {
        return RecipientCell::Unparseable;
    };
    let Ok(ebox) = Ebox::from_bytes(&bytes) else {
        return RecipientCell::Unparseable;
    };
    let mut ids: Vec<String> = Vec::new();
    for config in &ebox.configs {
        for part in &config.parts {
            let id = render_recipient(&part.piv_box.recipient_pubkey);
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    RecipientCell::Ids(ids)
}

/// Render a SEC1-compressed P-256 recipient pubkey as a
/// `piggy-recipient-v1@pivy_ecdh_p256_pub-…` markl wire string, or `"?"`
/// when it doesn't validate (wrong length, non-P-256). Mirrors the
/// pattern in `crates/piggy-box/examples/dump-recipients.rs`.
fn render_recipient(pubkey: &[u8]) -> String {
    MarklId::new(
        Some(PurposeId::PiggyRecipientV1),
        FormatId::PivyEcdhP256Pub,
        pubkey.to_vec(),
    )
    .map(|id| id.to_string())
    .unwrap_or_else(|_| "?".to_string())
}

/// The distinct rendered recipient IDs across `cells`, excluding the `"?"`
/// sentinel (it isn't truncatable).
fn distinct_recipients<'a>(cells: impl Iterator<Item = &'a RecipientCell>) -> BTreeSet<String> {
    cells
        .filter_map(|cell| match cell {
            RecipientCell::Ids(ids) => Some(ids),
            RecipientCell::Unparseable => None,
        })
        .flatten()
        .filter(|id| *id != "?")
        .cloned()
        .collect()
}

/// For a sorted distinct set of strings, compute each string's
/// shortest-unique-prefix length: one char past the longest common
/// prefix it shares with either neighbour, floored at [`MIN_BODY`]
/// characters past its [`body_start`] and capped at the string's own
/// length. Stable: identical input maps
/// to identical output regardless of how the set was built (BTreeSet
/// gives sorted order).
fn shortest_unique_prefixes(ids: &BTreeSet<String>) -> HashMap<String, usize> {
    let v: Vec<&str> = ids.iter().map(String::as_str).collect();
    let mut out = HashMap::with_capacity(v.len());
    for i in 0..v.len() {
        let lcp_prev = if i > 0 {
            common_prefix_len(v[i], v[i - 1])
        } else {
            0
        };
        let lcp_next = if i + 1 < v.len() {
            common_prefix_len(v[i], v[i + 1])
        } else {
            0
        };
        let needed = lcp_prev.max(lcp_next) + 1;
        let len = needed.max(body_start(v[i]) + MIN_BODY).min(v[i].len());
        out.insert(v[i].to_string(), len);
    }
    out
}

/// Number of shared leading bytes. markl IDs are ASCII (RFC 0003), so a
/// byte prefix is always a valid char boundary.
fn common_prefix_len(a: &str, b: &str) -> usize {
    a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count()
}

/// Render one recipient ID for display: the shortest-unique prefix with
/// a trailing `…` when truncated. The `"?"` sentinel renders as `?`.
fn render_id(id: &str, prefixes: &HashMap<String, usize>) -> String {
    if id == "?" {
        return "?".to_string();
    }
    let len = prefixes.get(id).copied().unwrap_or(id.len()).min(id.len());
    let mut s = id[..len].to_string();
    if len < id.len() {
        s.push('…');
    }
    s
}

/// Format the `[...]` recipient annotation for one ebox leaf.
fn format_annotation(recipients: &RecipientCell, prefixes: &HashMap<String, usize>) -> String {
    match recipients {
        RecipientCell::Unparseable => "[?]".to_string(),
        // `join` on an empty Vec yields "", so a (wire-format-impossible)
        // zero-recipient ebox renders as `[]` without a special arm.
        RecipientCell::Ids(ids) => {
            let rendered: Vec<String> = ids.iter().map(|id| render_id(id, prefixes)).collect();
            format!("[{}]", rendered.join(", "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// piggy#263: a lone recipient shows MIN_BODY body characters past its
    /// constant `purpose@format-` lead, so its annotation identifies the key
    /// instead of stopping inside the lead every piggy key shares.
    #[test]
    fn single_recipient_shows_min_body_past_the_constant_lead() {
        let id = "piggy-recipient-v1@pivy_ecdh_p256_pub-q0p9kkuxlongbody";
        let p = shortest_unique_prefixes(&ids(&[id]));
        let lead = "piggy-recipient-v1@pivy_ecdh_p256_pub-".len();
        assert_eq!(p[id], lead + MIN_BODY);
        assert_eq!(
            &id[..p[id]],
            "piggy-recipient-v1@pivy_ecdh_p256_pub-q0p9kkux"
        );
    }

    #[test]
    fn two_recipients_sharing_constant_prefix_diverge_in_body() {
        // Same `piggy-recipient-v1@pivy_ecdh_p256_pub-` lead; bodies
        // diverge at the second body char, well inside the MIN_BODY floor.
        let a = "piggy-recipient-v1@pivy_ecdh_p256_pub-q0p9aaaaaaaa";
        let b = "piggy-recipient-v1@pivy_ecdh_p256_pub-qd5taaaaaaaa";
        let set = ids(&[a, b]);
        let p = shortest_unique_prefixes(&set);
        let lead = "piggy-recipient-v1@pivy_ecdh_p256_pub-".len();
        assert_eq!(p[a], lead + MIN_BODY);
        assert_eq!(p[b], lead + MIN_BODY);
        assert_ne!(&a[..p[a]], &b[..p[b]]);
    }

    /// Bodies that share more than MIN_BODY characters still extend one past
    /// the longest common prefix.
    #[test]
    fn recipients_sharing_more_than_min_body_extend_past_it() {
        let a = "piggy-recipient-v1@pivy_ecdh_p256_pub-qqqqqqqqqqa";
        let b = "piggy-recipient-v1@pivy_ecdh_p256_pub-qqqqqqqqqqb";
        let p = shortest_unique_prefixes(&ids(&[a, b]));
        assert_eq!(p[a], a.len());
        assert_ne!(&a[..p[a]], &b[..p[b]]);
    }

    #[test]
    fn prefix_is_stable_regardless_of_insertion_order() {
        let a = "aaa-zzzz";
        let b = "aaa-yyyy";
        let one: BTreeSet<String> = [a, b].iter().map(|s| s.to_string()).collect();
        let two: BTreeSet<String> = [b, a].iter().map(|s| s.to_string()).collect();
        assert_eq!(
            shortest_unique_prefixes(&one),
            shortest_unique_prefixes(&two)
        );
    }

    #[test]
    fn prefix_capped_at_full_length() {
        // A short string (< MIN_BODY) can't exceed its own length.
        let set = ids(&["abc"]);
        let p = shortest_unique_prefixes(&set);
        assert_eq!(p["abc"], 3);
    }

    #[test]
    fn render_id_truncates_with_ellipsis() {
        let id = "piggy-recipient-v1@pivy_ecdh_p256_pub-q0p9kkuxlongbody";
        let mut prefixes = HashMap::new();
        prefixes.insert(id.to_string(), 42);
        let got = render_id(id, &prefixes);
        assert_eq!(got, format!("{}…", &id[..42]));
    }

    #[test]
    fn render_id_no_ellipsis_when_full() {
        let id = "short";
        let mut prefixes = HashMap::new();
        prefixes.insert(id.to_string(), 5);
        let got = render_id(id, &prefixes);
        assert_eq!(got, "short");
    }

    #[test]
    fn render_id_sentinel_passes_through() {
        let got = render_id("?", &HashMap::new());
        assert_eq!(got, "?");
    }

    use crate::store_tree::StoreTree;

    fn r_ids(items: &[&str]) -> RecipientCell {
        RecipientCell::Ids(items.iter().map(|s| s.to_string()).collect())
    }

    fn ebox(name: &str) -> StoreTree {
        StoreTree::Ebox {
            name: name.into(),
            path: PathBuf::from(format!("{name}.ebox")),
        }
    }

    /// Recipients keyed by the ebox's file stem, for the fixed trees here.
    fn by_stem<'a>(table: &'a [(&'a str, RecipientCell)]) -> impl Fn(&Path) -> RecipientCell + 'a {
        move |path: &Path| {
            let stem = path.file_stem().unwrap().to_str().unwrap();
            match table.iter().find(|(name, _)| *name == stem) {
                Some((_, RecipientCell::Ids(ids))) => RecipientCell::Ids(ids.clone()),
                _ => RecipientCell::Unparseable,
            }
        }
    }

    #[test]
    fn render_tree_glyphs_last_vs_nonlast() {
        let tree = vec![
            StoreTree::Dir {
                name: "etsy".into(),
                children: vec![ebox("jira.env")],
            },
            ebox("fastmail"),
        ];
        let table = [
            ("jira.env", r_ids(&["AAAA1111"])),
            ("fastmail", r_ids(&["BBBB2222"])),
        ];
        let prefixes = shortest_unique_prefixes(&ids(&["AAAA1111", "BBBB2222"]));
        // etsy is non-last → ├──, its child is last under │   .
        // fastmail is last → └──.
        let expected = format!(
            "├── etsy\n│   └── jira.env  [{}]\n└── fastmail  [{}]\n",
            render_id("AAAA1111", &prefixes),
            render_id("BBBB2222", &prefixes),
        );
        assert_eq!(render_with_recipients(&tree, by_stem(&table)), expected);
    }

    #[test]
    fn render_unparseable_shows_question_mark() {
        let out = render_with_recipients(&[ebox("broken")], by_stem(&[]));
        assert_eq!(out, "└── broken  [?]\n");
    }

    #[test]
    fn render_multiple_recipients_comma_joined() {
        let table = [("shared", r_ids(&["AAAA1111", "BBBB2222"]))];
        let out = render_with_recipients(&[ebox("shared")], by_stem(&table));
        assert!(
            out.contains(", "),
            "expected comma-joined recipients: {out}"
        );
    }

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "piggy-treerec-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// A store on disk: `.git` and non-ebox files left out, and a file that
    /// is not a real ebox annotated `[?]`.
    #[test]
    fn a_store_on_disk_renders_unparseable_eboxes_as_question_marks() {
        let root = tempdir();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".git/config"), b"x").unwrap();
        std::fs::write(root.join("a.ebox"), b"not-a-real-ebox").unwrap();
        std::fs::write(root.join("notes.txt"), b"ignored").unwrap();
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/b.ebox"), b"nope").unwrap();

        let tree = walk_tree(&root, UnreadableSubdir::ShowEmpty).unwrap();
        assert_eq!(
            render_with_recipients(&tree, extract_recipients),
            "├── a  [?]\n└── sub\n    └── b  [?]\n"
        );
    }
}
