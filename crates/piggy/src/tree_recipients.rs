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

use crate::store::{MAX_WALK_DEPTH, is_ebox};

/// Minimum number of leading chars shown for a recipient whose prefix
/// is otherwise unambiguous at a shorter length. Keeps a lone recipient
/// from collapsing to one or two characters.
const MIN_PREFIX: usize = 8;

/// One node in the rendered tree.
enum Node {
    Dir {
        name: String,
        children: Vec<Node>,
    },
    Ebox {
        /// Display name with the `.ebox` suffix stripped.
        name: String,
        recipients: RecipientCell,
    },
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
    let children = match build_tree(dir_target, 0) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("piggy pass show: walk {}: {err}", dir_target.display());
            return 1;
        }
    };

    // Collect the global distinct recipient set, compute each one's
    // shortest-unique prefix once, so a recipient renders identically
    // on every line it appears.
    let mut distinct: BTreeSet<String> = BTreeSet::new();
    collect_recipients(&children, &mut distinct);
    let prefixes = shortest_unique_prefixes(&distinct);

    let mut out = String::new();
    out.push_str(banner);
    out.push('\n');
    render(&children, "", &prefixes, &mut out);

    print!("{out}");
    0
}

/// Walk `dir` into a `Node` forest, mirroring `store::collect_eboxes`
/// semantics: prune `.git`, follow symlinks (via `metadata`), bound
/// depth at `MAX_WALK_DEPTH`, and sort each directory's children by
/// file name (so output is deterministic and matches `collect_eboxes`'s
/// lexicographic ordering). Non-ebox files are skipped. Any IO error on
/// a *subdirectory* — whether the `read_dir` open or a mid-iteration
/// `DirEntry` failure — propagates out of that recursive call and is
/// caught by `unwrap_or_default()`, so the subdirectory renders with
/// empty children (best-effort; never aborts the whole tree). This is a
/// deliberate softening of `store::walk`, which propagates the same
/// errors all the way up. The top-level error propagates so the caller
/// can report it (the target already passed `.is_dir()`).
fn build_tree(dir: &Path, depth: usize) -> std::io::Result<Vec<Node>> {
    if depth > MAX_WALK_DEPTH {
        return Ok(Vec::new());
    }
    let mut entries: Vec<(std::ffi::OsString, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == ".git" {
            continue;
        }
        entries.push((name, entry.path()));
    }
    // Sort by file name (raw, including `.ebox`) so dirs and files
    // interleave alphabetically — same order as `tree(1)` and
    // `collect_eboxes`.
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut nodes = Vec::with_capacity(entries.len());
    for (name, path) in entries {
        let meta = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            let children = build_tree(&path, depth + 1).unwrap_or_default();
            nodes.push(Node::Dir {
                name: name.to_string_lossy().into_owned(),
                children,
            });
        } else if meta.is_file() && is_ebox(&path) {
            nodes.push(Node::Ebox {
                name: strip_ebox_suffix(&name.to_string_lossy()),
                recipients: extract_recipients(&path),
            });
        }
    }
    Ok(nodes)
}

/// Strip a trailing `.ebox` suffix case-insensitively, matching
/// [`is_ebox`]'s `eq_ignore_ascii_case` acceptance (so `FOO.EBOX`
/// renders as `FOO`, not `FOO.EBOX`). Preserves the surviving prefix's
/// original casing. Mirrors `verify::strip_ebox`; a shared helper is a
/// followup (see the verify/tree_recipients walk-and-render unification
/// issue).
fn strip_ebox_suffix(name: &str) -> String {
    if name.len() >= ".ebox".len() {
        let (head, tail) = name.split_at(name.len() - ".ebox".len());
        if tail.eq_ignore_ascii_case(".ebox") {
            return head.to_string();
        }
    }
    name.to_string()
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

/// Gather the global distinct set of rendered recipient IDs across the
/// whole forest, excluding the `"?"` sentinel (it isn't truncatable).
fn collect_recipients(nodes: &[Node], out: &mut BTreeSet<String>) {
    for node in nodes {
        match node {
            Node::Dir { children, .. } => collect_recipients(children, out),
            Node::Ebox {
                recipients: RecipientCell::Ids(ids),
                ..
            } => {
                for id in ids {
                    if id != "?" {
                        out.insert(id.clone());
                    }
                }
            }
            Node::Ebox { .. } => {}
        }
    }
}

/// For a sorted distinct set of strings, compute each string's
/// shortest-unique-prefix length: one char past the longest common
/// prefix it shares with either neighbour, floored at [`MIN_PREFIX`]
/// and capped at the string's own length. Stable: identical input maps
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
        let len = needed.max(MIN_PREFIX).min(v[i].len());
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

/// Recursive tree render with `tree(1)`-style glyphs (plain text, no
/// ANSI). `prefix` is the accumulated indentation for the current
/// level.
fn render(nodes: &[Node], prefix: &str, prefixes: &HashMap<String, usize>, out: &mut String) {
    let n = nodes.len();
    for (i, node) in nodes.iter().enumerate() {
        let is_last = i + 1 == n;
        let connector = if is_last { "└── " } else { "├── " };
        let child_prefix = if is_last { "    " } else { "│   " };
        match node {
            Node::Dir { name, children } => {
                out.push_str(prefix);
                out.push_str(connector);
                out.push_str(name);
                out.push('\n');
                let next = format!("{prefix}{child_prefix}");
                render(children, &next, prefixes, out);
            }
            Node::Ebox { name, recipients } => {
                out.push_str(prefix);
                out.push_str(connector);
                out.push_str(name);
                out.push_str("  ");
                out.push_str(&format_annotation(recipients, prefixes));
                out.push('\n');
            }
        }
    }
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

    #[test]
    fn strip_ebox_suffix_is_case_insensitive() {
        // Matches is_ebox's eq_ignore_ascii_case acceptance, preserving
        // the surviving prefix's casing.
        assert_eq!(strip_ebox_suffix("jira.env.ebox"), "jira.env");
        assert_eq!(strip_ebox_suffix("FOO.EBOX"), "FOO");
        assert_eq!(strip_ebox_suffix("Mixed.EbOx"), "Mixed");
        // No suffix → unchanged; `.ebox` mid-name is not a suffix.
        assert_eq!(strip_ebox_suffix("notanebox"), "notanebox");
        assert_eq!(strip_ebox_suffix("a.eboxname"), "a.eboxname");
    }

    #[test]
    fn single_recipient_uses_min_prefix() {
        let set = ids(&["piggy-recipient-v1@pivy_ecdh_p256_pub-q0p9kkuxlongbody"]);
        let p = shortest_unique_prefixes(&set);
        let id = set.iter().next().unwrap();
        assert_eq!(p[id], MIN_PREFIX);
    }

    #[test]
    fn two_recipients_sharing_constant_prefix_diverge_in_body() {
        // Same `piggy-recipient-v1@pivy_ecdh_p256_pub-` prefix; bodies
        // diverge at the first body char.
        let a = "piggy-recipient-v1@pivy_ecdh_p256_pub-q0p9aaaa";
        let b = "piggy-recipient-v1@pivy_ecdh_p256_pub-qd5taaaa";
        let set = ids(&[a, b]);
        let p = shortest_unique_prefixes(&set);
        let constant = "piggy-recipient-v1@pivy_ecdh_p256_pub-".len();
        // They share the constant prefix plus the first body char `q`,
        // diverging at index constant+1 (`0` vs `d`). needed =
        // (constant+1) + 1.
        assert_eq!(p[a], constant + 2);
        assert_eq!(p[b], constant + 2);
        // The displayed prefixes must actually differ.
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
        // A short string (< MIN_PREFIX) can't exceed its own length.
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

    fn r_ids(items: &[&str]) -> RecipientCell {
        RecipientCell::Ids(items.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn render_tree_glyphs_last_vs_nonlast() {
        let nodes = vec![
            Node::Dir {
                name: "etsy".into(),
                children: vec![Node::Ebox {
                    name: "jira.env".into(),
                    recipients: r_ids(&["AAAA1111"]),
                }],
            },
            Node::Ebox {
                name: "fastmail".into(),
                recipients: r_ids(&["BBBB2222"]),
            },
        ];
        let set = ids(&["AAAA1111", "BBBB2222"]);
        let prefixes = shortest_unique_prefixes(&set);
        let mut out = String::new();
        render(&nodes, "", &prefixes, &mut out);
        // etsy is non-last → ├──, its child is last under │   .
        // fastmail is last → └──.
        let expected = format!(
            "├── etsy\n│   └── jira.env  [{}]\n└── fastmail  [{}]\n",
            render_id("AAAA1111", &prefixes),
            render_id("BBBB2222", &prefixes),
        );
        assert_eq!(out, expected);
    }

    #[test]
    fn render_unparseable_shows_question_mark() {
        let nodes = vec![Node::Ebox {
            name: "broken".into(),
            recipients: RecipientCell::Unparseable,
        }];
        let mut out = String::new();
        render(&nodes, "", &HashMap::new(), &mut out);
        assert_eq!(out, "└── broken  [?]\n");
    }

    #[test]
    fn render_multiple_recipients_comma_joined() {
        let set = ids(&["AAAA1111", "BBBB2222"]);
        let prefixes = shortest_unique_prefixes(&set);
        let nodes = vec![Node::Ebox {
            name: "shared".into(),
            recipients: r_ids(&["AAAA1111", "BBBB2222"]),
        }];
        let mut out = String::new();
        render(&nodes, "", &prefixes, &mut out);
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

    #[test]
    fn build_tree_prunes_git_and_skips_non_ebox() {
        let root = tempdir();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".git/config"), b"x").unwrap();
        std::fs::write(root.join("a.ebox"), b"not-a-real-ebox").unwrap();
        std::fs::write(root.join("notes.txt"), b"ignored").unwrap();
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/b.ebox"), b"nope").unwrap();

        let nodes = build_tree(&root, 0).unwrap();
        // Expect: `a.ebox` leaf and `sub` dir; no `.git`, no notes.txt.
        let names: Vec<&str> = nodes
            .iter()
            .map(|n| match n {
                Node::Dir { name, .. } => name.as_str(),
                Node::Ebox { name, .. } => name.as_str(),
            })
            .collect();
        assert_eq!(names, vec!["a", "sub"], "got: {names:?}");
        // The fake ebox bytes won't parse → Unparseable.
        match &nodes[0] {
            Node::Ebox {
                recipients: RecipientCell::Unparseable,
                ..
            } => {}
            other => panic!(
                "expected Unparseable ebox, got a {}",
                match other {
                    Node::Dir { .. } => "dir",
                    Node::Ebox { .. } => "parseable ebox",
                }
            ),
        }
    }
}
