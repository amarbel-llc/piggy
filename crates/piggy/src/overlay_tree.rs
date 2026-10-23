//! `piggy pass ls` over more than one store (piggy#330): one tree per
//! store, in search order, headed by the store's path, each entry an
//! earlier store also holds marked `[shadowed by <store>]` — reads take
//! the earlier one. A single store keeps the `tree(1)` listing in
//! `show.rs`; this renderer runs only when `PIGGY_STORE_DIR` names
//! several.

use std::path::{Path, PathBuf};

use crate::store::{MAX_WALK_DEPTH, is_ebox};

enum Node {
    Dir {
        name: String,
        children: Vec<Node>,
    },
    Entry {
        name: String,
        shadowed_by: Option<PathBuf>,
    },
}

/// The listing of `sub` (empty for the whole store) across `roots`, or
/// `None` when no store holds it as a directory.
pub(crate) fn render(roots: &[PathBuf], sub: &str) -> Option<String> {
    let mut out = String::new();
    let mut any = false;
    for (i, root) in roots.iter().enumerate() {
        let dir = if sub.is_empty() {
            root.clone()
        } else {
            root.join(sub)
        };
        if !dir.is_dir() {
            continue;
        }
        any = true;
        let banner = if sub.is_empty() {
            "Password Store"
        } else {
            sub
        };
        out.push_str(&format!("{banner} ({})\n", root.display()));
        let nodes = build(&dir, Path::new(sub), &roots[..i], 0);
        render_nodes(&nodes, "", &mut out);
    }
    any.then_some(out)
}

/// `dir`'s tree, `rel` being its path inside the store, each entry
/// checked against the `earlier` stores. Prunes `.git`, follows
/// symlinks, keeps directories and eboxes, sorts by file name — the
/// shape `tree -l` lists.
fn build(dir: &Path, rel: &Path, earlier: &[PathBuf], depth: usize) -> Vec<Node> {
    if depth > MAX_WALK_DEPTH {
        return Vec::new();
    }
    let Ok(read) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut entries: Vec<(String, PathBuf)> = read
        .filter_map(Result::ok)
        .filter(|e| e.file_name() != ".git")
        .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path()))
        .collect();
    entries.sort();

    let mut nodes = Vec::with_capacity(entries.len());
    for (name, path) in entries {
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        let rel = rel.join(&name);
        if meta.is_dir() {
            nodes.push(Node::Dir {
                children: build(&path, &rel, earlier, depth + 1),
                name,
            });
        } else if meta.is_file() && is_ebox(&path) {
            nodes.push(Node::Entry {
                name: crate::tree_recipients::strip_ebox_suffix(&name),
                shadowed_by: earlier
                    .iter()
                    .find(|root| root.join(&rel).is_file())
                    .cloned(),
            });
        }
    }
    nodes
}

fn render_nodes(nodes: &[Node], prefix: &str, out: &mut String) {
    for (i, node) in nodes.iter().enumerate() {
        let last = i + 1 == nodes.len();
        out.push_str(prefix);
        out.push_str(if last { "└── " } else { "├── " });
        match node {
            Node::Dir { name, children } => {
                out.push_str(name);
                out.push('\n');
                let child_prefix = format!("{prefix}{}", if last { "    " } else { "│   " });
                render_nodes(children, &child_prefix, out);
            }
            Node::Entry { name, shadowed_by } => {
                out.push_str(name);
                if let Some(store) = shadowed_by {
                    out.push_str(&format!("  [shadowed by {}]", store.display()));
                }
                out.push('\n');
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stores() -> (PathBuf, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "piggy-overlay-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let (rw, ro) = (base.join("rw"), base.join("ro"));
        for (dir, files) in [
            (&rw, &["both.ebox", "local/only-rw.ebox"][..]),
            (
                &ro,
                &["both.ebox", "tent/a.ebox", "tent/b.ebox", "notes.txt"][..],
            ),
        ] {
            for f in files {
                let p = dir.join(f);
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(p, b"x").unwrap();
            }
        }
        std::fs::create_dir_all(ro.join(".git")).unwrap();
        (base, rw, ro)
    }

    /// The golden listing: each store under its path, the entry the write
    /// store also holds marked shadowed, non-ebox files and `.git` left out.
    #[test]
    fn lists_each_store_and_marks_shadowed_entries() {
        let (_base, rw, ro) = stores();
        let got = render(&[rw.clone(), ro.clone()], "").unwrap();
        let want = format!(
            "Password Store ({rw})\n\
             ├── both\n\
             └── local\n    └── only-rw\n\
             Password Store ({ro})\n\
             ├── both  [shadowed by {rw}]\n\
             └── tent\n    ├── a\n    └── b\n",
            rw = rw.display(),
            ro = ro.display(),
        );
        assert_eq!(got, want);
    }

    #[test]
    fn a_subpath_lists_only_the_stores_holding_it() {
        let (_base, rw, ro) = stores();
        let got = render(&[rw, ro.clone()], "tent").unwrap();
        assert_eq!(got, format!("tent ({})\n├── a\n└── b\n", ro.display()));
    }

    #[test]
    fn no_store_holding_the_subpath_is_none() {
        let (_base, rw, ro) = stores();
        assert!(render(&[rw, ro], "absent").is_none());
    }
}
