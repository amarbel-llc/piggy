//! The one store-tree walk and `tree(1)`-glyph renderer (piggy#151).
//! `collect_eboxes` is a flatten of [`walk_tree`], so `pass verify`,
//! `find`, `grep`, `pass show -r` and the multi-store `pass ls` all see
//! the same entries in the same order: `.git` pruned, symlinks followed,
//! depth bounded at [`MAX_WALK_DEPTH`], each directory sorted by raw file
//! name, non-ebox files skipped.

use std::path::{Path, PathBuf};

use crate::store::{MAX_WALK_DEPTH, is_ebox};

pub(crate) enum StoreTree {
    Dir {
        name: String,
        children: Vec<StoreTree>,
    },
    Ebox {
        /// The file name with its `.ebox` suffix stripped.
        name: String,
        path: PathBuf,
    },
}

/// What a subdirectory that cannot be read becomes.
#[derive(Clone, Copy)]
pub(crate) enum UnreadableSubdir {
    /// The whole walk fails with its error (`collect_eboxes`).
    Fail,
    /// It is listed with no children (the listings).
    ShowEmpty,
}

/// The tree under `dir`; empty when `dir` is not a directory. An error
/// reading `dir` itself always propagates.
pub(crate) fn walk_tree(
    dir: &Path,
    unreadable: UnreadableSubdir,
) -> std::io::Result<Vec<StoreTree>> {
    walk_at(dir, 0, unreadable)
}

fn walk_at(
    dir: &Path,
    depth: usize,
    unreadable: UnreadableSubdir,
) -> std::io::Result<Vec<StoreTree>> {
    if depth > MAX_WALK_DEPTH || !std::fs::metadata(dir).is_ok_and(|m| m.is_dir()) {
        return Ok(Vec::new());
    }
    let mut entries: Vec<(std::ffi::OsString, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if name != ".git" {
            entries.push((name, entry.path()));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut nodes = Vec::with_capacity(entries.len());
    for (name, path) in entries {
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        let name = name.to_string_lossy();
        if meta.is_dir() {
            let children = match walk_at(&path, depth + 1, unreadable) {
                Ok(children) => children,
                Err(e) => match unreadable {
                    UnreadableSubdir::Fail => return Err(e),
                    UnreadableSubdir::ShowEmpty => Vec::new(),
                },
            };
            nodes.push(StoreTree::Dir {
                name: name.into_owned(),
                children,
            });
        } else if meta.is_file() && is_ebox(&path) {
            nodes.push(StoreTree::Ebox {
                name: strip_ebox_suffix(&name),
                path,
            });
        }
    }
    Ok(nodes)
}

/// Every ebox path in `nodes`, in tree order (which is path order).
pub(crate) fn ebox_paths(nodes: &[StoreTree]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    push_ebox_paths(nodes, &mut out);
    out
}

fn push_ebox_paths(nodes: &[StoreTree], out: &mut Vec<PathBuf>) {
    for node in nodes {
        match node {
            StoreTree::Dir { children, .. } => push_ebox_paths(children, out),
            StoreTree::Ebox { path, .. } => out.push(path.clone()),
        }
    }
}

/// `nodes` without the directories that hold no ebox at any depth.
pub(crate) fn without_empty_dirs(nodes: Vec<StoreTree>) -> Vec<StoreTree> {
    nodes
        .into_iter()
        .filter_map(|node| match node {
            StoreTree::Dir { name, children } => {
                let children = without_empty_dirs(children);
                (!children.is_empty()).then_some(StoreTree::Dir { name, children })
            }
            ebox => Some(ebox),
        })
        .collect()
}

/// Render `nodes` with `tree(1)` glyphs, one line per node. A directory's
/// line is its name; an ebox's is `ebox_label(name, path)`. With
/// `glyph_top_level` false the top tier is written bare and its children
/// start the glyphs, as `pass verify` lays it out.
pub(crate) fn render_tree(
    nodes: &[StoreTree],
    glyph_top_level: bool,
    mut ebox_label: impl FnMut(&str, &Path) -> String,
) -> String {
    let mut out = String::new();
    if glyph_top_level {
        render_glyphed(nodes, "", &mut ebox_label, &mut out);
        return out;
    }
    for node in nodes {
        match node {
            StoreTree::Dir { name, children } => {
                out.push_str(name);
                out.push('\n');
                render_glyphed(children, "", &mut ebox_label, &mut out);
            }
            StoreTree::Ebox { name, path } => {
                out.push_str(&ebox_label(name, path));
                out.push('\n');
            }
        }
    }
    out
}

fn render_glyphed(
    nodes: &[StoreTree],
    prefix: &str,
    ebox_label: &mut impl FnMut(&str, &Path) -> String,
    out: &mut String,
) {
    for (i, node) in nodes.iter().enumerate() {
        let last = i + 1 == nodes.len();
        out.push_str(prefix);
        out.push_str(if last { "└── " } else { "├── " });
        match node {
            StoreTree::Dir { name, children } => {
                out.push_str(name);
                out.push('\n');
                let child_prefix = format!("{prefix}{}", if last { "    " } else { "│   " });
                render_glyphed(children, &child_prefix, ebox_label, out);
            }
            StoreTree::Ebox { name, path } => {
                out.push_str(&ebox_label(name, path));
                out.push('\n');
            }
        }
    }
}

/// Strip a trailing `.ebox` case-insensitively, matching [`is_ebox`]'s
/// acceptance (`FOO.EBOX` renders as `FOO`), keeping the rest's casing.
pub(crate) fn strip_ebox_suffix(name: &str) -> String {
    if name.len() >= ".ebox".len() {
        let (head, tail) = name.split_at(name.len() - ".ebox".len());
        if tail.eq_ignore_ascii_case(".ebox") {
            return head.to_string();
        }
    }
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "piggy-store-tree-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn touch(root: &Path, rel: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, b"x").unwrap();
    }

    fn names(nodes: &[StoreTree]) -> Vec<&str> {
        nodes
            .iter()
            .map(|n| match n {
                StoreTree::Dir { name, .. } | StoreTree::Ebox { name, .. } => name.as_str(),
            })
            .collect()
    }

    #[test]
    fn strip_ebox_suffix_is_case_insensitive() {
        assert_eq!(strip_ebox_suffix("jira.env.ebox"), "jira.env");
        assert_eq!(strip_ebox_suffix("FOO.EBOX"), "FOO");
        assert_eq!(strip_ebox_suffix("Mixed.EbOx"), "Mixed");
        assert_eq!(strip_ebox_suffix("notanebox"), "notanebox");
        assert_eq!(strip_ebox_suffix("a.eboxname"), "a.eboxname");
    }

    /// Prunes `.git`, skips non-ebox files, keeps empty directories, sorts
    /// by raw file name (`a-b` before `a.ebox`), follows a symlinked dir.
    #[test]
    fn walk_tree_shape() {
        let root = tempdir();
        touch(&root, ".git/config.ebox");
        touch(&root, "a.ebox");
        touch(&root, "a-b/x.EBOX");
        touch(&root, "notes.txt");
        std::fs::create_dir_all(root.join("empty")).unwrap();
        std::os::unix::fs::symlink(root.join("a-b"), root.join("link")).unwrap();

        let tree = walk_tree(&root, UnreadableSubdir::Fail).unwrap();
        assert_eq!(names(&tree), ["a-b", "a", "empty", "link"]);
        let StoreTree::Dir { children, .. } = &tree[3] else {
            panic!("link is not a dir");
        };
        assert_eq!(names(children), ["x"]);
        assert_eq!(names(&without_empty_dirs(tree)), ["a-b", "a", "link"]);
    }

    /// The flatten is `collect_eboxes`' contract: every ebox, path-sorted.
    #[test]
    fn ebox_paths_are_path_sorted() {
        let root = tempdir();
        for rel in ["b.ebox", "a/z.ebox", "a/b/c.ebox", "a.ebox", "a-b/x.ebox"] {
            touch(&root, rel);
        }
        let got = ebox_paths(&walk_tree(&root, UnreadableSubdir::Fail).unwrap());
        let mut want = got.clone();
        want.sort();
        assert_eq!(got, want);
        assert_eq!(got.len(), 5);
    }

    #[test]
    fn a_non_directory_walks_to_nothing() {
        let root = tempdir();
        touch(&root, "a.ebox");
        assert!(
            walk_tree(&root.join("a.ebox"), UnreadableSubdir::Fail)
                .unwrap()
                .is_empty()
        );
        assert!(
            walk_tree(&root.join("absent"), UnreadableSubdir::Fail)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn render_tree_glyphs_every_tier_or_leaves_the_top_bare() {
        let nodes = vec![
            StoreTree::Dir {
                name: "etsy".into(),
                children: vec![StoreTree::Ebox {
                    name: "jira".into(),
                    path: PathBuf::from("etsy/jira.ebox"),
                }],
            },
            StoreTree::Ebox {
                name: "mail".into(),
                path: PathBuf::from("mail.ebox"),
            },
        ];
        let label = |name: &str, _: &Path| format!("{name}!");
        assert_eq!(
            render_tree(&nodes, true, label),
            "├── etsy\n│   └── jira!\n└── mail!\n"
        );
        assert_eq!(
            render_tree(&nodes, false, label),
            "etsy\n└── jira!\nmail!\n"
        );
    }
}
