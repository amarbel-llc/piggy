//! `piggy pass ls` over more than one store (piggy#330): one tree per
//! store, in search order, headed by the store's path, each entry an
//! earlier store also holds marked `[shadowed by <store>]` — reads take
//! the earlier one. A single store keeps the `tree(1)` listing in
//! `show.rs`; this renderer runs only when `PIGGY_STORE_DIR` names
//! several.

use std::path::PathBuf;

use crate::store_tree::{UnreadableSubdir, render_tree, walk_tree};

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
        let earlier = &roots[..i];
        let tree = walk_tree(&dir, UnreadableSubdir::ShowEmpty).unwrap_or_default();
        out.push_str(&render_tree(&tree, true, |name, path| {
            let rel = path.strip_prefix(root).unwrap_or(path);
            match earlier.iter().find(|store| store.join(rel).is_file()) {
                Some(store) => format!("{name}  [shadowed by {}]", store.display()),
                None => name.to_string(),
            }
        }));
    }
    any.then_some(out)
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
