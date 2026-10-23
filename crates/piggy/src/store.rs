//! Shared store-resolution and ebox-walk helpers used by the Rust
//! handlers (`verify`, `find`, `grep`, ...).
//!
//! These mirror the behavior of `src/piggy.sh`'s top-level `PREFIX=`
//! computation, `find_piggy_ids`, and the `find -L $PREFIX -path
//! '*/.git' -prune -o -iname '*.ebox' -print0` walk pattern used in
//! `cmd_grep` / `reencrypt_path`. Keeping a single source of truth for
//! these helpers prevents per-handler drift.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub(crate) const MAX_WALK_DEPTH: usize = 64;

pub(crate) trait EnvLookup {
    fn get(&self, key: &str) -> Option<OsString>;
}

pub(crate) struct RealEnv;

impl EnvLookup for RealEnv {
    fn get(&self, key: &str) -> Option<OsString> {
        std::env::var_os(key)
    }
}

/// The write store: the first of [`store_roots`]. Every write (insert,
/// generate, edit, rm, mv, init, recipients, git) lands here.
pub(crate) fn store_root() -> PathBuf {
    store_root_from(&RealEnv)
}

pub(crate) fn store_root_from(env: &dyn EnvLookup) -> PathBuf {
    store_roots_from(env).swap_remove(0)
}

/// Every store, in search order (piggy#330). `$PIGGY_STORE_DIR` is a
/// colon-separated list like `PATH`, empty components skipped; there is
/// no escape, so a store path containing `:` cannot be named. Unset or
/// empty, the one store is `$XDG_DATA_HOME/piggy`, else
/// `$HOME/.local/share/piggy`. Never empty.
pub(crate) fn store_roots() -> Vec<PathBuf> {
    store_roots_from(&RealEnv)
}

pub(crate) fn store_roots_from(env: &dyn EnvLookup) -> Vec<PathBuf> {
    if let Some(v) = env.get("PIGGY_STORE_DIR") {
        let roots: Vec<PathBuf> = std::env::split_paths(&v)
            .filter(|p| !p.as_os_str().is_empty())
            .collect();
        if !roots.is_empty() {
            return roots;
        }
    }
    if let Some(v) = env.get("XDG_DATA_HOME") {
        if !v.is_empty() {
            return vec![PathBuf::from(v).join("piggy")];
        }
    }
    let home = env.get("HOME").unwrap_or_default();
    vec![PathBuf::from(home).join(".local/share/piggy")]
}

/// The ebox for pass-name `name` in the first store that holds it.
pub(crate) fn find_entry_in(roots: &[PathBuf], name: &str) -> Option<PathBuf> {
    roots
        .iter()
        .map(|root| root.join(format!("{name}.ebox")))
        .find(|passfile| passfile.is_file())
}

/// [`find_entry_in`] over [`store_roots`].
pub(crate) fn find_entry(name: &str) -> Option<PathBuf> {
    find_entry_in(&store_roots(), name)
}

/// The later store holding `name` (an entry or a directory) when the
/// write store does not: the case a write to an existing entry refuses.
pub(crate) fn later_store_holding<'a>(roots: &'a [PathBuf], name: &str) -> Option<&'a Path> {
    let holds = |root: &Path| {
        let name = name.trim_end_matches('/');
        root.join(format!("{name}.ebox")).is_file()
            || (!name.is_empty() && root.join(name).is_dir())
    };
    let (write, later) = roots.split_first()?;
    if holds(write) {
        return None;
    }
    later.iter().map(PathBuf::as_path).find(|root| holds(root))
}

/// The refusal for an `op` on `name`, which lives only in `holder`, a
/// store after the write store.
pub(crate) fn not_in_write_store(op: &str, name: &str, holder: &Path, write: &Path) -> String {
    format!(
        "Error: {name} is in {}, not in the write store {} (the first store in \
         PIGGY_STORE_DIR); piggy only changes entries in the write store. To {op} it, \
         copy it there first with `piggy pass cp {name} {name}`, or put {} first in \
         PIGGY_STORE_DIR.",
        holder.display(),
        write.display(),
        holder.display(),
    )
}

/// [`later_store_holding`] over [`store_roots`], rendered as the refusal
/// for `op`; `None` when the write may go ahead.
pub(crate) fn refuse_write_to_later_store(op: &str, name: &str) -> Option<String> {
    let roots = store_roots();
    later_store_holding(&roots, name).map(|holder| not_in_write_store(op, name, holder, &roots[0]))
}

/// The refusal for an `op` when the write store `root` is read-only (a
/// home-manager store path, say); `None` when it is writable or does
/// not exist yet.
pub(crate) fn read_only_write_store(op: &str, root: &Path) -> Option<String> {
    let read_only = std::fs::metadata(root).is_ok_and(|m| m.permissions().readonly());
    read_only.then(|| {
        format!(
            "Error: the write store {} (the first store in PIGGY_STORE_DIR) is read-only, so \
             piggy cannot {op} entries in it. Put a writable store first in PIGGY_STORE_DIR, \
             for example PIGGY_STORE_DIR=<writable-store>:$PIGGY_STORE_DIR.",
            root.display(),
        )
    })
}

/// Both refusals a write to `name` can meet, the read-only write store
/// first; `None` when the write may go ahead.
pub(crate) fn refuse_write(op: &str, name: &str) -> Option<String> {
    read_only_write_store(op, &store_root()).or_else(|| refuse_write_to_later_store(op, name))
}

/// The note a new write store entry `name` prints when a later store
/// holds the same name, which reads now no longer reach.
pub(crate) fn shadow_note(name: &str) -> Option<String> {
    let roots = store_roots();
    later_store_holding(&roots, name).map(|holder| {
        format!(
            "note: {name} in {} is now shadowed by the write store {}",
            holder.display(),
            roots[0].display()
        )
    })
}

/// Resolve a user-supplied subpath against the store root, rejecting
/// sneaky paths the same way `check_sneaky_paths` in piggy.sh does
/// (empty, NUL, absolute, ParentDir component, post-canonicalize
/// escape).
pub(crate) fn resolve_target(root: &Path, subpath: Option<&str>) -> Result<PathBuf, String> {
    let Some(sub) = subpath else {
        return Ok(root.to_path_buf());
    };
    if sub.is_empty() {
        return Err("subpath is empty".into());
    }
    if sub.contains('\0') {
        return Err(format!("subpath contains NUL: {sub:?}"));
    }
    let sub_path = Path::new(sub);
    if sub_path.is_absolute() {
        return Err(format!("subpath must be relative: {sub}"));
    }
    for component in sub_path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(format!("subpath escapes the store: {sub}"));
        }
    }

    let joined = root.join(sub_path);
    if !joined.exists() {
        return Err(format!("subpath does not exist: {sub}"));
    }

    let canon_root = std::fs::canonicalize(root)
        .map_err(|e| format!("cannot canonicalize store root {}: {e}", root.display()))?;
    let canon_target = std::fs::canonicalize(&joined)
        .map_err(|e| format!("cannot canonicalize subpath {}: {e}", joined.display()))?;
    if !canon_target.starts_with(&canon_root) {
        return Err(format!("subpath escapes the store: {sub}"));
    }
    Ok(canon_target)
}

/// Walk `root` recursively and collect every `*.ebox` file, sorted
/// lexicographically. Mirrors the bash `find -L $root -path '*/.git'
/// -prune -o -iname '*.ebox' -print0` invocation. Follows symlinks
/// with a bounded depth (MAX_WALK_DEPTH) to handle cycles that bash's
/// `find -L` warn-and-skips.
pub(crate) fn collect_eboxes(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    walk(root, 0, &mut out)?;
    out.sort();
    Ok(out)
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if depth > MAX_WALK_DEPTH {
        return Ok(());
    }
    let meta = match std::fs::metadata(dir) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };
    if !meta.is_dir() {
        return Ok(());
    }
    let read = std::fs::read_dir(dir)?;
    for entry in read {
        let entry = entry?;
        let name = entry.file_name();
        if name == ".git" {
            continue;
        }
        let path = entry.path();
        let file_type = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            walk(&path, depth + 1, out)?;
        } else if file_type.is_file() && is_ebox(&path) {
            out.push(path);
        }
    }
    Ok(())
}

pub(crate) fn is_ebox(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("ebox"))
}

/// `dirname -- "$path"` semantics, projected into the subfolder
/// argument shape [`find_piggy_ids`] expects.
pub(crate) fn path_parent_for_search(path: &str) -> String {
    let p = PathBuf::from(path);
    match p.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_string_lossy().into_owned(),
        _ => String::new(),
    }
}

/// Why a pass-name is a sneaky path (absolute, or a `..` component), or
/// `None` if it is fine. Either would make `root.join(name)` resolve
/// outside the store (piggy#260).
pub(crate) fn sneaky_path_reason(path: &str) -> Option<&'static str> {
    if Path::new(path).is_absolute() {
        return Some("absolute path");
    }
    for component in Path::new(path).components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Some("`..` component");
        }
    }
    None
}

/// Walk up from `root/subfolder` toward `root`, returning the first
/// directory that contains a `piggy-ids` file. Mirrors
/// `find_piggy_ids` in piggy.sh.
///
/// `subfolder` is empty for top-level recipients commands. The walk
/// short-circuits at `root` regardless of whether `root/piggy-ids`
/// exists; callers receive `Err` if no `piggy-ids` is found in the
/// walk chain.
pub(crate) fn find_piggy_ids(root: &Path, subfolder: &str) -> Result<PathBuf, String> {
    let mut current = if subfolder.is_empty() {
        root.to_path_buf()
    } else {
        root.join(subfolder)
    };

    loop {
        let candidate = current.join("piggy-ids");
        if candidate.is_file() {
            return Ok(candidate);
        }
        if current == root {
            break;
        }
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => break,
        }
    }

    Err(format!(
        "no piggy-ids found under {} (run `piggy pass init -k <markl-id>` first)",
        root.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct FakeEnv(HashMap<&'static str, OsString>);

    impl EnvLookup for FakeEnv {
        fn get(&self, key: &str) -> Option<OsString> {
            self.0.get(key).cloned()
        }
    }

    fn fake(pairs: &[(&'static str, &str)]) -> FakeEnv {
        let mut m = HashMap::new();
        for (k, v) in pairs {
            m.insert(*k, OsString::from(*v));
        }
        FakeEnv(m)
    }

    #[test]
    fn store_root_prefers_piggy_store_dir() {
        let env = fake(&[
            ("PIGGY_STORE_DIR", "/a/piggy"),
            ("XDG_DATA_HOME", "/b/xdg"),
            ("HOME", "/c/home"),
        ]);
        assert_eq!(store_root_from(&env), PathBuf::from("/a/piggy"));
    }

    #[test]
    fn store_root_falls_back_to_xdg() {
        let env = fake(&[("XDG_DATA_HOME", "/b/xdg"), ("HOME", "/c/home")]);
        assert_eq!(store_root_from(&env), PathBuf::from("/b/xdg/piggy"));
    }

    #[test]
    fn store_root_falls_back_to_home() {
        let env = fake(&[("HOME", "/c/home")]);
        assert_eq!(
            store_root_from(&env),
            PathBuf::from("/c/home/.local/share/piggy")
        );
    }

    #[test]
    fn store_root_empty_piggy_dir_is_skipped() {
        let env = fake(&[("PIGGY_STORE_DIR", ""), ("HOME", "/c/home")]);
        assert_eq!(
            store_root_from(&env),
            PathBuf::from("/c/home/.local/share/piggy")
        );
    }

    #[test]
    fn store_roots_single_store_is_unchanged() {
        let env = fake(&[("PIGGY_STORE_DIR", "/a/piggy")]);
        assert_eq!(store_roots_from(&env), vec![PathBuf::from("/a/piggy")]);
    }

    #[test]
    fn store_roots_split_on_colon_in_order_skipping_empties() {
        let env = fake(&[("PIGGY_STORE_DIR", "/a/rw::/b/ro:")]);
        assert_eq!(
            store_roots_from(&env),
            vec![PathBuf::from("/a/rw"), PathBuf::from("/b/ro")]
        );
        assert_eq!(store_root_from(&env), PathBuf::from("/a/rw"));
    }

    #[test]
    fn store_roots_of_only_colons_fall_back() {
        let env = fake(&[("PIGGY_STORE_DIR", "::"), ("XDG_DATA_HOME", "/b/xdg")]);
        assert_eq!(store_roots_from(&env), vec![PathBuf::from("/b/xdg/piggy")]);
    }

    fn two_stores() -> (PathBuf, PathBuf) {
        let base = tempdir();
        let (rw, ro) = (base.join("rw"), base.join("ro"));
        std::fs::create_dir_all(rw.join("dir")).unwrap();
        std::fs::create_dir_all(ro.join("tent")).unwrap();
        std::fs::write(rw.join("both.ebox"), b"rw").unwrap();
        std::fs::write(ro.join("both.ebox"), b"ro").unwrap();
        std::fs::write(ro.join("tent/only-ro.ebox"), b"ro").unwrap();
        (rw, ro)
    }

    #[test]
    fn find_entry_takes_the_first_store_holding_it() {
        let (rw, ro) = two_stores();
        let roots = vec![rw.clone(), ro.clone()];
        assert_eq!(find_entry_in(&roots, "both"), Some(rw.join("both.ebox")));
        assert_eq!(
            find_entry_in(&roots, "tent/only-ro"),
            Some(ro.join("tent/only-ro.ebox"))
        );
        assert_eq!(find_entry_in(&roots, "absent"), None);
    }

    #[test]
    fn later_store_holding_names_the_store_a_write_would_refuse() {
        let (rw, ro) = two_stores();
        let roots = vec![rw.clone(), ro.clone()];
        assert_eq!(
            later_store_holding(&roots, "tent/only-ro"),
            Some(ro.as_path())
        );
        assert_eq!(later_store_holding(&roots, "tent"), Some(ro.as_path()));
        assert_eq!(
            later_store_holding(&roots, "both"),
            None,
            "the write store has it"
        );
        assert_eq!(later_store_holding(&roots, "absent"), None, "a new entry");
        assert_eq!(later_store_holding(&roots[..1], "tent/only-ro"), None);
    }

    #[test]
    fn the_refusal_names_both_stores_and_what_to_do() {
        let msg = not_in_write_store(
            "edit",
            "tent/x",
            Path::new("/ro/store"),
            Path::new("/rw/store"),
        );
        assert!(msg.contains("tent/x is in /ro/store"), "{msg}");
        assert!(msg.contains("the write store /rw/store"), "{msg}");
        assert!(msg.contains("piggy pass cp tent/x tent/x"), "{msg}");
        assert!(msg.contains("put /ro/store first"), "{msg}");
    }

    /// piggy#260: an absolute pass-name would make `root.join(name)` leave
    /// the store, so it is as sneaky as a `..` component.
    #[test]
    fn an_absolute_pass_name_is_sneaky() {
        assert_eq!(sneaky_path_reason("/etc/passwd"), Some("absolute path"));
        assert_eq!(sneaky_path_reason("a/../b"), Some("`..` component"));
        assert_eq!(sneaky_path_reason("a/b"), None);
        assert_eq!(sneaky_path_reason("a..b"), None);
        assert_eq!(sneaky_path_reason(""), None);
    }

    #[test]
    fn a_read_only_write_store_is_refused_naming_it() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempdir();
        assert_eq!(read_only_write_store("insert", &root), None);
        assert_eq!(
            read_only_write_store("insert", &root.join("not-yet")),
            None,
            "a store that does not exist yet is created on the first write"
        );
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o555)).unwrap();
        let msg = read_only_write_store("insert", &root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            msg.contains(&format!("the write store {}", root.display())),
            "{msg}"
        );
        assert!(msg.contains("cannot insert entries"), "{msg}");
        assert!(msg.contains("Put a writable store first"), "{msg}");
    }

    #[test]
    fn resolve_target_rejects_parent_dir() {
        let tmp = tempdir();
        let err = resolve_target(&tmp, Some("../etc")).unwrap_err();
        assert!(err.contains("escapes"), "got: {err}");
    }

    #[test]
    fn resolve_target_rejects_absolute() {
        let tmp = tempdir();
        let err = resolve_target(&tmp, Some("/etc/passwd")).unwrap_err();
        assert!(err.contains("relative"), "got: {err}");
    }

    #[test]
    fn resolve_target_rejects_empty() {
        let tmp = tempdir();
        let err = resolve_target(&tmp, Some("")).unwrap_err();
        assert!(err.contains("empty"), "got: {err}");
    }

    #[test]
    fn resolve_target_rejects_nul() {
        let tmp = tempdir();
        let err = resolve_target(&tmp, Some("foo\0bar")).unwrap_err();
        assert!(err.contains("NUL"), "got: {err}");
    }

    #[test]
    fn resolve_target_none_returns_root() {
        let tmp = tempdir();
        assert_eq!(resolve_target(&tmp, None).unwrap(), tmp);
    }

    #[test]
    fn find_piggy_ids_at_root() {
        let tmp = tempdir();
        std::fs::write(tmp.join("piggy-ids"), b"x").unwrap();
        let got = find_piggy_ids(&tmp, "").unwrap();
        assert_eq!(got, tmp.join("piggy-ids"));
    }

    #[test]
    fn find_piggy_ids_walks_up_to_root() {
        let tmp = tempdir();
        std::fs::create_dir_all(tmp.join("a/b/c")).unwrap();
        std::fs::write(tmp.join("piggy-ids"), b"x").unwrap();
        let got = find_piggy_ids(&tmp, "a/b/c").unwrap();
        assert_eq!(got, tmp.join("piggy-ids"));
    }

    #[test]
    fn find_piggy_ids_prefers_nearest() {
        let tmp = tempdir();
        std::fs::create_dir_all(tmp.join("a/b")).unwrap();
        std::fs::write(tmp.join("piggy-ids"), b"outer").unwrap();
        std::fs::write(tmp.join("a/piggy-ids"), b"inner").unwrap();
        let got = find_piggy_ids(&tmp, "a/b").unwrap();
        assert_eq!(got, tmp.join("a/piggy-ids"));
    }

    #[test]
    fn find_piggy_ids_errors_when_missing() {
        let tmp = tempdir();
        std::fs::create_dir_all(tmp.join("a")).unwrap();
        let err = find_piggy_ids(&tmp, "a").unwrap_err();
        assert!(err.contains("no piggy-ids"), "got: {err}");
    }

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "piggy-store-test-{}",
            std::process::id().wrapping_mul(0x9E37)
                ^ (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u32)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
