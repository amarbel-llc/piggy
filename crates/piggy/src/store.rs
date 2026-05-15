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

/// Resolve `$PIGGY_STORE_DIR` with the same precedence as piggy.sh:
/// PIGGY_STORE_DIR > $XDG_DATA_HOME/piggy > $HOME/.local/share/piggy.
pub(crate) fn store_root() -> PathBuf {
    store_root_from(&RealEnv)
}

pub(crate) fn store_root_from(env: &dyn EnvLookup) -> PathBuf {
    if let Some(v) = env.get("PIGGY_STORE_DIR") {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    if let Some(v) = env.get("XDG_DATA_HOME") {
        if !v.is_empty() {
            return PathBuf::from(v).join("piggy");
        }
    }
    let home = env.get("HOME").unwrap_or_default();
    PathBuf::from(home).join(".local/share/piggy")
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
