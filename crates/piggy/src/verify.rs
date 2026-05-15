//! `piggy pass verify [subpath]` — decrypt every *.ebox under the
//! store (or a sub-tree) and emit a tree-decorated ok/not-ok report.
//!
//! Sequential by design — piv-card serialization makes parallelism a
//! non-win and the simple model is easier to reason about.
//!
//! Path rendering is lossy on non-UTF-8 path segments (matches the
//! bash code which passes raw bytes through `tree(1)`); store entries
//! in practice are always UTF-8 paths.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MAX_DEPTH: usize = 64;

/// Exit code conventions:
/// - 0: every entry decrypted successfully (or store is empty)
/// - 1: at least one entry failed to decrypt
/// - 2: usage / IO error before verification could begin
pub fn run(subpath: Option<&str>) -> i32 {
    let root = store_root();
    let target = match resolve_target(&root, subpath) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("piggy pass verify: {msg}");
            return 2;
        }
    };

    if !target.exists() {
        return 0;
    }

    let entries = match collect_eboxes(&target) {
        Ok(v) => v,
        Err(err) => {
            eprintln!(
                "piggy pass verify: failed to walk {}: {}",
                target.display(),
                err
            );
            return 2;
        }
    };

    let mut results: Vec<(PathBuf, VerifyResult)> = Vec::with_capacity(entries.len());
    let mut any_fail = false;
    for path in entries {
        let result = verify_one(&path);
        if matches!(result, VerifyResult::Fail(_)) {
            any_fail = true;
        }
        results.push((path, result));
    }

    let rendered = render_tree(&target, &results);
    print!("{rendered}");

    if any_fail {
        1
    } else {
        0
    }
}

#[derive(Debug, PartialEq, Eq)]
enum VerifyResult {
    Ok,
    Fail(String),
}

trait EnvLookup {
    fn get(&self, key: &str) -> Option<OsString>;
}

struct RealEnv;

impl EnvLookup for RealEnv {
    fn get(&self, key: &str) -> Option<OsString> {
        std::env::var_os(key)
    }
}

fn store_root() -> PathBuf {
    store_root_from(&RealEnv)
}

fn store_root_from(env: &dyn EnvLookup) -> PathBuf {
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

fn resolve_target(root: &Path, subpath: Option<&str>) -> Result<PathBuf, String> {
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

fn collect_eboxes(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    walk(root, 0, &mut out)?;
    out.sort();
    Ok(out)
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if depth > MAX_DEPTH {
        return Ok(());
    }
    let meta = match std::fs::metadata(dir) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };
    if !meta.is_dir() {
        return Ok(());
    }
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(err) => {
            return Err(err);
        }
    };
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
        } else if file_type.is_file() {
            if is_ebox(&path) {
                out.push(path);
            }
        }
    }
    Ok(())
}

fn is_ebox(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("ebox"))
}

fn verify_one(path: &Path) -> VerifyResult {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(err) => return VerifyResult::Fail(format!("open: {err}")),
    };

    let mut child = match Command::new("pivy-box")
        .arg("stream")
        .arg("decrypt")
        .arg("-b")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(err) => return VerifyResult::Fail(format!("spawn pivy-box: {err}")),
    };

    {
        let mut stdin = match child.stdin.take() {
            Some(s) => s,
            None => {
                return VerifyResult::Fail("pivy-box stdin unavailable".into());
            }
        };
        let mut reader = file;
        if let Err(err) = std::io::copy(&mut reader, &mut stdin) {
            return VerifyResult::Fail(format!("write to pivy-box: {err}"));
        }
        let _ = stdin.flush();
    }

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(err) => return VerifyResult::Fail(format!("wait pivy-box: {err}")),
    };

    if output.status.success() {
        VerifyResult::Ok
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let last = stderr
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("")
            .trim();
        let msg = if last.is_empty() {
            match output.status.code() {
                Some(c) => format!("exit {c}"),
                None => "killed by signal".into(),
            }
        } else {
            last.to_string()
        };
        VerifyResult::Fail(msg)
    }
}

enum Node {
    Dir(BTreeMap<OsString, Node>),
    Leaf(VerifyResult),
}

fn render_tree(root: &Path, entries: &[(PathBuf, VerifyResult)]) -> String {
    let mut root_node: BTreeMap<OsString, Node> = BTreeMap::new();
    for (path, result) in entries {
        let rel = path.strip_prefix(root).unwrap_or(path);
        let segments: Vec<OsString> = rel
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(s) => Some(s.to_os_string()),
                _ => None,
            })
            .collect();
        if segments.is_empty() {
            continue;
        }
        insert_path(&mut root_node, &segments, 0, result);
    }

    let mut out = String::new();
    render_top_level(&root_node, &mut out);
    out
}

fn insert_path(
    node: &mut BTreeMap<OsString, Node>,
    segments: &[OsString],
    idx: usize,
    result: &VerifyResult,
) {
    let is_leaf = idx == segments.len() - 1;
    let key = if is_leaf {
        strip_ebox(&segments[idx])
    } else {
        segments[idx].clone()
    };

    if is_leaf {
        let leaf_result = match result {
            VerifyResult::Ok => VerifyResult::Ok,
            VerifyResult::Fail(msg) => VerifyResult::Fail(msg.clone()),
        };
        node.insert(key, Node::Leaf(leaf_result));
    } else {
        let child = node
            .entry(key)
            .or_insert_with(|| Node::Dir(BTreeMap::new()));
        if let Node::Dir(sub) = child {
            insert_path(sub, segments, idx + 1, result);
        }
        // If a leaf existed at this position something is structurally
        // off (e.g. a directory named the same as a stripped leaf);
        // silently overwrite would mask data. For v1 we leave the
        // existing leaf in place and skip — verify is read-only on
        // disk so the situation is unlikely.
    }
}

fn strip_ebox(name: &OsString) -> OsString {
    let s = name.to_string_lossy();
    if let Some(stripped) = s.strip_suffix(".ebox") {
        OsString::from(stripped)
    } else if let Some(stripped) = s.to_lowercase().strip_suffix(".ebox") {
        // case-insensitive fallback; preserve original casing of the
        // surviving prefix
        OsString::from(&s[..stripped.len()])
    } else {
        name.clone()
    }
}

fn render_top_level(node: &BTreeMap<OsString, Node>, out: &mut String) {
    for (name, child) in node.iter() {
        match child {
            Node::Dir(sub) => {
                let _ = writeln!(out, "{}", name.to_string_lossy());
                render_subtree(sub, "", out);
            }
            Node::Leaf(result) => {
                write_leaf(out, "", name, result);
            }
        }
    }
}

fn render_subtree(node: &BTreeMap<OsString, Node>, prefix: &str, out: &mut String) {
    let total = node.len();
    for (i, (name, child)) in node.iter().enumerate() {
        let last = i == total - 1;
        let branch = if last { "└── " } else { "├── " };
        let next_prefix = if last { "    " } else { "│   " };
        match child {
            Node::Dir(sub) => {
                let _ = writeln!(out, "{prefix}{branch}{}", name.to_string_lossy());
                let mut deeper = String::from(prefix);
                deeper.push_str(next_prefix);
                render_subtree(sub, &deeper, out);
            }
            Node::Leaf(result) => {
                write_leaf_branched(out, prefix, branch, name, result);
            }
        }
    }
}

fn write_leaf(out: &mut String, prefix: &str, name: &OsString, result: &VerifyResult) {
    match result {
        VerifyResult::Ok => {
            let _ = writeln!(out, "{prefix}ok     {}", name.to_string_lossy());
        }
        VerifyResult::Fail(msg) => {
            let _ = writeln!(out, "{prefix}not ok {}  ({msg})", name.to_string_lossy());
        }
    }
}

fn write_leaf_branched(
    out: &mut String,
    prefix: &str,
    branch: &str,
    name: &OsString,
    result: &VerifyResult,
) {
    match result {
        VerifyResult::Ok => {
            let _ = writeln!(out, "{prefix}{branch}ok     {}", name.to_string_lossy());
        }
        VerifyResult::Fail(msg) => {
            let _ = writeln!(
                out,
                "{prefix}{branch}not ok {}  ({msg})",
                name.to_string_lossy()
            );
        }
    }
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
    fn render_tree_matches_spec_sample() {
        let root = PathBuf::from("/store");
        let entries: Vec<(PathBuf, VerifyResult)> = vec![
            (
                root.join("rcm/config/ssh/rcm/config-user-secret.ebox"),
                VerifyResult::Ok,
            ),
            (
                root.join("rcm/config/ssh/rcm/old-key.ebox"),
                VerifyResult::Fail("LocalUnlockError: no matching key".into()),
            ),
            (root.join("work/aws/prod.ebox"), VerifyResult::Ok),
        ];
        let got = render_tree(&root, &entries);
        let want = concat!(
            "rcm\n",
            "└── config\n",
            "    └── ssh\n",
            "        └── rcm\n",
            "            ├── ok     config-user-secret\n",
            "            └── not ok old-key  (LocalUnlockError: no matching key)\n",
            "work\n",
            "└── aws\n",
            "    └── ok     prod\n",
        );
        assert_eq!(got, want, "\n--- got ---\n{got}\n--- want ---\n{want}");
    }

    #[test]
    fn render_tree_empty_is_empty() {
        let root = PathBuf::from("/store");
        assert_eq!(render_tree(&root, &[]), "");
    }

    #[test]
    fn render_tree_single_top_level_leaf() {
        let root = PathBuf::from("/store");
        let entries = vec![(root.join("only.ebox"), VerifyResult::Ok)];
        assert_eq!(render_tree(&root, &entries), "ok     only\n");
    }

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "piggy-verify-test-{}",
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
