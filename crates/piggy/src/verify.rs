//! `piggy pass verify [subpath]` — decrypt every *.ebox under the
//! store (or a sub-tree) and emit a tree-decorated ok/not-ok report.
//!
//! Sequential by design — piv-card serialization makes parallelism a
//! non-win and the simple model is easier to reason about.
//!
//! Path rendering is lossy on non-UTF-8 path segments (matches the
//! bash code which passes raw bytes through `tree(1)`); store entries
//! in practice are always UTF-8 paths.

use std::path::{Path, PathBuf};

use crate::store::{resolve_target, store_roots};
use crate::store_tree::{StoreTree, UnreadableSubdir, render_tree, walk_tree, without_empty_dirs};

/// Exit code conventions:
/// - 0: every entry decrypted successfully (or store is empty)
/// - 1: at least one entry failed to decrypt
/// - 2: usage / IO error before verification could begin
pub fn run(subpath: Option<&str>) -> i32 {
    let roots = store_roots();
    if roots.len() == 1 {
        return verify_store(&roots[0], subpath);
    }
    // piggy#330: every store holding the subpath gets its own report,
    // headed by its path; shadowed entries are verified too, since each
    // store's ciphertexts are checked for themselves.
    let holders: Vec<&PathBuf> = roots
        .iter()
        .filter(|root| subpath.is_none_or(|sub| root.join(sub).exists()))
        .collect();
    if holders.is_empty() {
        return verify_store(&roots[0], subpath);
    }
    let mut code = 0;
    for root in holders {
        println!("{}", root.display());
        code = code.max(verify_store(root, subpath));
    }
    code
}

fn verify_store(root: &Path, subpath: Option<&str>) -> i32 {
    let target = match resolve_target(root, subpath) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("piggy pass verify: {msg}");
            return 2;
        }
    };

    if !target.exists() {
        return 0;
    }

    // Only directories that hold an ebox are reported.
    let tree = match walk_tree(&target, UnreadableSubdir::Fail) {
        Ok(tree) => without_empty_dirs(tree),
        Err(err) => {
            eprintln!(
                "piggy pass verify: failed to walk {}: {}",
                target.display(),
                err
            );
            return 2;
        }
    };

    // One decryptor for the whole walk: the C era ran `pivy-box stream
    // decrypt -b` per ebox (batch: agent only, never a PIN prompt). In
    // process the card path is available too, and the shared oracle
    // caches the PIN per card, so an agentless verify prompts at most
    // once for the whole store rather than failing every entry. A true
    // no-prompt run is `SSH_ASKPASS_REQUIRE=never` without a tty.
    let mut decryptor = piggy::cmd::pivy_box::Decryptor::from_env();
    let mut any_fail = false;
    let rendered = render_report(&tree, |path| {
        let result = verify_one(path, &mut decryptor);
        any_fail |= matches!(result, VerifyResult::Fail(_));
        result
    });
    print!("{rendered}");

    if any_fail { 1 } else { 0 }
}

/// The report: the top tier bare, each ebox `ok     NAME` or
/// `not ok NAME  (MSG)`, verified by `verify` in tree order.
fn render_report(tree: &[StoreTree], mut verify: impl FnMut(&Path) -> VerifyResult) -> String {
    render_tree(tree, false, |name, path| match verify(path) {
        VerifyResult::Ok => format!("ok     {name}"),
        VerifyResult::Fail(msg) => format!("not ok {name}  ({msg})"),
    })
}

#[derive(Debug, PartialEq, Eq)]
enum VerifyResult {
    Ok,
    Fail(String),
}

fn verify_one(path: &Path, decryptor: &mut piggy::cmd::pivy_box::Decryptor) -> VerifyResult {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(err) => return VerifyResult::Fail(format!("open: {err}")),
    };
    match decryptor.decrypt(&bytes) {
        Ok(_) => VerifyResult::Ok,
        Err(msg) => VerifyResult::Fail(msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(files: &[&str]) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "piggy-verify-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        for f in files {
            let p = root.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, b"x").unwrap();
        }
        root
    }

    /// The report for the store at `root`, each ebox failing when its file
    /// name is in `failing`.
    fn report(root: &Path, failing: &[(&str, &str)]) -> String {
        let tree = without_empty_dirs(walk_tree(root, UnreadableSubdir::Fail).unwrap());
        render_report(&tree, |path| {
            let file = path.file_name().unwrap().to_str().unwrap();
            match failing.iter().find(|(name, _)| *name == file) {
                Some((_, msg)) => VerifyResult::Fail(msg.to_string()),
                None => VerifyResult::Ok,
            }
        })
    }

    #[test]
    fn report_matches_spec_sample() {
        let root = store(&[
            "rcm/config/ssh/rcm/config-user-secret.ebox",
            "rcm/config/ssh/rcm/old-key.ebox",
            "work/aws/prod.ebox",
            "work/notes.txt",
        ]);
        std::fs::create_dir_all(root.join("empty/deeper")).unwrap();
        let got = report(
            &root,
            &[("old-key.ebox", "LocalUnlockError: no matching key")],
        );
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
    fn report_of_an_empty_store_is_empty() {
        let root = store(&["notes.txt"]);
        assert_eq!(report(&root, &[]), "");
    }

    #[test]
    fn report_single_top_level_leaf() {
        let root = store(&["only.ebox"]);
        assert_eq!(report(&root, &[]), "ok     only\n");
    }
}
