//! `reencrypt_path` port — walk every `*.ebox` under a target
//! directory, decrypt with `pivy-box stream decrypt`, re-encrypt with
//! `piggy-ids encrypt $piggy_ids`, and atomic-rename over the
//! original.
//!
//! Mirrors `reencrypt_path` in `src/piggy.sh:88`. Each file picks up
//! the **nearest** `piggy-ids` (walking up from the file's directory
//! toward the store root), matching the bash `find_piggy_ids
//! "$passfile_dir"` call inside the loop.
//!
//! Symlinked eboxes are **resolved and their real target rewritten**,
//! leaving the link in place. The bash original (and earlier Rust)
//! skipped symlinks outright (`[[ -L $passfile ]] && continue`), which
//! makes `recipients sync` a permanent no-op on a symlink-farm store
//! (e.g. a store whose entries all symlink into an rcm checkout). We
//! follow the link, decrypt+re-encrypt the canonical target file, and
//! atomic-rename over *that* path so the store's symlink keeps pointing
//! at a freshly-rewritten file. Targets are deduplicated by canonical
//! path so two links to the same file (or a link beside its own target)
//! are processed exactly once. A rewritten target may live outside the
//! store (in rcm); the caller's git-commit step is store-scoped and
//! simply finds nothing to stage for those — re-encryption still
//! happens, the rcm working tree is left dirty for the user's own rcm
//! workflow to commit.
//!
//! Per-file failures are non-fatal: the temp file is removed and the
//! walk continues. This matches the bash, which uses
//! `(pipeline && mv) || rm` so a failed pipeline doesn't abort the
//! whole pass.
//!
//! The Rust port spawns the decrypt and encrypt processes connected
//! by an OS pipe (no buffering plaintext in our address space) — same
//! risk profile as the bash pipeline.
//!
//! This module is reachable two ways:
//!
//! 1. From Rust callers (`init`, `mv`, `cp`, `recipients
//!    add/remove/sync`) via `reencrypt::run`.
//! 2. From the hidden top-level `piggy internal-reencrypt-path
//!    <dir>` subcommand, kept for backward compat with out-of-tree
//!    integrations that historically invoked the bash
//!    `reencrypt_path` shim.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use piggy_box::ebox::Ebox;
use piggy_box::piv_box::EcCurve;
use piggy_box::recipients::piv_part_from_markl;
use piggy_ids::RecipientFile;

use crate::store::{collect_eboxes, find_piggy_ids, store_root};

/// Walk every ebox under `target` and re-encrypt it to its nearest
/// `piggy-ids`, emitting a TAP-14 stream on stdout (one point per ebox).
///
/// Output: `TAP version 14`, a `1..N` plan, then one
/// `ok`/`not ok`/`ok … # SKIP` line per ebox. A point is `# SKIP`ped
/// when the ebox already encrypts to exactly the current recipient set
/// (see [`reencrypt_unnecessary`]); under `verbose`, every point also
/// carries a YAML diagnostic block. Failures always carry one.
/// Subprocess noise (`pivy-box`/`piggy-ids`) stays on stderr so the TAP
/// stream is clean.
///
/// Exit code:
/// - 0: every point was `ok` or `# SKIP` (walk completed, no failures)
/// - 1: at least one point was `not ok`, OR a pre-walk fatal (`Bail
///   out!`: target missing / walk error) prevented the plan
pub fn run(target: &Path, verbose: bool) -> i32 {
    let store = store_root();
    let target = if target.is_absolute() {
        target.to_path_buf()
    } else {
        store.join(target)
    };

    let mut tap = tap::Emitter::new(std::io::stdout().lock(), verbose);

    if !target.exists() {
        let _ = tap.bail_out(&format!("target does not exist: {}", target.display()));
        return 1;
    }

    let entries = match collect_eboxes_dedup_targets(&target) {
        Ok(v) => v,
        Err(err) => {
            let _ = tap.bail_out(&format!("walk {}: {}", target.display(), err));
            return 1;
        }
    };

    if tap.header(entries.len()).is_err() {
        return 1;
    }

    let mut any_failed = false;
    for (idx, (path, real)) in entries.iter().enumerate() {
        let n = idx + 1;

        // Relative display name (drop store root prefix and `.ebox`
        // suffix). Matches bash $passfile_display; used as the TAP
        // point description. Uses the store-side `path`, not the
        // resolved target.
        let display = display_name(path, &store);

        // Find the nearest piggy-ids for this file's directory. This
        // walks up from the STORE-SIDE path, so a symlink picks up the
        // piggy-ids governing its store location (the rcm-farm case has
        // a single store-side piggy-ids governing everything). Every
        // entry MUST produce exactly one point so the count matches the
        // `1..N` plan — the early-out arms emit `not ok`, never a silent
        // `continue`.
        let passfile_dir = match path.parent() {
            Some(p) => p,
            None => {
                let _ = tap.not_ok(n, &display, "no parent directory");
                any_failed = true;
                continue;
            }
        };
        let subfolder = passfile_dir
            .strip_prefix(&store)
            .unwrap_or(passfile_dir)
            .to_string_lossy()
            .into_owned();
        let piggy_ids = match find_piggy_ids(&store, &subfolder) {
            Ok(p) => p,
            Err(err) => {
                let _ = tap.not_ok(n, &display, &err);
                any_failed = true;
                continue;
            }
        };

        if reencrypt_unnecessary(path, &piggy_ids) {
            let _ = tap.skip(n, &display, "recipients already current");
            continue;
        }

        // `real` is the canonical (symlink-resolved) target, already
        // computed during the dedup walk — pass it straight through so
        // reencrypt_one doesn't re-`canonicalize`.
        match reencrypt_one(real, &piggy_ids) {
            Ok(()) => {
                let _ = tap.ok(n, &display);
            }
            Err(err) => {
                let _ = tap.not_ok(n, &display, &err);
                any_failed = true;
            }
        }
    }

    i32::from(any_failed)
}

/// True iff `ebox_path` already encrypts to exactly the recipient set
/// declared in `piggy_ids` — i.e. re-encryption would be a no-op and the
/// point can be `# SKIP`ped.
///
/// Recipient identity is the set of `(curve, pubkey-bytes)` pairs. The
/// ebox side comes from parsing the box header (cleartext recipient
/// pubkeys, no decrypt and no card); the piggy-ids side comes from
/// mapping each markl ID through [`piv_part_from_markl`].
///
/// Conservative by construction: any parse failure, a box pubkey that
/// doesn't decode as a point, a non-PIV (age) recipient, or an empty
/// recipient set yields `false` (→ re-encrypt). It never returns a
/// false-positive SKIP. Under the base64 bats mock the stored bytes are
/// not real ebox wire format, so [`Ebox::from_bytes`] fails and the walk
/// re-encrypts as before.
fn reencrypt_unnecessary(ebox_path: &Path, piggy_ids: &Path) -> bool {
    let (Some(want), Some(have)) = (
        recipients_from_piggy_ids(piggy_ids),
        recipients_from_ebox(ebox_path),
    ) else {
        return false;
    };
    !want.is_empty() && want == have
}

/// The recipient `(curve, pubkey)` set declared in a `piggy-ids` file.
/// `None` on read/parse failure or any recipient that doesn't map to a
/// PIV pubkey (e.g. age) — the caller treats `None` as "re-encrypt".
fn recipients_from_piggy_ids(piggy_ids: &Path) -> Option<RecipientSet> {
    let text = std::fs::read_to_string(piggy_ids).ok()?;
    let file = RecipientFile::parse(&text).ok()?;
    let mut set = BTreeSet::new();
    for r in file.recipients() {
        let part = piv_part_from_markl(r.id()).ok()?;
        let pubkey = canonical_point(part.pubkey_curve, &part.pubkey)?;
        set.insert((curve_tag(part.pubkey_curve), pubkey));
    }
    Some(set)
}

/// The recipient `(curve, pubkey)` set carried in an ebox's config
/// parts. `None` on read/parse failure.
///
/// The recipient pubkey is read from each part's `piv_box`
/// (`recipient_pubkey`/`curve`), NOT the top-level `EboxPart.pubkey` —
/// the wire writer never emits the `PART_PUBKEY` tag, so that field is
/// always `None` after a round-trip; the box's `recipient_pubkey` is the
/// authoritative recipient identity (`piggy-box`'s `write_ebox_part`).
fn recipients_from_ebox(ebox_path: &Path) -> Option<RecipientSet> {
    let bytes = std::fs::read(ebox_path).ok()?;
    let ebox = Ebox::from_bytes(&bytes).ok()?;
    let mut set = BTreeSet::new();
    for config in &ebox.configs {
        for part in &config.parts {
            let curve = part.piv_box.curve;
            let pubkey = canonical_point(curve, &part.piv_box.recipient_pubkey)?;
            set.insert((curve_tag(curve), pubkey));
        }
    }
    Some(set)
}

/// Re-encode an EC point to its canonical SEC 1 compressed form so the
/// two recipient-set sides compare apples-to-apples regardless of how
/// each happened to be encoded on input. `None` if `bytes` is not a
/// valid point on `curve`. (`piggy-box`'s `seal` already stores the
/// box's recipient pubkey compressed, and markl P-256 IDs carry the
/// compressed point, so this is normally an identity round-trip — but
/// normalizing both sides removes any latent compressed/uncompressed
/// drift, and a parse failure here just means "re-encrypt", never a
/// false SKIP.)
fn canonical_point(curve: EcCurve, bytes: &[u8]) -> Option<Vec<u8>> {
    use openssl::bn::BigNumContext;
    use openssl::ec::{EcGroup, EcPoint, PointConversionForm};

    let group = EcGroup::from_curve_name(curve.nid()).ok()?;
    let mut ctx = BigNumContext::new().ok()?;
    let point = EcPoint::from_bytes(&group, bytes, &mut ctx).ok()?;
    point
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
        .ok()
}

/// A recipient set keyed by `(curve-tag, pubkey-bytes)`. `EcCurve` is
/// neither `Ord` nor `Hash`, so it's projected to a stable `u8` tag via
/// [`curve_tag`] to make the tuple set-comparable.
type RecipientSet = BTreeSet<(u8, Vec<u8>)>;

/// Stable ordinal for an `EcCurve` so recipient tuples can live in a
/// `BTreeSet`. The exact values are arbitrary but MUST stay stable
/// within a run (both sides of the comparison use the same mapping).
fn curve_tag(curve: EcCurve) -> u8 {
    match curve {
        EcCurve::NistP256 => 0,
        EcCurve::NistP384 => 1,
    }
}

/// TAP version 14 producer for the re-encryption walk. Models the
/// `Emitter<W>` shape used by `show_batch`'s NDJSON stream
/// (`show_batch.rs`), but emits TAP lines directly: a `TAP version 14`
/// header + `1..N` plan, then `ok`/`not ok`/`ok … # SKIP` points, each
/// optionally followed by a YAML diagnostic block.
mod tap {
    use std::io::Write;

    pub struct Emitter<W: Write> {
        out: W,
        verbose: bool,
    }

    impl<W: Write> Emitter<W> {
        pub fn new(out: W, verbose: bool) -> Self {
            Self { out, verbose }
        }

        /// `TAP version 14` + the `1..count` plan. Emitted once, before
        /// any point.
        pub fn header(&mut self, count: usize) -> std::io::Result<()> {
            writeln!(self.out, "TAP version 14")?;
            writeln!(self.out, "1..{count}")
        }

        pub fn ok(&mut self, n: usize, name: &str) -> std::io::Result<()> {
            writeln!(self.out, "ok {n} - {name}")?;
            if self.verbose {
                self.yaml(&[("result", "reencrypted")])?;
            }
            Ok(())
        }

        pub fn skip(&mut self, n: usize, name: &str, reason: &str) -> std::io::Result<()> {
            writeln!(self.out, "ok {n} - {name} # SKIP {reason}")?;
            if self.verbose {
                self.yaml(&[("result", "skipped"), ("reason", reason)])?;
            }
            Ok(())
        }

        /// A failed point. The YAML diagnostic block is emitted
        /// unconditionally (independent of `verbose`) so a failure always
        /// carries its message.
        pub fn not_ok(&mut self, n: usize, name: &str, message: &str) -> std::io::Result<()> {
            writeln!(self.out, "not ok {n} - {name}")?;
            self.yaml(&[("message", message), ("severity", "fail")])
        }

        /// `Bail out!` — a pre-plan fatal that aborts the whole walk.
        pub fn bail_out(&mut self, reason: &str) -> std::io::Result<()> {
            writeln!(self.out, "Bail out! {reason}")
        }

        /// A TAP-14 YAML diagnostic block: a 2-space-indented `---` /
        /// `...` envelope with one `key: 'value'` line per field. Values
        /// are single-quoted scalars with any internal `'` doubled (the
        /// YAML escape), keeping the bounded key set safe without pulling
        /// in a YAML serializer.
        fn yaml(&mut self, fields: &[(&str, &str)]) -> std::io::Result<()> {
            writeln!(self.out, "  ---")?;
            for (key, value) in fields {
                writeln!(self.out, "  {key}: '{}'", value.replace('\'', "''"))?;
            }
            writeln!(self.out, "  ...")
        }
    }
}

/// Walk like `collect_eboxes`, following symlinks, but deduplicate
/// entries by their canonical (symlink-resolved) target so a file
/// reachable by more than one path — a symlink beside its own target,
/// or two symlinks into the same rcm file — is re-encrypted exactly
/// once.
///
/// Returns `(store_side, canonical_real)` pairs, one per distinct
/// target, keyed on the first store-side path seen (sorted order). The
/// caller uses `store_side` for `display_name` and the nearest-
/// `piggy-ids` walk (both want the store's view), and `canonical_real`
/// as the file to rewrite — resolving the symlink exactly once here so
/// `reencrypt_one` doesn't `canonicalize` a second time.
fn collect_eboxes_dedup_targets(root: &Path) -> std::io::Result<Vec<(PathBuf, PathBuf)>> {
    let entries = collect_eboxes(root)?;
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(entries.len());
    for path in entries {
        // Canonicalize to collapse symlinks; on failure (dangling link,
        // race) fall back to the path itself so we still attempt it
        // once and surface the real error at reencrypt time.
        let real = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        if seen.insert(real.clone()) {
            out.push((path, real));
        }
    }
    Ok(out)
}

fn display_name(path: &Path, store: &Path) -> String {
    let rel = path.strip_prefix(store).unwrap_or(path);
    let rel_str = rel.to_string_lossy();
    rel_str
        .strip_suffix(".ebox")
        .unwrap_or(&rel_str)
        .to_string()
}

/// Run `pivy-box stream decrypt < real | piggy-ids encrypt $piggy_ids > tmp`
/// connected by an OS pipe, then atomic-rename tmp over `real`.
///
/// `real` is the canonical (symlink-resolved) target, resolved once by
/// [`collect_eboxes_dedup_targets`]. When the store-side entry was a
/// symlink (e.g. into an rcm checkout), `real` is the file the link
/// points at: the tmp is created as a sibling of `real` and
/// atomic-renamed over it, so the store's symlink is left untouched and
/// keeps pointing at a freshly-rewritten file. Renaming over the link
/// directly would replace the link with a regular file and orphan the
/// real target — the hazard the old skip-symlinks behavior avoided by
/// refusing to act at all.
fn reencrypt_one(real: &Path, piggy_ids: &Path) -> Result<(), String> {
    let tmp = make_tmp_path(real);

    let pipeline_result = (|| -> Result<(), String> {
        let input = std::fs::File::open(real).map_err(|e| format!("open passfile: {e}"))?;

        let mut decrypt_cmd = Command::new("pivy-box");
        decrypt_cmd
            .arg("stream")
            .arg("decrypt")
            .stdin(input)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        // Prefer piggy's own agent socket over the ambient SSH_AUTH_SOCK
        // (commonly an ssh-agent-mux that may not advertise ecdh@joyent.com).
        // The binary and library crates are disjoint, so this mirrors
        // piggy::agent_client::piggy_auth_sock_override rather than calling
        // it. See #123.
        if let Some(sock) = std::env::var_os("PIGGY_AUTH_SOCK").filter(|s| !s.is_empty()) {
            decrypt_cmd.env("SSH_AUTH_SOCK", sock);
        }
        let mut decrypt = decrypt_cmd
            .spawn()
            .map_err(|e| format!("spawn pivy-box: {e}"))?;

        let decrypt_stdout = decrypt
            .stdout
            .take()
            .ok_or_else(|| "pivy-box stdout unavailable".to_string())?;

        let piggy_ids_bin: OsString =
            std::env::var_os("PIGGY_IDS_PATH").unwrap_or_else(|| OsString::from("piggy-ids"));

        let tmp_file = std::fs::File::create(&tmp)
            .map_err(|e| format!("create tmp {}: {}", tmp.display(), e))?;

        let mut encrypt = Command::new(&piggy_ids_bin)
            .arg("encrypt")
            .arg(piggy_ids)
            .stdin(decrypt_stdout)
            .stdout(tmp_file)
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("spawn piggy-ids: {e}"))?;

        let decrypt_status = decrypt.wait().map_err(|e| format!("wait pivy-box: {e}"))?;
        let encrypt_status = encrypt.wait().map_err(|e| format!("wait piggy-ids: {e}"))?;

        if !decrypt_status.success() {
            return Err(format!("pivy-box exited {decrypt_status}"));
        }
        if !encrypt_status.success() {
            return Err(format!("piggy-ids encrypt exited {encrypt_status}"));
        }
        Ok(())
    })();

    match pipeline_result {
        // Rename over the resolved real target, not the store-side
        // symlink, so the link stays a link pointing at the rewritten
        // file.
        Ok(()) => std::fs::rename(&tmp, real).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("rename {} -> {}: {}", tmp.display(), real.display(), e)
        }),
        Err(err) => {
            let _ = std::fs::remove_file(&tmp);
            Err(err)
        }
    }
}

/// `${passfile}.tmp.<RANDOM>.<RANDOM>.<RANDOM>.<RANDOM>.--` to match
/// the bash naming pattern (informational; the file is always
/// renamed or removed).
fn make_tmp_path(passfile: &Path) -> PathBuf {
    let parent = passfile.parent().unwrap_or_else(|| Path::new("."));
    let name = passfile
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "ebox".to_string());
    let suffix = format!(
        "{}.tmp.{}.{}.{}.{}.--",
        name,
        pseudo_random(),
        pseudo_random(),
        pseudo_random(),
        pseudo_random(),
    );
    parent.join(suffix)
}

fn pseudo_random() -> u32 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    nanos
        .wrapping_mul(2654435761)
        .wrapping_add(pid.wrapping_mul(0x9E37))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_name_strips_store_root_and_ebox() {
        let store = Path::new("/store");
        let path = Path::new("/store/folder/cred1.ebox");
        assert_eq!(display_name(path, store), "folder/cred1");
    }

    #[test]
    fn display_name_top_level() {
        let store = Path::new("/store");
        let path = Path::new("/store/cred1.ebox");
        assert_eq!(display_name(path, store), "cred1");
    }

    #[test]
    fn tmp_path_uses_passfile_dir() {
        let p = Path::new("/store/folder/cred1.ebox");
        let tmp = make_tmp_path(p);
        assert_eq!(tmp.parent(), Some(Path::new("/store/folder")));
        assert!(
            tmp.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("cred1.ebox.tmp.") && s.ends_with(".--")),
            "unexpected tmp name: {:?}",
            tmp.file_name()
        );
    }

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "piggy-reencrypt-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// A symlinked ebox is now collected (not skipped). The walk follows
    /// the link, so the entry shows up exactly once.
    #[test]
    fn collect_follows_symlinked_ebox() {
        let dir = tempdir();
        let real = dir.join("real.ebox");
        std::fs::write(&real, b"ciphertext").unwrap();
        let link = dir.join("link.ebox");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // Drop the real file from the walk root so only the link is
        // present under `root`, proving the link itself is collected.
        let root = tempdir();
        let root_link = root.join("link.ebox");
        std::os::unix::fs::symlink(&real, &root_link).unwrap();

        let got = collect_eboxes_dedup_targets(&root).unwrap();
        assert_eq!(got.len(), 1, "expected the single link, got: {got:?}");
        let (store_side, resolved) = &got[0];
        assert_eq!(store_side, &root_link, "store-side path must be the link");
        assert_eq!(
            resolved,
            &std::fs::canonicalize(&real).unwrap(),
            "resolved target must be the real file"
        );
    }

    /// A symlink sitting beside its own target (both under the walk
    /// root, both resolving to the same file) is collected exactly once
    /// — we must not decrypt+re-encrypt the same file twice in one pass.
    #[test]
    fn collect_dedups_link_beside_its_target() {
        let root = tempdir();
        let real = root.join("real.ebox");
        std::fs::write(&real, b"ciphertext").unwrap();
        let link = root.join("link.ebox");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let got = collect_eboxes_dedup_targets(&root).unwrap();
        assert_eq!(
            got.len(),
            1,
            "link + its target must collapse to one entry, got: {got:?}"
        );
        // The surviving entry's resolved target is the real file
        // (whichever store-side path sorted first is kept).
        let (_, resolved) = &got[0];
        assert_eq!(resolved, &std::fs::canonicalize(&real).unwrap());
    }

    /// Two distinct symlinks pointing at the same out-of-root target
    /// collapse to a single entry.
    #[test]
    fn collect_dedups_two_links_to_same_target() {
        let target_dir = tempdir();
        let real = target_dir.join("shared.ebox");
        std::fs::write(&real, b"ciphertext").unwrap();

        let root = tempdir();
        let a = root.join("a.ebox");
        let b = root.join("b.ebox");
        std::os::unix::fs::symlink(&real, &a).unwrap();
        std::os::unix::fs::symlink(&real, &b).unwrap();

        let got = collect_eboxes_dedup_targets(&root).unwrap();
        assert_eq!(
            got.len(),
            1,
            "two links to one target must collapse to one entry, got: {got:?}"
        );
        let (_, resolved) = &got[0];
        assert_eq!(resolved, &std::fs::canonicalize(&real).unwrap());
    }

    // ---- TAP-14 emitter ----

    fn render(verbose: bool, body: impl FnOnce(&mut tap::Emitter<&mut Vec<u8>>)) -> String {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut emitter = tap::Emitter::new(&mut buf, verbose);
            body(&mut emitter);
        }
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn tap_minimal_renders_version_plan_and_points() {
        let out = render(false, |e| {
            e.header(3).unwrap();
            e.ok(1, "folder/cred1").unwrap();
            e.skip(2, "baz", "recipients already current").unwrap();
            e.not_ok(3, "secret/x", "pivy-box exited status 1").unwrap();
        });
        assert_eq!(
            out,
            "TAP version 14\n\
1..3\n\
ok 1 - folder/cred1\n\
ok 2 - baz # SKIP recipients already current\n\
not ok 3 - secret/x\n  ---\n  message: 'pivy-box exited status 1'\n  severity: 'fail'\n  ...\n"
        );
    }

    #[test]
    fn tap_verbose_adds_yaml_on_ok_and_skip() {
        let out = render(true, |e| {
            e.header(2).unwrap();
            e.ok(1, "a").unwrap();
            e.skip(2, "b", "recipients already current").unwrap();
        });
        assert_eq!(
            out,
            "TAP version 14\n\
1..2\n\
ok 1 - a\n  ---\n  result: 'reencrypted'\n  ...\n\
ok 2 - b # SKIP recipients already current\n  ---\n  result: 'skipped'\n  reason: 'recipients already current'\n  ...\n"
        );
    }

    #[test]
    fn tap_yaml_single_quotes_are_doubled() {
        let out = render(false, |e| {
            e.not_ok(1, "x", "it's a 'quoted' error").unwrap();
        });
        assert!(
            out.contains("  message: 'it''s a ''quoted'' error'\n"),
            "got: {out}"
        );
    }

    #[test]
    fn tap_empty_plan_and_bail_out() {
        assert_eq!(
            render(false, |e| e.header(0).unwrap()),
            "TAP version 14\n1..0\n"
        );
        assert_eq!(
            render(false, |e| e.bail_out("target does not exist: /x").unwrap()),
            "Bail out! target does not exist: /x\n"
        );
    }

    // ---- recipients-match SKIP ----

    use openssl::bn::BigNumContext;
    use openssl::ec::{EcGroup, EcKey, PointConversionForm};
    use openssl::nid::Nid;
    use piggy_box::ebox::EboxType;
    use piggy_box::recipients::template_from_recipients;
    use piggy_ids::Recipient;
    use piggy_markl::{FormatId, Id, PurposeId};

    /// A fresh, curve-valid P-256 recipient markl ID. Its `data()` is the
    /// 33-byte SEC 1 compressed point, matching what `piv_part_from_markl`
    /// and `Ebox::create` consume.
    fn fresh_p256_id() -> Id {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let pubkey = key
            .public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap();
        Id::new(
            Some(PurposeId::PiggyRecipientV1),
            FormatId::PivyEcdhP256Pub,
            pubkey,
        )
        .unwrap()
    }

    /// Encrypt a real `.ebox` (stream type) to `ids` and write it under `dir`.
    fn write_ebox_for(dir: &Path, ids: &[Id]) -> PathBuf {
        let tpl = template_from_recipients(ids).unwrap();
        let ebox = Ebox::create(&tpl, b"piggy-test-secret", EboxType::Stream).unwrap();
        let path = dir.join("cred.ebox");
        std::fs::write(&path, ebox.to_bytes().unwrap()).unwrap();
        path
    }

    /// Render a canonical `piggy-ids` file listing `ids` under `dir`.
    fn write_piggy_ids_for(dir: &Path, ids: &[Id]) -> PathBuf {
        let recipients = ids
            .iter()
            .map(|id| Recipient::new(id.clone(), None).unwrap())
            .collect();
        let path = dir.join("piggy-ids");
        std::fs::write(&path, RecipientFile::new(recipients).render()).unwrap();
        path
    }

    #[test]
    fn reencrypt_unnecessary_true_when_recipients_match() {
        let dir = tempdir();
        let ids = vec![fresh_p256_id(), fresh_p256_id()];
        let ebox = write_ebox_for(&dir, &ids);
        let pids = write_piggy_ids_for(&dir, &ids);
        assert!(reencrypt_unnecessary(&ebox, &pids));
    }

    #[test]
    fn reencrypt_unnecessary_false_when_recipient_added() {
        let dir = tempdir();
        let a = fresh_p256_id();
        let b = fresh_p256_id();
        let ebox = write_ebox_for(&dir, std::slice::from_ref(&a));
        let pids = write_piggy_ids_for(&dir, &[a, b]);
        assert!(!reencrypt_unnecessary(&ebox, &pids));
    }

    #[test]
    fn reencrypt_unnecessary_false_when_recipient_removed() {
        let dir = tempdir();
        let a = fresh_p256_id();
        let b = fresh_p256_id();
        let ebox = write_ebox_for(&dir, &[a.clone(), b]);
        let pids = write_piggy_ids_for(&dir, std::slice::from_ref(&a));
        assert!(!reencrypt_unnecessary(&ebox, &pids));
    }

    #[test]
    fn reencrypt_unnecessary_false_on_unparseable_ebox() {
        // The base64 bats mock writes opaque non-ebox bytes; the SKIP
        // check must conservatively treat them as "necessary".
        let dir = tempdir();
        let pids = write_piggy_ids_for(&dir, &[fresh_p256_id()]);
        let ebox = dir.join("garbage.ebox");
        std::fs::write(&ebox, b"not an ebox, just base64-ish text\n").unwrap();
        assert!(!reencrypt_unnecessary(&ebox, &pids));
    }

    #[test]
    fn ebox_and_piggy_ids_recipient_sets_agree() {
        // Pins the load-bearing invariant for SKIP: the recipient set
        // extracted from a real ebox equals the set extracted from a
        // piggy-ids listing the same recipient. Both go through
        // `canonical_point`, so this is encoding-agnostic.
        let dir = tempdir();
        let id = fresh_p256_id();
        let ebox = write_ebox_for(&dir, std::slice::from_ref(&id));
        let pids = write_piggy_ids_for(&dir, std::slice::from_ref(&id));
        let from_ebox = recipients_from_ebox(&ebox).unwrap();
        let from_ids = recipients_from_piggy_ids(&pids).unwrap();
        assert_eq!(from_ebox.len(), 1);
        assert_eq!(from_ebox, from_ids);
    }
}
