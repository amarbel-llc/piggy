//! Sniffs a `piggy-ids` path's content (RFC 0003 legacy lines, a pigpen
//! recipient-set-face document, or a pigpen pointer-face document —
//! RFC 0009 §3.2, RFC 0008 §2.2) and returns a path every existing
//! consumer (in-process readers and the external `piggy-ids`/`pivy-box`
//! subprocesses) can treat exactly like a plain RFC 0003 file.
//!
//! For the RFC 0003 case this is a no-op passthrough of the input path
//! (zero behavior change). For a pigpen recipient-set document it
//! converts to RFC 0003 text and writes it to a cache file, returning
//! that path instead. Pointer-face resolution (RFC 0010) is wired in by
//! a later task; for now a pointer face is treated as an error.

use std::path::{Path, PathBuf};

/// See module docs. Returns the path a caller should read/pass to a
/// subprocess in place of the raw `piggy-ids` path.
pub(crate) fn resolve_piggy_ids_path(piggy_ids: &Path) -> Result<PathBuf, String> {
    let raw =
        std::fs::read(piggy_ids).map_err(|e| format!("reading {}: {e}", piggy_ids.display()))?;

    // RFC 0009 §3.2's one-byte sniff: a hyphence document opens with
    // the literal boundary; an RFC 0003 file's first non-blank line is
    // a `#` comment or a bare markl ID, never `---`.
    if !raw.starts_with(b"---\n") {
        return Ok(piggy_ids.to_path_buf());
    }

    if let Ok(ptr) = piggy_pigpen::Pointer::parse(&raw) {
        return Err(format!(
            "{}: pointer face (kind={:?}, locator={:?}) — resolver dispatch not yet wired",
            piggy_ids.display(),
            ptr.kind,
            ptr.locator
        ));
    }

    let doc = piggy_pigpen::Document::parse(&raw)
        .map_err(|e| format!("parsing {} as a pigpen document: {e}", piggy_ids.display()))?;
    let recipients: Result<Vec<piggy_ids::Recipient>, String> = doc
        .recipients
        .into_iter()
        .map(|r| {
            piggy_ids::Recipient::new(r.id, r.comment)
                .map_err(|e| format!("converting recipient: {e}"))
        })
        .collect();
    let rendered = piggy_ids::RecipientFile::new(recipients?).render();

    let cache_path = cache_path_for(piggy_ids)?;
    if let Some(parent) = cache_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    std::fs::write(&cache_path, rendered)
        .map_err(|e| format!("writing {}: {e}", cache_path.display()))?;
    Ok(cache_path)
}

/// Like [`resolve_piggy_ids_path`], but for callers that intend to WRITE
/// to the returned path to persist a change to the `piggy-ids` content
/// itself (`recipients add`/`remove`/`sync`). Refuses — rather than
/// silently redirecting a write to a throwaway cache file — when the
/// content is resolver/pigpen-backed: RFC 0009's payload-less pigpen
/// face has no write-back format defined yet, and a pointer face's
/// recipient set lives at the remote source, so local mutation would be
/// meaningless (piggy#216). Detected by comparing the resolved path
/// against the input: [`resolve_piggy_ids_path`]'s RFC 0003 passthrough
/// case is the only one that returns the input path unchanged.
pub(crate) fn resolve_piggy_ids_path_for_mutation(piggy_ids: &Path) -> Result<PathBuf, String> {
    let resolved = resolve_piggy_ids_path(piggy_ids)?;
    if resolved != piggy_ids {
        return Err(format!(
            "{}: cannot mutate a resolver/pigpen-backed piggy-ids in place \
             (recipients add/remove/sync requires plain RFC 0003 piggy-ids content)",
            piggy_ids.display()
        ));
    }
    Ok(resolved)
}

/// `$XDG_CACHE_HOME/piggy/<hash-of-piggy_ids-path>.piggy-ids` — never
/// inside the store itself (the store is typically git-synced).
fn cache_path_for(piggy_ids: &Path) -> Result<PathBuf, String> {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    piggy_ids.hash(&mut hasher);
    let cache_home = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .ok_or_else(|| "neither XDG_CACHE_HOME nor HOME is set".to_string())?;
    Ok(cache_home
        .join("piggy")
        .join(format!("{:016x}.piggy-ids", hasher.finish())))
}

/// RFC 0010: PATH-discover `pigpen-resolver-<kind>` and run
/// `resolve <locator>`, returning its stdout on success (exit 0) or an
/// error folding in its stderr on failure. Mirrors the age-plugin-*
/// PATH-discovery convention already used by `age-plugin-piggy`.
fn invoke_resolver(kind: &str, locator: &str) -> Result<Vec<u8>, String> {
    let binary = format!("pigpen-resolver-{kind}");
    let output = std::process::Command::new(&binary)
        .arg("resolve")
        .arg(locator)
        .output()
        .map_err(|e| format!("{binary} not found on PATH: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{binary} resolve {locator} exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mutex-protected env mutation helper. Same pattern as
    /// `crypt.rs::env_lock()` — tests run on multiple threads by
    /// default, and `PATH` is process-global. Without this, two tests
    /// that both mutate `PATH` race with each other. See #132.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "piggy-pigpen-pointer-test-{}",
            std::process::id().wrapping_mul(0x9E37)
                ^ (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u32)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn rfc0003_file_passes_through_unchanged() {
        let dir = tempdir();
        let ids = dir.join("piggy-ids");
        std::fs::write(&ids, "piggy-recipient-v1@age_x25519_pub-qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\n").unwrap();
        let resolved = resolve_piggy_ids_path(&ids).unwrap();
        assert_eq!(resolved, ids, "RFC 0003 files must pass through unchanged");
    }

    #[test]
    fn recipient_set_pigpen_converts_to_rfc0003_cache_file() {
        // resolve_piggy_ids_path's pigpen-conversion branch writes its
        // cache file under cache_path_for()'s $XDG_CACHE_HOME (falling
        // back to $HOME/.cache). Point that at a writable per-test
        // tempdir so the test never depends on the ambient $HOME/.cache
        // being writable — it isn't in the nix build sandbox, where
        // $HOME is the deliberately-unwritable /homeless-shelter and
        // $XDG_CACHE_HOME is unset (piggy#216). Same save/restore +
        // env_lock() pattern as crypt.rs's PIGGY_IDS_PATH tests.
        let _guard = env_lock();
        let dir = tempdir();
        let ids = dir.join("piggy-ids");
        // A minimal payload-less pigpen document, no recipients — proves
        // the sniff + conversion path without needing a real markl ID.
        std::fs::write(&ids, "---\n! pigpen-v1\n---\n").unwrap();

        let saved_cache_home = std::env::var_os("XDG_CACHE_HOME");
        std::env::set_var("XDG_CACHE_HOME", dir.join("cache"));
        let resolved = resolve_piggy_ids_path(&ids);
        match saved_cache_home {
            Some(v) => std::env::set_var("XDG_CACHE_HOME", v),
            None => std::env::remove_var("XDG_CACHE_HOME"),
        }
        let resolved = resolved.unwrap();

        assert_ne!(
            resolved, ids,
            "a pigpen doc must produce a distinct cache path"
        );
        let rendered = std::fs::read_to_string(&resolved).unwrap();
        assert_eq!(
            rendered, "",
            "zero recipients renders to an empty RFC 0003 file"
        );
    }

    #[test]
    fn pointer_face_errors_before_resolver_dispatch_exists() {
        let dir = tempdir();
        let ids = dir.join("piggy-ids");
        std::fs::write(
            &ids,
            "---\n- kind=\"papi-http\"\n- locator=\"https://example.com\"\n! pigpen-pointer-v1\n---\n",
        )
        .unwrap();
        let err = resolve_piggy_ids_path(&ids).unwrap_err();
        assert!(err.contains("pointer"), "got: {err}");
    }

    #[test]
    fn mutation_allowed_for_rfc0003_passthrough() {
        let dir = tempdir();
        let ids = dir.join("piggy-ids");
        std::fs::write(&ids, "piggy-recipient-v1@age_x25519_pub-qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\n").unwrap();
        let resolved = resolve_piggy_ids_path_for_mutation(&ids).unwrap();
        assert_eq!(resolved, ids);
    }

    #[test]
    fn mutation_refused_for_pigpen_recipient_set() {
        // Same XDG_CACHE_HOME isolation as
        // recipient_set_pigpen_converts_to_rfc0003_cache_file:
        // resolve_piggy_ids_path_for_mutation calls resolve_piggy_ids_path
        // internally, which writes a cache file for a pigpen doc before
        // the mutation check runs. See piggy#216.
        let _guard = env_lock();
        let dir = tempdir();
        let ids = dir.join("piggy-ids");
        std::fs::write(&ids, "---\n! pigpen-v1\n---\n").unwrap();

        let saved_cache_home = std::env::var_os("XDG_CACHE_HOME");
        std::env::set_var("XDG_CACHE_HOME", dir.join("cache"));
        let err = resolve_piggy_ids_path_for_mutation(&ids);
        match saved_cache_home {
            Some(v) => std::env::set_var("XDG_CACHE_HOME", v),
            None => std::env::remove_var("XDG_CACHE_HOME"),
        }

        let err = err.unwrap_err();
        assert!(err.contains("cannot mutate"), "got: {err}");
    }

    #[test]
    fn resolver_not_on_path_produces_named_error() {
        let _guard = env_lock();
        let err = invoke_resolver("nonexistent-test-kind", "whatever").unwrap_err();
        assert!(
            err.contains("pigpen-resolver-nonexistent-test-kind"),
            "got: {err}"
        );
    }

    #[test]
    fn resolver_success_returns_stdout_bytes() {
        use std::os::unix::fs::PermissionsExt as _;
        let _guard = env_lock();
        let dir = tempdir();
        let resolver = dir.join("pigpen-resolver-echo-test");
        std::fs::write(
            &resolver,
            b"#!/bin/sh\nprintf -- '---\\n! pigpen-v1\\n---\\n'\n",
        )
        .unwrap();
        std::fs::set_permissions(&resolver, std::fs::Permissions::from_mode(0o755)).unwrap();

        let saved_path = std::env::var_os("PATH");
        std::env::set_var(
            "PATH",
            format!(
                "{}:{}",
                dir.display(),
                saved_path
                    .as_ref()
                    .map_or_else(String::new, |p| p.to_string_lossy().into_owned())
            ),
        );
        let out = invoke_resolver("echo-test", "ignored-locator");
        match saved_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }

        assert_eq!(out.unwrap(), b"---\n! pigpen-v1\n---\n".to_vec());
    }

    #[test]
    fn resolver_nonzero_exit_surfaces_stderr() {
        use std::os::unix::fs::PermissionsExt as _;
        let _guard = env_lock();
        let dir = tempdir();
        let resolver = dir.join("pigpen-resolver-fail-test");
        std::fs::write(
            &resolver,
            b"#!/bin/sh\necho 'papi unreachable' >&2\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&resolver, std::fs::Permissions::from_mode(0o755)).unwrap();

        let saved_path = std::env::var_os("PATH");
        std::env::set_var(
            "PATH",
            format!(
                "{}:{}",
                dir.display(),
                saved_path
                    .as_ref()
                    .map_or_else(String::new, |p| p.to_string_lossy().into_owned())
            ),
        );
        let err = invoke_resolver("fail-test", "whatever");
        match saved_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }

        let err = err.unwrap_err();
        assert!(err.contains("papi unreachable"), "got: {err}");
    }
}
