//! Sniffs a `piggy-ids` path's content (RFC 0003 legacy lines, a pigpen
//! recipient-set-face document, or a pigpen pointer-face document —
//! RFC 0009 §3.2, RFC 0008 §2.2) and returns a path every existing
//! consumer (in-process readers and the external `piggy-ids`/`pivy-box`
//! subprocesses) can treat exactly like a plain RFC 0003 file.
//!
//! For the RFC 0003 case this is a no-op passthrough of the input path
//! (zero behavior change). For a pigpen recipient-set document it
//! converts to RFC 0003 text and writes it to a cache file, returning
//! that path instead. For a pointer face (RFC 0010) it PATH-discovers
//! and invokes the matching `pigpen-resolver-<kind>` binary, caches its
//! output for `CACHE_TTL`, then applies the same recipient-set-to-RFC
//! 0003 conversion. `PIGGY_PIGPEN_NO_CACHE` (any non-empty value)
//! disables the cache and forces a resolve on every call.

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
        // Cache the resolver's *raw* output separately from the
        // RFC 0003-converted result that recipient_set_doc_to_rfc0003_cache
        // writes below. Both derive from cache_path_for(piggy_ids) alone
        // (hashed only on the input path), so if this used the same file
        // the final write would clobber the raw cache: a second call
        // within the TTL window would then try to parse already-converted
        // RFC 0003 text as a pigpen document and fail. See
        // resolved_pointer_cache_path_for's doc comment.
        let cache_file = resolved_pointer_cache_path_for(piggy_ids)?;
        let resolved_bytes = if !cache_disabled() && cache_is_fresh(&cache_file, CACHE_TTL) {
            std::fs::read(&cache_file)
                .map_err(|e| format!("reading cache {}: {e}", cache_file.display()))?
        } else {
            let bytes = invoke_resolver(&ptr.kind, &ptr.locator).map_err(|e| {
                format!(
                    "{}: resolving pointer (kind={:?}, locator={:?}): {e}",
                    piggy_ids.display(),
                    ptr.kind,
                    ptr.locator
                )
            })?;
            if let Some(parent) = cache_file.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("create {}: {e}", parent.display()))?;
            }
            std::fs::write(&cache_file, &bytes)
                .map_err(|e| format!("writing cache {}: {e}", cache_file.display()))?;
            bytes
        };
        let doc = piggy_pigpen::Document::parse(&resolved_bytes)
            .map_err(|e| format!("parsing resolved bytes as a pigpen document: {e}"))?;
        return recipient_set_doc_to_rfc0003_cache(piggy_ids, doc);
    }

    let doc = piggy_pigpen::Document::parse(&raw)
        .map_err(|e| format!("parsing {} as a pigpen document: {e}", piggy_ids.display()))?;
    recipient_set_doc_to_rfc0003_cache(piggy_ids, doc)
}

/// Shared tail of [`resolve_piggy_ids_path`]'s two document-bearing
/// branches (plain recipient-set face, and pointer face after
/// resolution): convert a parsed pigpen [`piggy_pigpen::Document`]'s
/// recipients to RFC 0003 text and write it to the input path's cache
/// file, returning that cache path.
fn recipient_set_doc_to_rfc0003_cache(
    piggy_ids: &Path,
    doc: piggy_pigpen::Document,
) -> Result<PathBuf, String> {
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
/// meaningless (piggy#216).
///
/// Refuses on a cheap **local** sniff of the raw bytes (RFC 0009 §3.2's
/// same `---\n`-prefix check `resolve_piggy_ids_path` uses), BEFORE ever
/// calling `resolve_piggy_ids_path` — deliberately not "call the full
/// resolver-invoking path and compare the result against the input".
/// For a pointer face that comparison would only be knowable after
/// `resolve_piggy_ids_path` had already spawned `pigpen-resolver-<kind>`
/// (potentially a network round-trip per RFC 0010 §3) and written a
/// cache file, just to immediately discard both and refuse — real cost
/// paid on every mutation call site for content that was always going
/// to be rejected. `resolve_piggy_ids_path` is only reached for content
/// that passes the local sniff, where it's a pure, cheap passthrough.
pub(crate) fn resolve_piggy_ids_path_for_mutation(piggy_ids: &Path) -> Result<PathBuf, String> {
    let raw =
        std::fs::read(piggy_ids).map_err(|e| format!("reading {}: {e}", piggy_ids.display()))?;
    if raw.starts_with(b"---\n") {
        return Err(format!(
            "{}: cannot mutate a resolver/pigpen-backed piggy-ids in place \
             (recipients add/remove/sync requires plain RFC 0003 piggy-ids content)",
            piggy_ids.display()
        ));
    }
    resolve_piggy_ids_path(piggy_ids)
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

/// Cache path for a pointer face's *raw resolved bytes* (the resolver's
/// stdout — itself a pigpen document), kept distinct from
/// [`cache_path_for`]'s final RFC 0003-rendered cache so the two writes
/// don't clobber each other. See the call site's comment in
/// [`resolve_piggy_ids_path`].
fn resolved_pointer_cache_path_for(piggy_ids: &Path) -> Result<PathBuf, String> {
    let mut path = cache_path_for(piggy_ids)?;
    path.set_extension("piggy-pointer-raw");
    Ok(path)
}

/// Tuning lever (design doc): 1 hour default. Change signal: real usage
/// shows stale-recipient complaints (lower it) or resolver-load
/// complaints (raise it).
const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

/// `true` when `cache_file` exists and was modified less than `ttl` ago.
/// Any I/O error (missing file, unsupported mtime, clock skew making
/// `elapsed()` fail) is treated as "not fresh" so callers fall back to
/// resolving — conservative in the same spirit as
/// `reencrypt::reencrypt_unnecessary`.
fn cache_is_fresh(cache_file: &Path, ttl: std::time::Duration) -> bool {
    let Ok(meta) = std::fs::metadata(cache_file) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    modified.elapsed().is_ok_and(|age| age < ttl)
}

/// `PIGGY_PIGPEN_NO_CACHE` (any non-empty value) forces every pointer
/// resolution to skip the cache and re-invoke the resolver.
fn cache_disabled() -> bool {
    std::env::var_os("PIGGY_PIGPEN_NO_CACHE").is_some_and(|v| !v.is_empty())
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
    fn pointer_face_with_unreachable_resolver_produces_named_error() {
        // Now that resolve_piggy_ids_path's pointer branch actually
        // invokes invoke_resolver (piggy#216 Task 8), this exercises a
        // real subprocess spawn attempt for a resolver kind that isn't
        // on PATH ("papi-http") rather than the old placeholder error.
        // env_lock() because invoke_resolver reads the process-global
        // PATH, same as the other invoke_resolver tests below.
        let _guard = env_lock();
        let dir = tempdir();
        let ids = dir.join("piggy-ids");
        std::fs::write(
            &ids,
            "---\n- kind=\"papi-http\"\n- locator=\"https://example.com\"\n! pigpen-pointer-v1\n---\n",
        )
        .unwrap();
        let err = resolve_piggy_ids_path(&ids).unwrap_err();
        assert!(err.contains("pointer"), "got: {err}");
        assert!(err.contains("pigpen-resolver-papi-http"), "got: {err}");
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
        // resolve_piggy_ids_path_for_mutation refuses on a cheap local
        // `---\n`-prefix sniff, before ever calling
        // resolve_piggy_ids_path — so unlike
        // recipient_set_pigpen_converts_to_rfc0003_cache_file (which
        // exercises resolve_piggy_ids_path directly and does write a
        // cache file), no XDG_CACHE_HOME isolation is needed here: this
        // path never touches the cache. See piggy#216.
        let dir = tempdir();
        let ids = dir.join("piggy-ids");
        std::fs::write(&ids, "---\n! pigpen-v1\n---\n").unwrap();

        let err = resolve_piggy_ids_path_for_mutation(&ids).unwrap_err();
        assert!(err.contains("cannot mutate"), "got: {err}");
    }

    #[test]
    fn mutation_refused_for_pointer_face_without_invoking_resolver() {
        // Regression test: resolve_piggy_ids_path_for_mutation used to
        // call the FULL resolve_piggy_ids_path (which, since piggy#216
        // Task 8, actually spawns pigpen-resolver-<kind> for a pointer
        // face — potentially a network round-trip per RFC 0010 §3) and
        // only afterward compared the result against the input to
        // decide whether to refuse. That meant every mutation call site
        // (recipients add/remove/sync) paid for a real resolver
        // invocation against pointer-backed content just to immediately
        // discard it and refuse. The fix short-circuits on a cheap
        // local sniff before ever calling resolve_piggy_ids_path.
        //
        // Proof: name a resolver kind that does NOT exist on PATH. If
        // the refusal is genuinely local/pre-resolver, the error is the
        // "cannot mutate" message. If the bug regresses (resolver
        // invocation happens first), the error instead comes from
        // invoke_resolver's "not found on PATH" / "resolving pointer"
        // path. No env_lock/PATH/XDG_CACHE_HOME isolation needed here —
        // that's the point: a correct implementation touches neither.
        let dir = tempdir();
        let ids = dir.join("piggy-ids");
        std::fs::write(
            &ids,
            "---\n- kind=\"mutation-test-nonexistent-kind\"\n- locator=\"unused\"\n! pigpen-pointer-v1\n---\n",
        )
        .unwrap();
        let err = resolve_piggy_ids_path_for_mutation(&ids).unwrap_err();
        assert!(err.contains("cannot mutate"), "got: {err}");
        assert!(
            !err.contains("resolving pointer") && !err.contains("not found on PATH"),
            "resolver must never be invoked when refusing mutation on a \
             pointer-backed piggy-ids; got: {err}"
        );
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

    #[test]
    fn fresh_cache_within_ttl_skips_resolver() {
        let dir = tempdir();
        let cache_file = dir.join("cache.piggy-ids");
        std::fs::write(&cache_file, "cached content\n").unwrap();
        assert!(
            cache_is_fresh(&cache_file, std::time::Duration::from_secs(3600)),
            "a just-written file must be fresh under a 1h TTL"
        );
    }

    #[test]
    fn stale_cache_past_ttl_is_not_fresh() {
        let dir = tempdir();
        let cache_file = dir.join("cache.piggy-ids");
        std::fs::write(&cache_file, "cached content\n").unwrap();
        assert!(
            !cache_is_fresh(&cache_file, std::time::Duration::from_secs(0)),
            "a zero-second TTL must never be fresh"
        );
    }

    #[test]
    fn missing_cache_file_is_not_fresh() {
        let dir = tempdir();
        let cache_file = dir.join("does-not-exist.piggy-ids");
        assert!(!cache_is_fresh(
            &cache_file,
            std::time::Duration::from_secs(3600)
        ));
    }

    #[test]
    fn no_cache_env_var_forces_resolve() {
        let _guard = env_lock();
        std::env::set_var("PIGGY_PIGPEN_NO_CACHE", "1");
        let disabled = cache_disabled();
        std::env::remove_var("PIGGY_PIGPEN_NO_CACHE");
        assert!(disabled);
    }

    #[test]
    fn pointer_face_resolves_via_fixture_resolver() {
        use std::os::unix::fs::PermissionsExt as _;
        let _guard = env_lock();
        let dir = tempdir();
        let resolver = dir.join("pigpen-resolver-fixture-kind");
        std::fs::write(
            &resolver,
            b"#!/bin/sh\nprintf -- '---\\n! pigpen-v1\\n---\\n'\n",
        )
        .unwrap();
        std::fs::set_permissions(&resolver, std::fs::Permissions::from_mode(0o755)).unwrap();

        let ids = dir.join("piggy-ids");
        std::fs::write(
            &ids,
            "---\n- kind=\"fixture-kind\"\n- locator=\"unused\"\n! pigpen-pointer-v1\n---\n",
        )
        .unwrap();

        // Isolate PATH (resolver discovery) and XDG_CACHE_HOME (cache
        // writes) to per-test tempdirs. The XDG_CACHE_HOME override is
        // required, not optional: without it, cache_path_for falls back
        // to $HOME/.cache, which is the deliberately-unwritable
        // /homeless-shelter in the nix-sandboxed pre-merge build gate
        // (piggy#216 — see this file's module-level lesson in the task
        // history / commit 93528ba).
        let saved_path = std::env::var_os("PATH");
        let saved_cache = std::env::var_os("XDG_CACHE_HOME");
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
        std::env::set_var("XDG_CACHE_HOME", dir.join("xdg-cache"));
        let resolved = resolve_piggy_ids_path(&ids);
        match saved_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        match saved_cache {
            Some(v) => std::env::set_var("XDG_CACHE_HOME", v),
            None => std::env::remove_var("XDG_CACHE_HOME"),
        }

        let resolved = resolved.unwrap();
        assert_eq!(std::fs::read_to_string(&resolved).unwrap(), "");
    }

    #[test]
    fn pointer_face_cached_within_ttl_does_not_reinvoke_resolver_on_second_call() {
        // Regression coverage for the raw-vs-final cache path collision:
        // the pointer branch caches the resolver's raw output separately
        // from the RFC 0003-converted result (see
        // resolved_pointer_cache_path_for's doc comment). Without that
        // separation, this test's second resolve_piggy_ids_path call
        // would try to parse the *already-converted* RFC 0003 cache
        // (here, an empty string — zero recipients) as a pigpen document
        // and fail, instead of hitting the raw-bytes cache and skipping
        // the resolver.
        use std::os::unix::fs::PermissionsExt as _;
        let _guard = env_lock();
        let dir = tempdir();
        let call_count_file = dir.join("call-count");
        std::fs::write(&call_count_file, "").unwrap();
        let resolver = dir.join("pigpen-resolver-count-test");
        std::fs::write(
            &resolver,
            format!(
                "#!/bin/sh\nprintf x >> {}\nprintf -- '---\\n! pigpen-v1\\n---\\n'\n",
                call_count_file.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&resolver, std::fs::Permissions::from_mode(0o755)).unwrap();

        let ids = dir.join("piggy-ids");
        std::fs::write(
            &ids,
            "---\n- kind=\"count-test\"\n- locator=\"unused\"\n! pigpen-pointer-v1\n---\n",
        )
        .unwrap();

        let saved_path = std::env::var_os("PATH");
        let saved_cache = std::env::var_os("XDG_CACHE_HOME");
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
        std::env::set_var("XDG_CACHE_HOME", dir.join("xdg-cache"));

        let first = resolve_piggy_ids_path(&ids);
        let second = resolve_piggy_ids_path(&ids);

        match saved_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        match saved_cache {
            Some(v) => std::env::set_var("XDG_CACHE_HOME", v),
            None => std::env::remove_var("XDG_CACHE_HOME"),
        }

        first.unwrap();
        second.unwrap();
        let calls = std::fs::read_to_string(&call_count_file).unwrap();
        assert_eq!(
            calls.len(),
            1,
            "resolver should be invoked once; the second call within the \
             TTL window must hit the raw-bytes cache instead of \
             re-resolving"
        );
    }
}
