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
            // Check the answer before caching it: a bad one must not be
            // served for the next CACHE_TTL.
            resolved_recipient_set(&bytes, &ptr)?;
            if let Some(parent) = cache_file.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("create {}: {e}", parent.display()))?;
            }
            std::fs::write(&cache_file, &bytes)
                .map_err(|e| format!("writing cache {}: {e}", cache_file.display()))?;
            bytes
        };
        let doc = resolved_recipient_set(&resolved_bytes, &ptr)?;
        return recipient_set_doc_to_rfc0003_cache(piggy_ids, doc);
    }

    let doc = piggy_pigpen::Document::parse(&raw).map_err(|e| {
        // A document that says it is a pointer but is not a valid one gets
        // the pointer parser's reason, not "unexpected type".
        match piggy_pigpen::Pointer::parse(&raw) {
            Err(pointer_err) if names_pointer_type(&raw) => {
                format!(
                    "parsing {} as a pigpen pointer: {pointer_err}",
                    piggy_ids.display()
                )
            }
            _ => format!("parsing {} as a pigpen document: {e}", piggy_ids.display()),
        }
    })?;
    recipient_set_doc_to_rfc0003_cache(piggy_ids, doc)
}

/// What a resolver may answer with (RFC 0010 §3, §5): a recipient-set
/// document naming at least one encryption recipient. A sealed document
/// and an empty set are failures, as in the Go resolver.
fn resolved_recipient_set(
    bytes: &[u8],
    ptr: &piggy_pigpen::Pointer,
) -> Result<piggy_pigpen::Document, String> {
    let fail = |cause: String| {
        format!(
            "pointer (kind={:?}, locator={:?}) {cause}",
            ptr.kind, ptr.locator
        )
    };
    let doc = piggy_pigpen::Document::parse(bytes)
        .map_err(|e| fail(format!("did not resolve to a pigpen recipient set: {e}")))?;
    if doc.sealed() {
        return Err(fail(
            "resolved to a sealed document, want a recipient set".into(),
        ));
    }
    if doc.encryption_recipients().next().is_none() {
        return Err(fail("resolved to no encryption recipients".into()));
    }
    Ok(doc)
}

/// Whether the bytes carry the pointer type line, valid pointer or not.
/// Only chooses which parser's error to report.
fn names_pointer_type(raw: &[u8]) -> bool {
    raw.split(|&b| b == b'\n')
        .any(|line| line == b"! pigpen-pointer-v1")
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
        // Skip unrecognized-purpose lines (e.g. papi self-sig) — they are
        // valid pigpen tags but have no RFC 0003 representation and must not
        // be passed to Recipient::new's strict whitelist (RFC 0002 §6.6 /
        // madder#255: unknown purposes are carried opaquely by the parser,
        // not rejected, so they reach here and must be filtered out).
        .filter(|r| !matches!(r.id.purpose(), Some(piggy_markl::PurposeId::Other(_))))
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
///
/// The resolver is somebody else's program talking to somebody else's
/// server, so the run is bounded (piggy#302): a deadline, a cap on what it
/// may print, and its own process group, which is killed whole when either
/// is exceeded. Its stderr reaches the error quoted, so it cannot write
/// control sequences to the terminal.
fn invoke_resolver(kind: &str, locator: &str) -> Result<Vec<u8>, String> {
    use std::os::unix::process::CommandExt as _;
    use std::process::Stdio;

    piggy_pigpen::validate_pointer_kind(kind).map_err(|e| e.to_string())?;
    let binary = format!("pigpen-resolver-{kind}");
    let path = find_on_absolute_path(&binary).ok_or_else(|| {
        format!("{binary} not found on PATH (relative and empty PATH entries are not searched)")
    })?;

    // Retry on ETXTBSY ("Text file busy", os error 26): on Linux, exec fails
    // this way while any process holds the target file open for writing. In a
    // multi-threaded program a concurrent fork can transiently inherit a
    // just-written executable's write fd across the fork→exec window — the
    // parallel test suite trips this (a resolver written and exec'd while
    // another thread forks). A short bounded retry rides it out. A stable
    // installed resolver never hits it, so production behaviour is unchanged.
    const MAX_RETRIES: u32 = 5;
    let mut attempts = 0u32;
    let mut child = loop {
        match std::process::Command::new(&path)
            .arg("resolve")
            .arg(locator)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
        {
            Ok(child) => break child,
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && attempts < MAX_RETRIES => {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(e) => return Err(format!("running {}: {e}", path.display())),
        }
    };

    // The child leads its own process group, so this reaches whatever it
    // started as well.
    let group = child.id() as libc::pid_t;
    let kill_group = || {
        // SAFETY: kill(2) with a negative pid signals a process group; it
        // touches no memory of ours.
        unsafe { libc::kill(-group, libc::SIGKILL) };
    };

    let stdout = read_capped(
        child.stdout.take().expect("piped"),
        MAX_RESOLVER_STDOUT,
        PastLimit::Close,
    );
    let stderr = read_capped(
        child.stderr.take().expect("piped"),
        MAX_RESOLVER_STDERR,
        PastLimit::Discard,
    );

    let timeout = resolver_timeout();
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() >= deadline => {
                kill_group();
                let _ = child.wait();
                return Err(format!(
                    "{binary} did not finish within {}s",
                    timeout.as_secs()
                ));
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(10)),
            Err(e) => {
                kill_group();
                return Err(format!("waiting for {binary}: {e}"));
            }
        }
    };

    // The resolver has exited; anything it left running still holds the
    // pipes. Give the readers a moment, then end the group.
    let collect = |reader: std::sync::mpsc::Receiver<CappedOutput>| {
        reader.recv_timeout(RESOLVER_WAIT_DELAY).or_else(|_| {
            kill_group();
            reader.recv_timeout(RESOLVER_WAIT_DELAY)
        })
    };
    let (Ok(stdout), Ok(stderr)) = (collect(stdout), collect(stderr)) else {
        return Err(format!("{binary} left a process holding its output open"));
    };

    if stdout.overflowed {
        return Err(format!(
            "{binary} printed more than the {MAX_RESOLVER_STDOUT}-byte recipient-set size limit"
        ));
    }
    if !status.success() {
        return Err(format!(
            "{binary} exited {status}: {:?}",
            String::from_utf8_lossy(&stderr.bytes).trim()
        ));
    }
    Ok(stdout.bytes)
}

/// A recipient set is a few hundred bytes per recipient; a megabyte is
/// thousands of them.
const MAX_RESOLVER_STDOUT: usize = 1 << 20;
const MAX_RESOLVER_STDERR: usize = 4 << 10;
const RESOLVER_WAIT_DELAY: std::time::Duration = std::time::Duration::from_secs(2);
const DEFAULT_RESOLVER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// `PIGGY_PIGPEN_RESOLVER_TIMEOUT` (whole seconds, at least 1) overrides
/// the 30-second default; anything else is ignored.
fn resolver_timeout() -> std::time::Duration {
    std::env::var("PIGGY_PIGPEN_RESOLVER_TIMEOUT")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&secs| secs > 0)
        .map_or(DEFAULT_RESOLVER_TIMEOUT, std::time::Duration::from_secs)
}

struct CappedOutput {
    bytes: Vec<u8>,
    overflowed: bool,
}

/// What a reader does once it has `limit` bytes.
#[derive(Clone, Copy)]
enum PastLimit {
    /// Close the pipe: the writer gets EPIPE and the run is over. For
    /// stdout, where more than the limit is an error anyway.
    Close,
    /// Keep reading and throw it away, so a chatty but working resolver
    /// is not killed for what it logs. For stderr.
    Discard,
}

/// Collect up to `limit` bytes of `source` on a thread.
fn read_capped<R: std::io::Read + Send + 'static>(
    mut source: R,
    limit: usize,
    past_limit: PastLimit,
) -> std::sync::mpsc::Receiver<CappedOutput> {
    use std::io::Read as _;
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        // One byte past the limit tells "exactly the limit" from "more".
        let _ = source
            .by_ref()
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes);
        let overflowed = bytes.len() > limit;
        bytes.truncate(limit);
        if overflowed && matches!(past_limit, PastLimit::Discard) {
            let _ = std::io::copy(&mut source, &mut std::io::sink());
        }
        let _ = send.send(CappedOutput { bytes, overflowed });
    });
    receive
}

/// The first executable regular file named `binary` in an ABSOLUTE `PATH`
/// entry. A relative or empty entry means "the working directory", which
/// for a store is not a place to run programs from.
fn find_on_absolute_path(binary: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(binary))
        .find(|candidate| {
            std::fs::metadata(candidate)
                .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        })
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
        // Poison-tolerant: the guarded region only mutates PATH, so a panic in
        // one test (e.g. a transient exec failure) leaves no invariant broken —
        // recover the guard instead of cascading a PoisonError into every
        // sibling test that shares this lock.
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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

    /// A valid encryption-recipient line for resolver fixtures.
    fn test_recipient() -> String {
        piggy_markl::Id::new(
            Some(piggy_markl::PurposeId::PiggyRecipientV1),
            piggy_markl::FormatId::AgeX25519Pub,
            vec![1u8; 32],
        )
        .unwrap()
        .to_wire()
    }

    fn one_recipient_resolver_script() -> String {
        format!(
            "#!/bin/sh\nprintf -- '---\\n- {}\\n! pigpen-v1\\n---\\n'\n",
            test_recipient()
        )
    }

    /// Install `pigpen-resolver-<kind>` with `script` in a fresh directory,
    /// put that directory first on PATH, run `body`, restore PATH. Holds
    /// env_lock for the duration.
    fn with_resolver<T>(kind: &str, script: &str, body: impl FnOnce(&Path) -> T) -> T {
        use std::os::unix::fs::PermissionsExt as _;
        let _guard = env_lock();
        let dir = tempdir();
        let resolver = dir.join(format!("pigpen-resolver-{kind}"));
        std::fs::write(&resolver, script).unwrap();
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
        let out = body(&dir);
        match saved_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        out
    }

    /// Resolve a pointer of `kind` through the full path, with the cache
    /// in the fixture directory.
    fn resolve_pointer_of_kind(dir: &Path, kind: &str) -> Result<PathBuf, String> {
        let ids = dir.join("piggy-ids");
        std::fs::write(
            &ids,
            format!("---\n- kind=\"{kind}\"\n- locator=\"unused\"\n! pigpen-pointer-v1\n---\n"),
        )
        .unwrap();
        let saved_cache = std::env::var_os("XDG_CACHE_HOME");
        std::env::set_var("XDG_CACHE_HOME", dir.join("xdg-cache"));
        let resolved = resolve_piggy_ids_path(&ids);
        match saved_cache {
            Some(v) => std::env::set_var("XDG_CACHE_HOME", v),
            None => std::env::remove_var("XDG_CACHE_HOME"),
        }
        resolved
    }

    // --- piggy#302: the resolver run is bounded ---------------------------

    #[test]
    fn resolver_that_never_exits_is_stopped_at_the_deadline() {
        let started = std::time::Instant::now();
        let err = with_resolver("hangs", "#!/bin/sh\nexec sleep 60\n", |_| {
            std::env::set_var("PIGGY_PIGPEN_RESOLVER_TIMEOUT", "1");
            let out = invoke_resolver("hangs", "l");
            std::env::remove_var("PIGGY_PIGPEN_RESOLVER_TIMEOUT");
            out
        })
        .unwrap_err();
        assert!(err.contains("did not finish"), "got: {err}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "took {:?}; the deadline did not stop the resolver",
            started.elapsed()
        );
    }

    #[test]
    fn resolver_child_holding_the_output_does_not_hold_the_caller() {
        // The resolver exits at once; the sleep it started keeps stdout.
        let started = std::time::Instant::now();
        let out = with_resolver("forks", "#!/bin/sh\nsleep 60 &\nexit 0\n", |_| {
            invoke_resolver("forks", "l")
        });
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "took {:?}; a grandchild held the caller",
            started.elapsed()
        );
        // Killing the group closes the pipe, so the (empty) output arrives.
        assert_eq!(out.unwrap(), b"");
    }

    #[test]
    fn resolver_output_past_the_size_limit_is_refused() {
        let err = with_resolver(
            "floods",
            "#!/bin/sh\nwhile :; do echo 0123456789abcdef0123456789abcdef; done\n",
            |_| invoke_resolver("floods", "l"),
        )
        .unwrap_err();
        assert!(err.contains("size limit"), "got: {err}");
    }

    #[test]
    fn resolver_stderr_is_quoted_and_bounded() {
        let err = with_resolver(
            "noisy",
            "#!/bin/sh\nprintf '\\033[31mred\\033[0m' >&2\ni=0\nwhile [ $i -lt 2000 ]; do echo 0123456789abcdef >&2; i=$((i+1)); done\nexit 1\n",
            |_| invoke_resolver("noisy", "l"),
        )
        .unwrap_err();
        assert!(!err.contains('\x1b'), "raw escape sequence in: {err:?}");
        assert!(
            err.len() < 4 * MAX_RESOLVER_STDERR,
            "error is {} bytes; stderr was not bounded",
            err.len()
        );
    }

    #[test]
    fn resolver_logging_past_the_stderr_limit_still_succeeds() {
        let out = with_resolver(
            "chatty",
            "#!/bin/sh\ni=0\nwhile [ $i -lt 2000 ]; do echo 0123456789abcdef >&2; i=$((i+1)); done\nprintf ok\n",
            |_| invoke_resolver("chatty", "l"),
        );
        assert_eq!(out.unwrap(), b"ok");
    }

    #[test]
    fn resolver_in_a_relative_path_entry_is_not_run() {
        use std::os::unix::fs::PermissionsExt as _;
        let _guard = env_lock();
        let dir = tempdir();
        let resolver = dir.join("pigpen-resolver-cwd-only");
        std::fs::write(&resolver, one_recipient_resolver_script()).unwrap();
        std::fs::set_permissions(&resolver, std::fs::Permissions::from_mode(0o755)).unwrap();

        // A relative spelling of `dir`, built by climbing out of the working
        // directory, so the test need not change it (it is process-wide and
        // other tests run in parallel).
        let cwd = std::env::current_dir().unwrap();
        let climb = "../".repeat(cwd.components().count());
        let relative = format!("{climb}{}", dir.strip_prefix("/").unwrap().display());
        assert!(
            Path::new(&relative)
                .join("pigpen-resolver-cwd-only")
                .exists(),
            "the relative entry does not reach the fixture"
        );

        let saved_path = std::env::var_os("PATH");
        // The relative entry, and the empty entry that means the working
        // directory.
        std::env::set_var("PATH", format!("{relative}::/nonexistent-piggy-test-dir"));
        let out = invoke_resolver("cwd-only", "l");
        match saved_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }

        let err = out.unwrap_err();
        assert!(err.contains("not found on PATH"), "got: {err}");
    }

    #[test]
    fn pointer_resolving_to_no_recipients_is_refused_and_not_cached() {
        let (first, cached) = with_resolver(
            "empty",
            "#!/bin/sh\nprintf -- '---\\n! pigpen-v1\\n---\\n'\n",
            |dir| {
                let first = resolve_pointer_of_kind(dir, "empty");
                let cached = dir.join("xdg-cache").join("piggy").exists()
                    && std::fs::read_dir(dir.join("xdg-cache").join("piggy"))
                        .unwrap()
                        .next()
                        .is_some();
                (first, cached)
            },
        );
        let err = first.unwrap_err();
        assert!(err.contains("no encryption recipients"), "got: {err}");
        assert!(!cached, "a refused answer was written to the cache");
    }

    #[test]
    fn pointer_resolving_to_a_sealed_document_is_refused() {
        // Any X25519 u-coordinate that is not a low-order point will do:
        // nobody opens this document.
        let sealed_to =
            piggy_pigpen::recipient_id(piggy_markl::FormatId::AgeX25519Pub, vec![9u8; 32]).unwrap();
        let sealed = piggy_pigpen::Document::seal(b"piggy-test: not a recipient set", &[sealed_to])
            .unwrap()
            .to_bytes()
            .unwrap();

        let err = with_resolver(
            "sealed",
            "#!/bin/sh\ncat \"$(dirname \"$0\")/sealed.pigpen\"\n",
            |dir| {
                std::fs::write(dir.join("sealed.pigpen"), &sealed).unwrap();
                resolve_pointer_of_kind(dir, "sealed")
            },
        )
        .unwrap_err();
        assert!(err.contains("sealed document"), "got: {err}");
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
    fn unknown_purpose_line_silently_filtered_in_rfc0003_conversion() {
        // A pigpen recipient-set doc may carry unrecognized-purpose `-` lines
        // (e.g. `papi-pigpen-self-sig-v1@ecdsa_p256_sig-<blech32>` from papi's
        // self-signed pigpen format). These are valid pigpen tags but have no
        // RFC 0003 representation. recipient_set_doc_to_rfc0003_cache must skip
        // them rather than passing them to Recipient::new's strict whitelist.
        use piggy_markl::{FormatId, Id, PurposeId};
        let _guard = env_lock();
        let dir = tempdir();
        let ids = dir.join("piggy-ids");

        // Build a recipient-set doc: one valid age recipient + one self-sig tag.
        let known_id = Id::new(
            Some(PurposeId::PiggyRecipientV1),
            FormatId::AgeX25519Pub,
            vec![1u8; 32],
        )
        .unwrap();
        let sig_id = Id::new(
            Some(PurposeId::Other("papi-pigpen-self-sig-v1".to_string())),
            FormatId::EcdsaP256Sig,
            vec![0u8; 64],
        )
        .unwrap();
        let doc = piggy_pigpen::Document::new_recipient_set(vec![
            piggy_pigpen::Recipient {
                id: known_id.clone(),
                comment: None,
                wrap: None,
            },
            piggy_pigpen::Recipient {
                id: sig_id,
                comment: None,
                wrap: None,
            },
        ]);
        std::fs::write(&ids, doc.to_bytes().unwrap()).unwrap();

        let saved_cache_home = std::env::var_os("XDG_CACHE_HOME");
        std::env::set_var("XDG_CACHE_HOME", dir.join("cache"));
        let resolved = resolve_piggy_ids_path(&ids);
        match saved_cache_home {
            Some(v) => std::env::set_var("XDG_CACHE_HOME", v),
            None => std::env::remove_var("XDG_CACHE_HOME"),
        }
        let resolved = resolved.unwrap();

        let rendered = std::fs::read_to_string(&resolved).unwrap();
        // Only the known recipient should appear; the self-sig line is absent.
        assert!(
            rendered.contains(&known_id.to_wire()),
            "known recipient missing from RFC 0003 output: {rendered}"
        );
        assert!(
            !rendered.contains("papi-pigpen-self-sig-v1"),
            "self-sig tag must not appear in RFC 0003 output: {rendered}"
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
    fn malformed_pointer_reports_the_pointer_parsers_reason() {
        let dir = tempdir();
        let path = dir.join("piggy-ids");
        std::fs::write(
            &path,
            "---\n- kind=\"../evil\"\n- locator=\"l\"\n! pigpen-pointer-v1\n---\n",
        )
        .unwrap();
        let err = resolve_piggy_ids_path(&path).unwrap_err();
        assert!(
            err.contains("path separator"),
            "error does not say what is wrong with the pointer: {err}"
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
        std::fs::write(&resolver, one_recipient_resolver_script()).unwrap();
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
        assert_eq!(
            std::fs::read_to_string(&resolved).unwrap().trim(),
            test_recipient()
        );
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
                "#!/bin/sh\nprintf x >> {}\nprintf -- '---\\n- {}\\n! pigpen-v1\\n---\\n'\n",
                call_count_file.display(),
                test_recipient()
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
