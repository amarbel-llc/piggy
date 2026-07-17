# Pigpen Pointer Face + Resolver Dispatch Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use eng:subagent-driven-development to implement this plan task-by-task.

**Goal:** Let `piggy-ids` be a pointer to a resolver plugin (e.g. a PAPI
instance) instead of only a literal recipient list, with piggy shelling
out to a PATH-discovered `pigpen-resolver-<kind>` binary and caching the
result — no papi-specific (or any-specific) logic inside piggy itself.

**Architecture:** Every one of the 7 existing `find_piggy_ids(...)` call
sites gets swapped for a new `resolve_piggy_ids_path(...)` wrapper with
the *same* `Result<PathBuf, String>` signature. For a plain RFC 0003
file it's a no-op passthrough (zero behavior change, matches the design
doc's rollback requirement). For a pigpen recipient-set-face document it
parses via `piggy-pigpen` and re-renders as RFC 0003 text to a cache
file, so nothing downstream — not even the external `piggy-ids`
subprocess `crypt::encrypt` shells out to — needs to know pigpen exists.
For a pigpen pointer-face document it additionally invokes the resolver
plugin (cache-or-invoke, TTL) before that same conversion. This means
Task 6 (wiring) is a mechanical signature-compatible swap at every call
site, and the `piggy-ids`/`pivy-box` subprocesses never need
pointer-awareness at all.

Two corrections against the approved design doc
(`docs/plans/2026-07-16-pigpen-pointer-resolver-design.md`), found while
grounding this plan in the actual code:

1. **Integration point is path-substituting, not content-parsing.**
   `find_piggy_ids` only ever returns a path (it never reads file
   content) and several call sites hand that path straight to a
   *subprocess* (`crypt::encrypt` shells to the external `piggy-ids`
   binary; `recipients.rs`'s `piggy_ids_ok` helper shells to
   `piggy-ids diff`/`validate`/`canonicalize`). A content-returning
   wrapper can't serve those call sites. `resolve_piggy_ids_path`
   returns a `PathBuf` instead — the original path, or a cache file's
   path — so every consumer (in-process reader or subprocess) is
   unaffected downstream.
2. **`piggy pigpen inspect` doesn't exist yet.** Grepped
   `crates/piggy/src/main.rs` for `Pigpen`/`pigpen` — RFC 0009 §4.2's
   entire `piggy pigpen` command group is still unimplemented (draft
   RFC, not yet built). The design doc's §7 assumed it existed and just
   needed to learn pointer-awareness. Dropped from this plan's scope —
   noted as a follow-up once that command group is built by whatever
   plan implements RFC 0009's baseline CLI surface.

**Tech Stack:** Rust (existing `crates/piggy`, `crates/piggy-ids`,
`crates/piggy-pigpen` — the last currently excluded from the cargo
workspace but usable as a `path` dependency), bats (`zz-tests_bats/`).

**Rollback:** Purely additive. A store that never creates a pointer-face
`piggy-ids` sees zero behavior change — `resolve_piggy_ids_path` is a
no-op passthrough for the two existing shapes. Revert by deleting the
new module and reverting the 7 call-site swaps back to `find_piggy_ids`.

---

## Task 1: RFC 0008 amendment — pointer face

**Promotion criteria:** N/A (documentation).

**Files:**
- Modify: `docs/rfcs/0008-pigpen-encrypted-document.md` (§2.2 "The two
  faces of a pigpen document", currently lines 127–139)

**Step 1: Update the section heading and table**

Change "### 2.2 The two faces of a pigpen document" to "### 2.2 The
three faces of a pigpen document" and add a third row:

```markdown
| Face | Metadata | Body / `@` | Equivalent to |
|------|----------|------------|---------------|
| **Recipient set** | `-` recipient lines, **no** `<` wrap locks; `! pigpen-v1` with **no** MAC lock | absent | a `piggy-ids` file (RFC 0003) |
| **Sealed document** | `-` recipient lines **each** with a `<` wrap lock; `! pigpen-v1@<mac>` | inline ciphertext body **or** `@` ciphertext blob | an `.ebox` (RFC 0002) |
| **Pointer** | `- kind="<resolver-kind>"` and `- locator="<opaque>"` tags, **no** recipient lines; `! pigpen-pointer-v1` | absent | new — no RFC 0003 equivalent (RFC 0010) |
```

Add below the existing structural-disambiguation paragraph:

```markdown
A pointer is disambiguated by its distinct type string
(`pigpen-pointer-v1`, not `pigpen-v1`) rather than structurally, since
it carries no recipient lines to key off. A document whose type is
`pigpen-pointer-v1` but which carries `-` recipient lines (or vice
versa) is malformed and MUST be rejected. See RFC 0010 for the pointer
face's resolution semantics.
```

**Step 2: Add a worked example near §9 "Worked Example"**

Insert after the existing worked example block (around line 519, before
"## 10. Conformance"):

```markdown
A pointer face, naming a resolver by kind and opaque locator:

    ---
    - kind="papi-http"
    - locator="https://example.com"
    ! pigpen-pointer-v1
    ---
```

**Step 3: Commit**

```bash
git add docs/rfcs/0008-pigpen-encrypted-document.md
git commit -m "docs(rfc0008): add the pointer face (piggy#216)"
```

---

## Task 2: New RFC 0010 — pigpen pointer resolution

**Promotion criteria:** N/A (documentation).

**Files:**
- Create: `docs/rfcs/0010-pigpen-pointer-resolution.md`

**Step 1: Write the RFC**

Follow the existing RFC 0008/0009 front-matter and section conventions
(`status: draft`, `date:`, `provenance:`). Required sections, each a
few sentences to a short paragraph:

- **Abstract** — one paragraph, cites RFC 0008 §2.2's pointer face.
- **1. Motivation** — the piggy#216 problem statement and the
  neutral-primitive layering constraint (piggy#191, papi's
  `docs/rfcs/0002-piggy-mgmt-constraints.md`).
- **2. Resolver discovery** — `pigpen-resolver-<kind>` PATH lookup,
  explicitly citing the existing `age-plugin-<name>` convention
  (`age-plugin-piggy`) as precedent.
- **3. Invocation contract** — `pigpen-resolver-<kind> resolve
  <locator>` → recipient-set-face pigpen bytes on stdout, exit 0;
  non-zero exit + stderr on failure. State explicitly that this is a
  one-shot contract, not the bidirectional age-plugin protocol, and
  why (§3 of the design doc has the reasoning to lift).
- **4. Caching** (informative, not wire-format-normative — this is
  piggy's own runtime behavior, not a cross-implementation
  interoperability concern) — `$XDG_CACHE_HOME/piggy/`, TTL tuning
  lever, `--no-cache`/`PIGGY_PIGPEN_NO_CACHE`.
- **5. Failure semantics** — hard-fail, no stale-cache fallback, error
  message shape (kind, locator, underlying stderr).
- **6. Security considerations** — piggy performs zero trust
  evaluation of the resolved bytes or the locator; that is entirely
  the resolver plugin's responsibility. A malicious or compromised
  `pigpen-resolver-<kind>` binary on `PATH` can return any recipient
  set — this is the same trust boundary as any other PATH-discovered
  plugin (`age-plugin-*`, `ssh-askpass`).
- **Worked examples** — a pointer document, a resolver invocation
  transcript (stdin/argv/stdout), a failure transcript.
- **References** — RFC 0008 (normative), papi RFC-0001 §14
  (informative, the papi-side producer/consumer this motivated).

**Step 2: Commit**

```bash
git add docs/rfcs/0010-pigpen-pointer-resolution.md
git commit -m "docs(rfc0010): pigpen pointer resolution protocol (piggy#216)"
```

---

## Task 3: RFC 0009 amendment — three-way `piggy-ids` sniff

**Promotion criteria:** N/A (documentation).

**Files:**
- Modify: `docs/rfcs/0009-pigpen-cutover.md` (§3.2 "Recipient set —
  `piggy-ids`, sniffed", currently lines 110–129)

**Step 1: Extend the sniff description**

After the existing "A reader disambiguates by a one-byte sniff" paragraph,
add:

```markdown
A third shape is a **pointer** (RFC 0008 §2.2, RFC 0010): still sniffed
by the same `---\n` opening-boundary check as the payload-less pigpen
case, then disambiguated from a recipient-set document by its type
line (`pigpen-pointer-v1` vs `pigpen-v1`). A pointer resolves — via
RFC 0010's plugin dispatch — into an in-memory recipient-set document
before any downstream consumer sees it; nothing below the sniff point
is pointer-aware.
```

**Step 2: Commit**

```bash
git add docs/rfcs/0009-pigpen-cutover.md
git commit -m "docs(rfc0009): three-way piggy-ids sniff for the pointer face (piggy#216)"
```

---

## Task 4: `piggy-pigpen` — pointer-face parse/construct

**Promotion criteria:** N/A (net-new code in an already-prototype
crate).

**Files:**
- Modify: `crates/piggy-pigpen/src/document.rs`
- Test: same file, `#[cfg(test)] mod tests`

**Step 1: Write the failing test**

Add near the existing `Document` tests (search for `mod tests` at the
bottom of the file):

```rust
#[test]
fn pointer_round_trips_kind_and_locator() {
    let ptr = Pointer {
        kind: "papi-http".into(),
        locator: "https://example.com".into(),
    };
    let bytes = ptr.to_bytes().unwrap();
    let parsed = Pointer::parse(&bytes).unwrap();
    assert_eq!(parsed.kind, "papi-http");
    assert_eq!(parsed.locator, "https://example.com");
}

#[test]
fn pointer_wire_shape_matches_rfc0008() {
    let ptr = Pointer {
        kind: "papi-http".into(),
        locator: "https://example.com".into(),
    };
    let bytes = ptr.to_bytes().unwrap();
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        "---\n- kind=\"papi-http\"\n- locator=\"https://example.com\"\n! pigpen-pointer-v1\n---\n"
    );
}

#[test]
fn pointer_parse_rejects_recipient_set_type() {
    let raw = b"---\n! pigpen-v1\n---\n";
    assert!(Pointer::parse(raw).is_err());
}

#[test]
fn pointer_parse_rejects_missing_locator() {
    let raw = b"---\n- kind=\"papi-http\"\n! pigpen-pointer-v1\n---\n";
    assert!(Pointer::parse(raw).is_err());
}
```

**Step 2: Run test to verify it fails**

Run: `just test-rust -p piggy-pigpen pointer_`

Note: `piggy-pigpen` is excluded from the workspace (root `Cargo.toml`),
so this runs against its own standalone `Cargo.lock` — `just
test-rust` already handles `-p <crate>` scoping correctly for
workspace members; for this excluded crate, `cd crates/piggy-pigpen &&
cargo test pointer_` is the fallback if `just test-rust -p piggy-pigpen`
doesn't resolve it (verify which works first; `just test-rust
--manifest-path crates/piggy-pigpen/Cargo.toml pointer_` is the third
fallback).

Expected: FAIL with "cannot find type `Pointer` in this scope" (or
similar — the type doesn't exist yet).

**Step 3: Write the implementation**

Add to `crates/piggy-pigpen/src/document.rs`, near the top with the
other type-tag constants:

```rust
const POINTER_TYPE_TAG: &str = "pigpen-pointer-v1";
```

Add near `Document` (after its `impl` block, or in a new section):

```rust
/// A pigpen pointer face (RFC 0008 §2.2, RFC 0010): names a resolver
/// by opaque `kind` + `locator` rather than carrying recipients
/// directly. `locator` is never interpreted by this crate — it is
/// handed verbatim to whatever invokes the resolver.
pub struct Pointer {
    pub kind: String,
    pub locator: String,
}

impl Pointer {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let h = HyphenceDoc {
            meta: vec![
                MetaLine {
                    prefix: b'-',
                    body: format!("kind=\"{}\"", self.kind),
                },
                MetaLine {
                    prefix: b'-',
                    body: format!("locator=\"{}\"", self.locator),
                },
                MetaLine {
                    prefix: b'!',
                    body: POINTER_TYPE_TAG.to_string(),
                },
            ],
            body: Vec::new(),
        };
        h.marshal()
    }

    pub fn parse(raw: &[u8]) -> Result<Pointer> {
        let h = crate::hyphence::parse(raw)?;
        let is_pointer = h
            .meta
            .iter()
            .any(|l| l.prefix == b'!' && l.body == POINTER_TYPE_TAG);
        if !is_pointer {
            return Err(Error::Malformed(format!(
                "not a {POINTER_TYPE_TAG} document"
            )));
        }
        let mut kind = None;
        let mut locator = None;
        for l in &h.meta {
            if l.prefix != b'-' {
                continue;
            }
            if let Some(v) = parse_quoted_kv(&l.body, "kind") {
                kind = Some(v);
            } else if let Some(v) = parse_quoted_kv(&l.body, "locator") {
                locator = Some(v);
            }
        }
        let kind = kind.ok_or_else(|| Error::Malformed("pointer missing kind tag".into()))?;
        let locator =
            locator.ok_or_else(|| Error::Malformed("pointer missing locator tag".into()))?;
        Ok(Pointer { kind, locator })
    }
}

/// Parse a `key="value"` tag body, e.g. `kind="papi-http"` with
/// `key = "kind"` returns `Some("papi-http")`. Returns `None` if the
/// prefix or quoting doesn't match — callers try each key in turn.
fn parse_quoted_kv(body: &str, key: &str) -> Option<String> {
    let rest = body.strip_prefix(key)?.strip_prefix('=')?;
    let inner = rest.strip_prefix('"')?.strip_suffix('"')?;
    Some(inner.to_string())
}
```

Add `Pointer` and `POINTER_TYPE_TAG` (if any other module needs it) to
the crate's public exports in `crates/piggy-pigpen/src/lib.rs`:

```rust
pub use document::{Document, EcdhOracle, Pointer, Recipient, X25519Identity, recipient_id};
```

**Step 4: Run test to verify it passes**

Run the same command as Step 2.

Expected: PASS, 4 tests.

**Step 5: Commit**

```bash
git add crates/piggy-pigpen/src/document.rs crates/piggy-pigpen/src/lib.rs
git commit -m "feat(piggy-pigpen): pigpen-pointer-v1 face (piggy#216)"
```

---

## Task 5: `resolve_piggy_ids_path` — sniff + RFC 0003 passthrough/conversion (no resolver yet)

**Promotion criteria:** N/A — this task deliberately stops short of
resolver dispatch (Task 7) so the sniff/conversion plumbing is testable
in isolation first.

**Files:**
- Create: `crates/piggy/src/pigpen_pointer.rs`
- Modify: `crates/piggy/Cargo.toml` (add dependency)
- Modify: `crates/piggy/src/main.rs` (register the new module — check
  how other modules like `health` are declared, likely a `mod
  pigpen_pointer;` line)

**Step 1: Add the dependency**

In `crates/piggy/Cargo.toml`, under `[dependencies]`, add:

```toml
piggy-pigpen = { path = "../piggy-pigpen" }
```

Run `just build-rust -p piggy` once to confirm the path dependency
resolves (piggy-pigpen's own `[workspace]` empty-table trick doesn't
block being depended on by a workspace member — cargo supports this;
if it errors, the fallback is investigating whether piggy-pigpen needs
`[package] workspace = false` removed or adjusted, but this configuration
is standard cargo and expected to work as-is).

**Step 2: Write the failing test**

Create `crates/piggy/src/pigpen_pointer.rs`:

```rust
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let dir = tempdir();
        let ids = dir.join("piggy-ids");
        // A minimal payload-less pigpen document, no recipients — proves
        // the sniff + conversion path without needing a real markl ID.
        std::fs::write(&ids, "---\n! pigpen-v1\n---\n").unwrap();
        let resolved = resolve_piggy_ids_path(&ids).unwrap();
        assert_ne!(resolved, ids, "a pigpen doc must produce a distinct cache path");
        let rendered = std::fs::read_to_string(&resolved).unwrap();
        assert_eq!(rendered, "", "zero recipients renders to an empty RFC 0003 file");
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
}
```

**Step 3: Run test to verify it fails**

Run: `just test-rust -p piggy pigpen_pointer::`

Expected: FAIL — `resolve_piggy_ids_path` doesn't exist yet.

**Step 4: Write the minimal implementation**

Append to `crates/piggy/src/pigpen_pointer.rs` (above the `#[cfg(test)]`
block):

```rust
/// See module docs. Returns the path a caller should read/pass to a
/// subprocess in place of the raw `piggy-ids` path.
pub(crate) fn resolve_piggy_ids_path(piggy_ids: &Path) -> Result<PathBuf, String> {
    let raw = std::fs::read(piggy_ids)
        .map_err(|e| format!("reading {}: {e}", piggy_ids.display()))?;

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
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    std::fs::write(&cache_path, rendered)
        .map_err(|e| format!("writing {}: {e}", cache_path.display()))?;
    Ok(cache_path)
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
```

Register the module in `crates/piggy/src/main.rs` — find the existing
`mod health;` (or similar) line and add:

```rust
mod pigpen_pointer;
```

**Step 5: Run test to verify it passes**

Run: `just test-rust -p piggy pigpen_pointer::`

Expected: PASS, 3 tests.

**Step 6: Commit**

```bash
git add crates/piggy/Cargo.toml crates/piggy/src/pigpen_pointer.rs crates/piggy/src/main.rs
git commit -m "feat(piggy): sniff + convert pigpen piggy-ids to RFC 0003 (piggy#216)"
```

---

## Task 6: Wire `resolve_piggy_ids_path` into the 7 existing call sites

**Promotion criteria:** N/A — `find_piggy_ids` itself is unchanged and
stays the low-level path lookup; this task only changes what callers do
with its result.

**Files:**
- Modify: `crates/piggy/src/reencrypt.rs:128`
- Modify: `crates/piggy/src/ssh_copy_id.rs:61`
- Modify: `crates/piggy/src/generate.rs:76`
- Modify: `crates/piggy/src/insert.rs:72`
- Modify: `crates/piggy/src/edit.rs:71`
- Modify: `crates/piggy/src/recipients.rs:46,105,164,320,415` (5 sites)

**Step 1: Confirm the exact shape at each site**

At each of the line numbers above, the pattern is:

```rust
let piggy_ids = match find_piggy_ids(&root, &subfolder) {
    Ok(p) => p,
    Err(msg) => { ... return ...; }
};
```

**Step 2: Swap in the new wrapper**

At each site, change `find_piggy_ids(&root, &subfolder)` (or whatever
the local variable names are — `subfolder`, `parsed.subfolder`, or `""`
for `ssh_copy_id.rs`) to a two-step call:

```rust
let piggy_ids = match find_piggy_ids(&root, &subfolder)
    .and_then(|p| pigpen_pointer::resolve_piggy_ids_path(&p))
{
    Ok(p) => p,
    Err(msg) => { ... return ...; }
};
```

The `Err(msg) => { ... }` arm's existing body (error printing + return
code) is unchanged at every site — `resolve_piggy_ids_path` returns the
same `Result<PathBuf, String>` shape `find_piggy_ids` did, so no arm
logic needs editing, only the `Ok(...)` expression being matched on.

**Step 3: Run the full crate test suite**

Run: `just test-rust -p piggy`

Expected: all existing tests still PASS (this task changes no test
files — it's a pure call-site swap covered by Task 5's own tests plus
every existing `recipients`/`reencrypt`/`insert`/`generate`/`edit`/
`ssh_copy_id` test, which all use RFC 0003 fixtures and must be
unaffected by the passthrough no-op path).

**Step 4: Commit**

```bash
git add crates/piggy/src/reencrypt.rs crates/piggy/src/ssh_copy_id.rs \
        crates/piggy/src/generate.rs crates/piggy/src/insert.rs \
        crates/piggy/src/edit.rs crates/piggy/src/recipients.rs
git commit -m "feat(piggy): route piggy-ids reads through the pigpen sniff (piggy#216)"
```

---

## Task 7: Resolver discovery + invocation

**Promotion criteria:** N/A.

**Files:**
- Modify: `crates/piggy/src/pigpen_pointer.rs`

**Step 1: Write the failing test**

Add to the `tests` module:

```rust
#[test]
fn resolver_not_on_path_produces_named_error() {
    // No fixture resolver installed for this kind — PATH lookup must
    // fail with a message naming the missing binary, not a generic
    // "command not found".
    let err = invoke_resolver("nonexistent-test-kind", "whatever").unwrap_err();
    assert!(
        err.contains("pigpen-resolver-nonexistent-test-kind"),
        "got: {err}"
    );
}

#[test]
fn resolver_success_returns_stdout_bytes() {
    use std::os::unix::fs::PermissionsExt as _;
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
        format!("{}:{}", dir.display(), saved_path.as_ref().map_or_else(String::new, |p| p.to_string_lossy().into_owned())),
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
        format!("{}:{}", dir.display(), saved_path.as_ref().map_or_else(String::new, |p| p.to_string_lossy().into_owned())),
    );
    let err = invoke_resolver("fail-test", "whatever");
    match saved_path {
        Some(v) => std::env::set_var("PATH", v),
        None => std::env::remove_var("PATH"),
    }

    let err = err.unwrap_err();
    assert!(err.contains("papi unreachable"), "got: {err}");
}
```

Note: these three tests mutate the process-wide `PATH` env var. Follow
the `crypt.rs::env_lock()` pattern (a `static Mutex` guard acquired at
the top of each mutating test) to keep them race-free under bats'
default multi-threaded test runner — copy that helper into this file's
test module rather than re-deriving it.

**Step 2: Run test to verify it fails**

Run: `just test-rust -p piggy pigpen_pointer::`

Expected: FAIL — `invoke_resolver` doesn't exist yet.

**Step 3: Write the minimal implementation**

Add to `crates/piggy/src/pigpen_pointer.rs` (non-test section):

```rust
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
```

**Step 4: Run test to verify it passes**

Run the same command as Step 2.

Expected: PASS, 3 new tests (6 total in this module).

**Step 5: Commit**

```bash
git add crates/piggy/src/pigpen_pointer.rs
git commit -m "feat(piggy): pigpen-resolver-<kind> PATH discovery + invocation (piggy#216)"
```

---

## Task 8: Cache TTL + `--no-cache` / `PIGGY_PIGPEN_NO_CACHE`

**Promotion criteria:** N/A.

**Files:**
- Modify: `crates/piggy/src/pigpen_pointer.rs`

**Step 1: Write the failing test**

```rust
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
    assert!(!cache_is_fresh(&cache_file, std::time::Duration::from_secs(3600)));
}

#[test]
fn no_cache_env_var_forces_resolve() {
    let _guard = env_lock();
    std::env::set_var("PIGGY_PIGPEN_NO_CACHE", "1");
    let disabled = cache_disabled();
    std::env::remove_var("PIGGY_PIGPEN_NO_CACHE");
    assert!(disabled);
}
```

**Step 2: Run test to verify it fails**

Run: `just test-rust -p piggy pigpen_pointer::`

Expected: FAIL — `cache_is_fresh`/`cache_disabled` don't exist yet.

**Step 3: Write the minimal implementation**

```rust
/// Tuning lever (design doc): 1 hour default. Change signal: real usage
/// shows stale-recipient complaints (lower it) or resolver-load
/// complaints (raise it).
const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

fn cache_is_fresh(cache_file: &Path, ttl: std::time::Duration) -> bool {
    let Ok(meta) = std::fs::metadata(cache_file) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    modified.elapsed().is_ok_and(|age| age < ttl)
}

fn cache_disabled() -> bool {
    std::env::var_os("PIGGY_PIGPEN_NO_CACHE").is_some_and(|v| !v.is_empty())
}
```

Also add the `env_lock()` helper (copy verbatim from `crypt.rs`'s test
module, per Task 7 Step 1's note) at the top of this file's `tests`
module if not already present from Task 7.

**Step 4: Run test to verify it passes**

Expected: PASS, 4 new tests (10 total in this module).

**Step 5: Wire the pointer branch of `resolve_piggy_ids_path` to actually
call the resolver, honoring cache-fresh/disabled/miss**

Replace the placeholder pointer-face branch from Task 5 Step 4:

```rust
    if let Ok(ptr) = piggy_pigpen::Pointer::parse(&raw) {
        return Err(format!(
            "{}: pointer face (kind={:?}, locator={:?}) — resolver dispatch not yet wired",
            piggy_ids.display(),
            ptr.kind,
            ptr.locator
        ));
    }
```

with:

```rust
    if let Ok(ptr) = piggy_pigpen::Pointer::parse(&raw) {
        let cache_file = cache_path_for(piggy_ids)?;
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
```

Factor the existing recipient-set-to-RFC0003 conversion (Task 5 Step 4's
tail, from `let recipients: Result<...>` through the final `Ok(cache_path)`)
into a shared helper `recipient_set_doc_to_rfc0003_cache(piggy_ids: &Path,
doc: piggy_pigpen::Document) -> Result<PathBuf, String>` so both the
plain-recipient-set branch and this newly-resolved-pointer branch call
the same conversion code — avoids duplicating the
recipient-conversion-and-cache-write logic.

**Step 6: Add an end-to-end unit test for the pointer branch**

```rust
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

    let saved_path = std::env::var_os("PATH");
    let saved_cache = std::env::var_os("XDG_CACHE_HOME");
    std::env::set_var(
        "PATH",
        format!("{}:{}", dir.display(), saved_path.as_ref().map_or_else(String::new, |p| p.to_string_lossy().into_owned())),
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
```

**Step 7: Run the full module test suite**

Run: `just test-rust -p piggy pigpen_pointer::`

Expected: PASS, 11 tests total in this module.

**Step 8: Commit**

```bash
git add crates/piggy/src/pigpen_pointer.rs
git commit -m "feat(piggy): cache TTL + resolver dispatch wiring for pigpen pointers (piggy#216)"
```

---

## Task 9: Bats end-to-end coverage

**Promotion criteria:** N/A.

**Files:**
- Create: `zz-tests_bats/t0900-pigpen-pointer.bats`
- Reference (existing convention to mirror): `zz-tests_bats/helpers/mock-pivy-box.sh`

**Step 1: Write the bats file**

```bash
#!/usr/bin/env bats
# bats file_tags=

setup() {
  load "$(dirname "$BATS_TEST_FILE")/helpers/common.bash" 2>/dev/null || true
  export PIGGY_STORE_DIR="$BATS_TEST_TMPDIR/store"
  mkdir -p "$PIGGY_STORE_DIR"
  export XDG_CACHE_HOME="$BATS_TEST_TMPDIR/cache"

  # Fixture resolver: always returns an empty recipient-set pigpen doc.
  # (A store with zero encryption recipients is enough to prove the
  # pointer -> resolver -> RFC 0003 cache path end-to-end; the
  # crate-level tests in pigpen_pointer.rs already cover recipient
  # content conversion in depth.)
  local fixture_dir="$BATS_TEST_TMPDIR/bin"
  mkdir -p "$fixture_dir"
  cat >"$fixture_dir/pigpen-resolver-bats-fixture" <<'EOF'
#!/bin/sh
printf -- '---\n! pigpen-v1\n---\n'
EOF
  chmod +x "$fixture_dir/pigpen-resolver-bats-fixture"
  export PATH="$fixture_dir:$PATH"

  cat >"$PIGGY_STORE_DIR/piggy-ids" <<'EOF'
---
- kind="bats-fixture"
- locator="unused"
! pigpen-pointer-v1
---
EOF
}

function pigpen_pointer_resolves_for_recipients_list { # @test
  run "$PIGGY_BIN" pass recipients list
  assert_success
  # Zero recipients in the resolved (empty) recipient-set doc.
  assert_output ""
}
```

Confirm the exact `PIGGY_BIN` variable name and `assert_success`/
`assert_output` helper availability by checking an existing bats file in
`zz-tests_bats/t07*.bats` or `t08*.bats` before finalizing — this plan's
snippet mirrors the general shape but the harness's exact bats-support
library loading (`bats-assert`, `bats-support`) conventions should be
copied from a neighboring file rather than re-derived.

**Step 2: Run it**

Run: `just test-bats-file zz-tests_bats/t0900-pigpen-pointer.bats`

Expected: PASS.

**Step 3: Commit**

```bash
git add zz-tests_bats/t0900-pigpen-pointer.bats
git commit -m "test(bats): end-to-end pigpen pointer resolution (piggy#216)"
```

---

## Task 10: Full suite + update piggy#26 and piggy#216

**Files:** N/A (verification + issue tracker updates).

**Step 1: Run the full local gate**

Run: `just test`

Expected: PASS (this is what `merge-this-session`'s pre-merge hook also
runs, per the repo's `sweatfile`).

**Step 2: Update piggy#26**

Add a dated entry to piggy#26 (the triage tracker) noting piggy#216 is
implemented, referencing the new RFC 0008/0009/0010 amendments and this
plan's commits.

**Step 3: Close piggy#216**

Comment on piggy#216 summarizing what landed (the pointer face, the
resolver-dispatch contract, the cache/failure semantics) and close it,
linking the design doc, this plan, and the RFC amendments.
