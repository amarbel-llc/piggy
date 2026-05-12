# `piggy pass recipients add --all-attached` Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use eng:subagent-driven-development to implement this plan task-by-task.

**Goal:** Add `--all-attached` / `-A` flag to `piggy pass recipients add` that enumerates every plugged-in PIV card, classifies each card's slot 9D as supported / unsupported, dedupes against the active `piggy-ids`, prompts on the unsupported set, and appends the supported recipients via the existing canonicalize/reencrypt/commit path.

**Design doc:** `docs/plans/2026-05-12-recipients-add-attached-design.md` (commit `fdb9f52`).

**Architecture:** A new pure-compute Rust subcommand `piggy-ids detect-all-pubkeys` emits structured lines (`supported <id> <guid>` / `unsupported <guid> <reason>`) for every attached PIV card. A new branch in `cmd_pass_recipients_add` (`src/piggy.sh`) consumes that output, dedupes against the existing `piggy-ids`, drives the unsupported-cards dialog and TTY prompt, and reuses the existing add-path tail (append + canonicalize + reencrypt + two commits) for survivors.

**Tech Stack:** Rust (clap, openssl re-used via existing `compress_p256_pubkey`), bash (`src/piggy.sh`), bats (tier 1 mock-driven + tier 2 fib-driven conformance), `just` recipes.

**Rollback:** Purely additive. To revert: delete the `DetectAllPubkeys` clap variant in `crates/piggy-ids/src/main.rs`, delete the `--all-attached` / `-A` branch in `cmd_pass_recipients_add` in `src/piggy.sh`, and remove the new bats / justfile recipe. No data migration, no stored state.

**Companion follow-up:** amarbel-llc/piggy#83 (fib multi-card support for end-to-end multi-card test coverage). Roadmap tracker: amarbel-llc/piggy#26.

---

## Phase A — Rust helper

### Task 1: Extract a pure `classify_slot_9d` function

**Promotion criteria:** N/A — additive refactor.

**Files:**
- Modify: `crates/piggy-ids/src/main.rs` (the existing `cmd_detect_pubkey` body, around lines 194–222)
- Test: `crates/piggy-ids/tests/classify.rs` (new)

**Context:** Today the classify-one-card logic is inline in `cmd_detect_pubkey`. We extract it into a pure function that takes the parts of a card we care about (GUID, slot algorithm, slot cert DER) and returns a `Classification` enum. Both `cmd_detect_pubkey` (existing) and `cmd_detect_all_pubkeys` (new in Task 3) call into it. Pure-function shape lets us unit-test classification without spinning up a `PivContext`.

**Step 1: Write the failing unit test**

Create `crates/piggy-ids/tests/classify.rs`:

```rust
//! Unit tests for `piggy_ids::classify_slot_9d`. No PIV context needed —
//! we feed synthetic algorithm values and cert bytes.

use piggy_ids::{classify_slot_9d, Classification};
use piggy_piv::{Guid, PivAlgorithm};

fn fake_guid() -> Guid {
    Guid::from_hex("00112233445566778899aabbccddeeff").expect("valid hex")
}

#[test]
fn rsa_in_9d_is_unsupported() {
    let guid = fake_guid();
    let cert: &[u8] = &[]; // irrelevant when algorithm rejects the slot
    match classify_slot_9d(guid, PivAlgorithm::Rsa2048, cert) {
        Classification::Unsupported { reason, .. } => {
            assert!(
                reason.contains("Rsa2048") || reason.contains("RsaP2048"),
                "reason missing algorithm name: {reason}"
            );
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn malformed_cert_in_9d_is_unsupported() {
    let guid = fake_guid();
    let cert: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF]; // not a valid X.509 cert
    match classify_slot_9d(guid, PivAlgorithm::EcP256, cert) {
        Classification::Unsupported { reason, .. } => {
            assert!(
                reason.contains("pubkey decode failed") || reason.contains("decode"),
                "reason missing decode error: {reason}"
            );
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}
```

(Note: we deliberately skip a `Supported` happy-path test in this unit because constructing a valid P-256 X.509 fixture in-test is awkward and the supported path is exercised end-to-end by tier-2 fib bats in Task 11.)

**Step 2: Run test, verify it fails**

```
just test-rust -p piggy-ids --test classify
```

Expected: compilation failure — `classify_slot_9d`, `Classification`, and the module-level re-exports don't exist yet.

**Step 3: Implement classifier and re-export**

In `crates/piggy-ids/src/lib.rs`, add a new module + re-exports:

```rust
pub mod classify;
pub use classify::{classify_slot_9d, Classification};
```

Create `crates/piggy-ids/src/classify.rs`:

```rust
//! Classify a PIV card's slot 9D as supported (P-256 ECDH, the only
//! algorithm piggy 2.x can encrypt to) or unsupported (anything else,
//! including a malformed cert in a slot the card *claims* is EcP256).
//!
//! Pure function; no PCSC, no I/O. Callers feed it the GUID + slot
//! metadata they already read from `PivContext::enumerate_tokens()` and
//! `token.read_slot(0x9D)`.

use piggy_markl::{FormatId, Id as MarklId, PurposeId};
use piggy_piv::{Guid, PivAlgorithm};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification {
    Supported { id: MarklId, guid: Guid },
    Unsupported { guid: Guid, reason: String },
}

pub fn classify_slot_9d(guid: Guid, algo: PivAlgorithm, cert_der: &[u8]) -> Classification {
    if algo != PivAlgorithm::EcP256 {
        return Classification::Unsupported {
            guid,
            reason: format!("slot 9D is {algo:?}"),
        };
    }
    let compressed = match compress_p256_pubkey(cert_der) {
        Ok(c) => c,
        Err(e) => {
            return Classification::Unsupported {
                guid,
                reason: format!("pubkey decode failed: {e}"),
            };
        }
    };
    match MarklId::new(
        Some(PurposeId::PiggyRecipientV1),
        FormatId::PivyEcdhP256Pub,
        compressed,
    ) {
        Ok(id) => Classification::Supported { id, guid },
        Err(e) => Classification::Unsupported {
            guid,
            reason: format!("markl ID build failed: {e}"),
        },
    }
}

fn compress_p256_pubkey(cert_der: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cert = openssl::x509::X509::from_der(cert_der)?;
    let pubkey = cert.public_key()?;
    let ec = pubkey.ec_key()?;
    let group = ec.group();
    let mut bn_ctx = openssl::bn::BigNumContext::new()?;
    let compressed = ec.public_key().to_bytes(
        group,
        openssl::ec::PointConversionForm::COMPRESSED,
        &mut bn_ctx,
    )?;
    if compressed.len() != 33 {
        return Err(format!("expected 33-byte compressed P-256 point, got {}", compressed.len()).into());
    }
    Ok(compressed)
}
```

Make sure `crates/piggy-ids/Cargo.toml` already depends on `openssl`, `piggy-markl`, and `piggy-piv`. (If not present, copy from the `[dependencies]` table the `main.rs` already uses.)

**Step 4: Run tests, verify they pass**

```
just test-rust -p piggy-ids --test classify
```

Expected: both tests pass.

**Step 5: Commit**

```
git add crates/piggy-ids/src/lib.rs crates/piggy-ids/src/classify.rs crates/piggy-ids/tests/classify.rs
git commit -m "crates/piggy-ids: extract pure classify_slot_9d helper

Splits the inline classify-one-card logic out of cmd_detect_pubkey
into a pure function that takes (guid, algorithm, cert_der) and
returns a Classification enum. Pure-function shape lets us unit-test
the algorithm-rejection and cert-decode-failure paths without a
PivContext. The existing cmd_detect_pubkey is re-pointed in the
next commit; the new detect-all-pubkeys subcommand consumes it in
the commit after that.

:clown: Designed with [Clown](https://github.com/amarbel-llc/clown)."
```

---

### Task 2: Re-point `cmd_detect_pubkey` at `classify_slot_9d`

**Promotion criteria:** N/A — no-op refactor; behavior preserved.

**Files:**
- Modify: `crates/piggy-ids/src/main.rs` (`cmd_detect_pubkey`, around lines 190–222 and `compress_p256_pubkey` around lines 255–274)

**Step 1: Verify existing tests pass before touching**

```
just test-rust -p piggy-ids
just test-bats-file zz-tests_bats/t0002-init-piggy-ids.bats
```

Expected: pass. (`t0002` exercises `piggy pass init` which drives `detect-pubkey`; the bats mock short-circuits, so this only proves the test wrapper still compiles. The real coverage of `detect-pubkey` is tier-2 conformance against fib — we'll verify there in step 4.)

**Step 2: Refactor `cmd_detect_pubkey` to use `classify_slot_9d`**

In `crates/piggy-ids/src/main.rs`, replace the body of `cmd_detect_pubkey` (around lines 194–222) with:

```rust
fn cmd_detect_pubkey(guid_hex: Option<&str>) -> Result<ExitCode, DynErr> {
    use piggy_ids::{classify_slot_9d, Classification};

    let ctx = PivContext::new()?;
    let tokens = ctx.enumerate_tokens()?;
    if tokens.is_empty() {
        return Err("no PIV cards detected".into());
    }

    let token = pick_token(&tokens, guid_hex)?;
    let slot = token.read_slot(0x9D)?;
    match classify_slot_9d(*token.guid(), slot.algorithm(), slot.cert_der()) {
        Classification::Supported { id, .. } => {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            writeln!(out, "{}", id)?;
            Ok(ExitCode::SUCCESS)
        }
        Classification::Unsupported { reason, .. } => Err(reason.into()),
    }
}
```

Delete the now-unused local `compress_p256_pubkey` helper at the bottom of `main.rs` (the one we moved into `classify.rs`).

Delete the now-unused imports `FormatId`, `PurposeId`, `MarklId`, `PivAlgorithm` from the top of `main.rs` if Rust complains about unused.

**Step 3: Run tests**

```
just test-rust -p piggy-ids
just lint-rust
just build-rust
```

Expected: green.

**Step 4: Live-check `detect-pubkey` against fib (sanity)**

```
just fib-up
eval "$(cat .fib/env)"
pivy-tool -P 123456 -K default -a eccp256 generate 9d >/dev/null
./target/debug/piggy-ids detect-pubkey
just fib-down
```

Expected: emits a single line `piggy-recipient-v1@pivy_ecdh_p256_pub-...` to stdout, exit 0. (Tests this refactor didn't change behavior.)

**Step 5: Commit**

```
git add crates/piggy-ids/src/main.rs
git commit -m "crates/piggy-ids: route cmd_detect_pubkey through classify_slot_9d

No behavior change. Removes the inline algorithm check and
compress_p256_pubkey helper (now in the classify module) in favor
of dispatching on Classification. Mechanical refactor in preparation
for the detect-all-pubkeys subcommand in the next commit.

:clown: Designed with [Clown](https://github.com/amarbel-llc/clown)."
```

---

### Task 3: Add `detect-all-pubkeys` subcommand

**Promotion criteria:** N/A — new surface.

**Files:**
- Modify: `crates/piggy-ids/src/main.rs` (clap enum at line 44 and dispatch at line 95)

**Step 1: Write the failing live-run check**

There's no clean unit test for the subcommand surface itself (the meat is the structured-output rendering, which is one line of `writeln!` per token). We rely on the Tier-2 fib bats in Task 11 for end-to-end coverage. For this task the test is a hand-run smoke check after the binary builds.

**Step 2: Add the clap variant**

In `crates/piggy-ids/src/main.rs`, extend the `Cmd` enum (around line 44):

```rust
    /// Enumerate every attached PIV card and emit one line per card:
    /// `supported <markl-id>  <guid-hex>` or
    /// `unsupported <guid-hex>  <reason>`. Lines are sorted by GUID for
    /// stable output. Exit 0 even when all cards are unsupported or no
    /// cards are attached; nonzero only on PCSC failure.
    DetectAllPubkeys,
```

And the dispatch arm in `fn dispatch` (around line 95):

```rust
        Cmd::DetectAllPubkeys => cmd_detect_all_pubkeys(),
```

Update the module-level doc comment at the top of `main.rs` (around line 14) to mention the new subcommand alongside `detect-pubkey`.

**Step 3: Implement `cmd_detect_all_pubkeys`**

Append to `crates/piggy-ids/src/main.rs`:

```rust
fn cmd_detect_all_pubkeys() -> Result<ExitCode, DynErr> {
    use piggy_ids::{classify_slot_9d, Classification};

    let ctx = PivContext::new()?;
    let tokens = ctx.enumerate_tokens()?;

    let mut classifications: Vec<Classification> = Vec::with_capacity(tokens.len());
    for token in &tokens {
        match token.read_slot(0x9D) {
            Ok(slot) => classifications.push(classify_slot_9d(
                *token.guid(),
                slot.algorithm(),
                slot.cert_der(),
            )),
            Err(e) => classifications.push(Classification::Unsupported {
                guid: *token.guid(),
                reason: format!("slot 9D unreadable: {e}"),
            }),
        }
    }

    classifications.sort_by_key(|c| match c {
        Classification::Supported { guid, .. } => guid.to_hex(),
        Classification::Unsupported { guid, .. } => guid.to_hex(),
    });

    let stdout = io::stdout();
    let mut out = stdout.lock();
    for c in &classifications {
        match c {
            Classification::Supported { id, guid } => {
                writeln!(out, "supported {}  {}", id, guid.to_hex())?;
            }
            Classification::Unsupported { guid, reason } => {
                writeln!(out, "unsupported {}  {}", guid.to_hex(), reason)?;
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}
```

**Step 4: Run tests**

```
just build-rust
just lint-rust
just test-rust -p piggy-ids
```

Expected: green.

**Step 5: Live smoke against fib**

```
just fib-up
eval "$(cat .fib/env)"
pivy-tool -P 123456 -K default -a eccp256 generate 9d >/dev/null
./target/debug/piggy-ids detect-all-pubkeys
```

Expected one line of the shape:
```
supported piggy-recipient-v1@pivy_ecdh_p256_pub-<blech32>  <guid-hex>
```

Then test the unsupported branch by regenerating 9D as RSA:

```
pivy-tool -P 123456 -K default -a rsa2048 generate 9d >/dev/null
./target/debug/piggy-ids detect-all-pubkeys
just fib-down
```

Expected one line of the shape:
```
unsupported <guid-hex>  slot 9D is Rsa2048
```

(Algorithm enum name may differ slightly; that's fine — bats matches by substring.)

**Step 6: Commit**

```
git add crates/piggy-ids/src/main.rs
git commit -m "crates/piggy-ids: add detect-all-pubkeys subcommand

Emits one line per attached PIV card:
- supported <markl-id>  <guid-hex>
- unsupported <guid-hex>  <reason>

Lines sorted by GUID for stable output. Exit 0 even when all cards
are unsupported or no cards are attached; nonzero only on PCSC
failure. Pure-compute: no piggy-ids reads, no prompts, no mutation.

Drives the new piggy pass recipients add --all-attached path
(landing in the following commits).

:clown: Designed with [Clown](https://github.com/amarbel-llc/clown)."
```

---

## Phase B — Bats mock helper

### Task 4: Extend `mock-piggy-ids.sh` with `detect-all-pubkeys`

**Promotion criteria:** N/A.

**Files:**
- Modify: `zz-tests_bats/helpers/mock-piggy-ids.sh`

**Step 1: Add the case**

Add a new branch in the `case` block (sibling to the existing `detect-pubkey` case) in `zz-tests_bats/helpers/mock-piggy-ids.sh`:

```bash
detect-all-pubkeys)
  # Canned output via env vars. Each var is newline-separated.
  # PIGGY_TEST_DETECT_ALL_SUPPORTED: lines of "<markl-id>\t<guid-hex>"
  # PIGGY_TEST_DETECT_ALL_UNSUPPORTED: lines of "<guid-hex>\t<reason>"
  # Unset → empty output (i.e. no cards attached).
  if [[ -n ${PIGGY_TEST_DETECT_ALL_FAIL:-} ]]; then
    echo "mock-piggy-ids: $PIGGY_TEST_DETECT_ALL_FAIL" >&2
    exit 1
  fi
  while IFS=$'\t' read -r id guid; do
    [[ -z $id && -z $guid ]] && continue
    printf 'supported %s  %s\n' "$id" "$guid"
  done <<<"${PIGGY_TEST_DETECT_ALL_SUPPORTED:-}"
  while IFS=$'\t' read -r guid reason; do
    [[ -z $guid && -z $reason ]] && continue
    printf 'unsupported %s  %s\n' "$guid" "$reason"
  done <<<"${PIGGY_TEST_DETECT_ALL_UNSUPPORTED:-}"
  ;;
```

Also update the file-level comment to mention `detect-all-pubkeys` and the new env vars.

**Step 2: Smoke-test the mock**

```
PIGGY_TEST_DETECT_ALL_SUPPORTED=$'piggy-recipient-v1@pivy_ecdh_p256_pub-foo\tdeadbeef' \
PIGGY_TEST_DETECT_ALL_UNSUPPORTED=$'cafef00d\tslot 9D is Rsa2048' \
  zz-tests_bats/helpers/mock-piggy-ids.sh detect-all-pubkeys
```

Expected output:
```
supported piggy-recipient-v1@pivy_ecdh_p256_pub-foo  deadbeef
unsupported cafef00d  slot 9D is Rsa2048
```

**Step 3: Commit**

```
git add zz-tests_bats/helpers/mock-piggy-ids.sh
git commit -m "zz-tests_bats/helpers: mock detect-all-pubkeys in mock-piggy-ids.sh

Canned output driven by PIGGY_TEST_DETECT_ALL_SUPPORTED and
PIGGY_TEST_DETECT_ALL_UNSUPPORTED (newline-separated, tab-delimited).
Unset → empty output (no cards). PIGGY_TEST_DETECT_ALL_FAIL flips
the command to a stderr failure, mirroring the existing
PIGGY_TEST_DETECT_FAIL pattern.

:clown: Designed with [Clown](https://github.com/amarbel-llc/clown)."
```

---

## Phase C — Bash CLI surface (TDD via Tier-1 bats)

### Task 5: Tier-1 bats — usage-error case (`--all-attached` + positional)

**Promotion criteria:** N/A.

**Files:**
- Create: `zz-tests_bats/t0610-recipients-add-attached.bats`

**Step 1: Write the failing test**

Create `zz-tests_bats/t0610-recipients-add-attached.bats`:

```bash
setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  init_test_git
  "$PIGGY" pass init -k "$RECIPIENT_PRIMARY"
}

RECIPIENT_PRIMARY="piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu"
RECIPIENT_SECONDARY="piggy-recipient-v1@pivy_ecdh_p256_pub-qvqq6x38x3q5ukmgwkpgl89fkmpaph027uzpz83t8pz4yhmv0xrfxgs3lef"

function add_attached_with_positional_id_is_usage_error { # @test
  run "$PIGGY" pass recipients add --all-attached "$RECIPIENT_SECONDARY"
  assert_failure
  assert_output --partial "mutually exclusive"
}
```

**Step 2: Run the test, verify it fails**

```
just test-bats-file zz-tests_bats/t0610-recipients-add-attached.bats
```

Expected: failure — either the flag isn't recognized at all (parsing falls through and treats `--all-attached` as a markl ID, succeeds in adding garbage), or the error message doesn't contain "mutually exclusive".

**Step 3: Add the arg parser**

In `src/piggy.sh`, modify `cmd_pass_recipients_add` (currently lines 790–818) so the head looks like:

```bash
cmd_pass_recipients_add() {
  local subfolder=""
  local all_attached=0
  local assume_yes=0
  local -a ids=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
    -p)
      subfolder="$2"
      shift 2
      ;;
    -A | --all-attached)
      all_attached=1
      shift
      ;;
    --yes)
      assume_yes=1
      shift
      ;;
    *)
      ids+=("$1")
      shift
      ;;
    esac
  done

  if [[ $all_attached -eq 1 && ${#ids[@]} -gt 0 ]]; then
    die "Error: --all-attached and explicit markl IDs are mutually exclusive."
  fi

  if [[ $all_attached -eq 1 ]]; then
    _cmd_pass_recipients_add_all_attached "$subfolder" "$assume_yes"
    return
  fi

  [[ ${#ids[@]} -gt 0 ]] || die "Usage: $PROGRAM_PASS recipients add <markl-id>... [-A | --all-attached] [--yes] [-p subfolder]"
  find_piggy_ids "$subfolder"
  set_git "$PIGGY_IDS"
  for id in "${ids[@]}"; do
    echo "$id" >>"$PIGGY_IDS"
  done
  "${PIGGY_IDS_PATH:-piggy-ids}" canonicalize "$PIGGY_IDS" || die "Error: invalid recipient(s); aborting."

  local id_dir="${PIGGY_IDS%/piggy-ids}"
  git_add_file "$PIGGY_IDS" "Add recipient(s) to piggy-ids."
  reencrypt_path "$id_dir"
  git_add_file "$id_dir" "Reencrypt password store after adding recipient(s)."
}

_cmd_pass_recipients_add_all_attached() {
  local subfolder="$1"
  local assume_yes="$2"
  die "Error: --all-attached not yet implemented."
}
```

(The `_cmd_pass_recipients_add_all_attached` stub will be fleshed out in subsequent tasks.)

Update the usage block in `cmd_pass_recipients` (around lines 754–764) to mention the new flag:

```
    $PROGRAM_PASS recipients add <markl-id>... [-p subfolder]
    $PROGRAM_PASS recipients add -A | --all-attached [--yes] [-p subfolder]
        Append recipients to piggy-ids and re-encrypt. With -A,
        enumerate attached PIV cards and add supported ones.
```

**Step 4: Run the test, verify it passes**

```
just test-bats-file zz-tests_bats/t0610-recipients-add-attached.bats
```

Expected: pass.

**Step 5: Commit**

```
git add zz-tests_bats/t0610-recipients-add-attached.bats src/piggy.sh
git commit -m "src/piggy.sh: parse --all-attached / -A / --yes in recipients add

Adds flag parsing and a stub handler that errors out; the
end-to-end behavior is wired up in the following commits. Test
covers the mutual-exclusion with positional markl IDs.

:clown: Designed with [Clown](https://github.com/amarbel-llc/clown)."
```

---

### Task 6: Tier-1 bats — happy path (one new card)

**Promotion criteria:** N/A.

**Files:**
- Modify: `zz-tests_bats/t0610-recipients-add-attached.bats`
- Modify: `src/piggy.sh` (`_cmd_pass_recipients_add_all_attached`)

**Step 1: Write the failing test**

Append to `zz-tests_bats/t0610-recipients-add-attached.bats`:

```bash
function add_attached_happy_path_one_new_card { # @test
  # Store is initialized with RECIPIENT_PRIMARY; mock emits a
  # different card so --all-attached has something to add.
  local new_card="$RECIPIENT_SECONDARY"
  local guid="deadbeef00000000aabbccddeeff0011"
  export PIGGY_TEST_DETECT_ALL_SUPPORTED=$'piggy-recipient-v1@pivy_ecdh_p256_pub-qvqq6x38x3q5ukmgwkpgl89fkmpaph027uzpz83t8pz4yhmv0xrfxgs3lef\tdeadbeef00000000aabbccddeeff0011'

  run "$PIGGY" pass recipients add --all-attached
  assert_success
  run cat "$PIGGY_STORE_DIR/piggy-ids"
  assert_success
  assert_output --partial "$new_card"
  assert_output --partial "$RECIPIENT_PRIMARY"  # original still present
}
```

**Step 2: Run, verify failure**

```
just test-bats-file zz-tests_bats/t0610-recipients-add-attached.bats
```

Expected: `add_attached_happy_path_one_new_card` fails — stub still dies. The `add_attached_with_positional_id_is_usage_error` from Task 5 must still pass.

**Step 3: Implement the main flow (minus dedup/dialog)**

Replace the body of `_cmd_pass_recipients_add_all_attached` in `src/piggy.sh`:

```bash
_cmd_pass_recipients_add_all_attached() {
  local subfolder="$1"
  local assume_yes="$2"

  find_piggy_ids "$subfolder"
  set_git "$PIGGY_IDS"

  local helper_out
  helper_out="$("${PIGGY_IDS_PATH:-piggy-ids}" detect-all-pubkeys)" ||
    die "Error: detect-all-pubkeys failed; see stderr."

  local -a supported_ids=()
  local -a supported_guids=()
  local -a unsupported_lines=()
  while IFS= read -r line; do
    [[ -z $line ]] && continue
    case "$line" in
    "supported "*)
      # supported <id>  <guid>
      local rest="${line#supported }"
      local id="${rest%%  *}"
      local guid="${rest##*  }"
      supported_ids+=("$id")
      supported_guids+=("$guid")
      ;;
    "unsupported "*)
      unsupported_lines+=("${line#unsupported }")
      ;;
    *)
      die "Error: malformed line from piggy-ids detect-all-pubkeys: $line"
      ;;
    esac
  done <<<"$helper_out"

  if [[ ${#supported_ids[@]} -eq 0 && ${#unsupported_lines[@]} -eq 0 ]]; then
    die "Error: no PIV cards detected."
  fi

  # Dedup support and dialog are added in subsequent commits.
  # For now: assume all supported are new.
  local -a to_add=("${supported_ids[@]}")
  if [[ ${#to_add[@]} -eq 0 ]]; then
    echo "nothing to add" >&2
    return 0
  fi

  for id in "${to_add[@]}"; do
    echo "$id" >>"$PIGGY_IDS"
  done
  "${PIGGY_IDS_PATH:-piggy-ids}" canonicalize "$PIGGY_IDS" || die "Error: invalid recipient(s); aborting."

  local id_dir="${PIGGY_IDS%/piggy-ids}"
  git_add_file "$PIGGY_IDS" "Add ${#to_add[@]} attached card(s) to piggy-ids."
  reencrypt_path "$id_dir"
  git_add_file "$id_dir" "Reencrypt password store after adding ${#to_add[@]} attached card(s)."
}
```

**Step 4: Run the test, verify it passes**

```
just test-bats-file zz-tests_bats/t0610-recipients-add-attached.bats
```

Expected: both tests pass.

**Step 5: Commit**

```
git add zz-tests_bats/t0610-recipients-add-attached.bats src/piggy.sh
git commit -m "src/piggy.sh: implement --all-attached happy path

Calls detect-all-pubkeys, parses supported / unsupported lines, and
feeds the supported set through the existing add path. Dedup
against existing recipients and the unsupported-cards dialog are
added in subsequent commits.

:clown: Designed with [Clown](https://github.com/amarbel-llc/clown)."
```

---

### Task 7: Tier-1 bats — already-a-recipient info lines

**Promotion criteria:** N/A.

**Files:**
- Modify: `zz-tests_bats/t0610-recipients-add-attached.bats`
- Modify: `src/piggy.sh` (`_cmd_pass_recipients_add_all_attached`)

**Step 1: Write the failing test**

Append to `zz-tests_bats/t0610-recipients-add-attached.bats`:

```bash
function add_attached_already_present_prints_info_line { # @test
  # Mock emits exactly the recipient the store was init'd with.
  local guid="cafef00d00000000ddee00011223344"
  export PIGGY_TEST_DETECT_ALL_SUPPORTED=$"$RECIPIENT_PRIMARY\t$guid"

  local before_sha
  before_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"

  run "$PIGGY" pass recipients add --all-attached
  assert_success
  assert_output --partial "already a recipient: $RECIPIENT_PRIMARY"
  assert_output --partial "GUID $guid"

  local after_sha
  after_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"
  [[ "$before_sha" = "$after_sha" ]] || fail "expected no new commit when all attached cards are already recipients"
}
```

**Step 2: Run, verify failure**

```
just test-bats-file zz-tests_bats/t0610-recipients-add-attached.bats
```

Expected: this new test fails — either the info line isn't emitted, or a new commit lands.

**Step 3: Add dedup + info-line logic**

In `src/piggy.sh`, replace the "Dedup support and dialog are added in subsequent commits." block of `_cmd_pass_recipients_add_all_attached` with:

```bash
  # Canonicalize current piggy-ids so equality below is byte-equality
  # on the markl-ID column. canonicalize is idempotent.
  "${PIGGY_IDS_PATH:-piggy-ids}" canonicalize "$PIGGY_IDS" || die "Error: existing piggy-ids invalid."

  # Build a set of currently-present markl IDs (column 1, stripped of
  # inline comments).
  declare -A current_set=()
  while IFS= read -r line; do
    case "$line" in
    "#"* | "") continue ;;
    esac
    local id="${line%%  #*}"        # strip "  # comment" if present
    id="${id##[[:space:]]}"
    id="${id%%[[:space:]]}"
    [[ -n $id ]] && current_set["$id"]=1
  done <"$PIGGY_IDS"

  local -a to_add=()
  local -a to_add_guids=()
  local i=0
  while [[ $i -lt ${#supported_ids[@]} ]]; do
    local id="${supported_ids[$i]}"
    local guid="${supported_guids[$i]}"
    if [[ -n ${current_set["$id"]:-} ]]; then
      echo "already a recipient: $id  # GUID $guid"
    else
      to_add+=("$id")
      to_add_guids+=("$guid")
    fi
    i=$((i + 1))
  done

  if [[ ${#to_add[@]} -eq 0 ]]; then
    echo "nothing to add" >&2
    return 0
  fi
```

(Note: we removed the unconditional `to_add=("${supported_ids[@]}")` line and the early `nothing to add` exit — both are subsumed by this block.)

**Step 4: Run the test, verify it passes**

```
just test-bats-file zz-tests_bats/t0610-recipients-add-attached.bats
```

Expected: all three tests pass.

**Step 5: Commit**

```
git add zz-tests_bats/t0610-recipients-add-attached.bats src/piggy.sh
git commit -m "src/piggy.sh: dedup --all-attached against existing piggy-ids

Emits one stdout info line per already-present card:
  already a recipient: <markl-id>  # GUID <guid-hex>

Equality is by markl ID, matching RFC 0003. If every attached card
is already a recipient, exits 0 with no commit \\(noop case\\).

:clown: Designed with [Clown](https://github.com/amarbel-llc/clown)."
```

---

### Task 8: Tier-1 bats — unsupported gate (non-TTY abort)

**Promotion criteria:** N/A.

**Files:**
- Modify: `zz-tests_bats/t0610-recipients-add-attached.bats`
- Modify: `src/piggy.sh` (`_cmd_pass_recipients_add_all_attached`)

**Step 1: Write the failing test**

Append two tests covering the non-TTY paths (TTY-prompt path is exercised manually; bats runs without a TTY by default which is exactly the non-TTY case):

```bash
function add_attached_unsupported_without_yes_aborts { # @test
  export PIGGY_TEST_DETECT_ALL_SUPPORTED=$"$RECIPIENT_SECONDARY\tdeadbeef00000000aabbccddeeff0011"
  export PIGGY_TEST_DETECT_ALL_UNSUPPORTED=$"cafef00d11223344556677889900aabb\tslot 9D is Rsa2048"

  local before_sha
  before_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"

  run "$PIGGY" pass recipients add --all-attached
  assert_failure
  assert_output --partial "Cannot encrypt to 1 attached card"
  assert_output --partial "cafef00d11223344556677889900aabb: slot 9D is Rsa2048"
  assert_output --partial "stdin is not a TTY"

  local after_sha
  after_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"
  [[ "$before_sha" = "$after_sha" ]] || fail "expected no commit when aborted"
}

function add_attached_unsupported_with_yes_adds_supported_only { # @test
  export PIGGY_TEST_DETECT_ALL_SUPPORTED=$"$RECIPIENT_SECONDARY\tdeadbeef00000000aabbccddeeff0011"
  export PIGGY_TEST_DETECT_ALL_UNSUPPORTED=$"cafef00d11223344556677889900aabb\tslot 9D is Rsa2048"

  run "$PIGGY" pass recipients add --all-attached --yes
  assert_success
  assert_output --partial "Cannot encrypt to 1 attached card"
  run cat "$PIGGY_STORE_DIR/piggy-ids"
  assert_output --partial "$RECIPIENT_SECONDARY"
}

function add_attached_only_unsupported_yes_is_nothing_to_add { # @test
  export PIGGY_TEST_DETECT_ALL_UNSUPPORTED=$"cafef00d11223344556677889900aabb\tslot 9D is Rsa2048"

  local before_sha
  before_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"

  run "$PIGGY" pass recipients add --all-attached --yes
  assert_success
  assert_output --partial "nothing to add"

  local after_sha
  after_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"
  [[ "$before_sha" = "$after_sha" ]] || fail "expected no commit when nothing to add"
}

function add_attached_no_cards_errors { # @test
  # Both env vars unset → mock emits empty output.
  unset PIGGY_TEST_DETECT_ALL_SUPPORTED PIGGY_TEST_DETECT_ALL_UNSUPPORTED || true
  run "$PIGGY" pass recipients add --all-attached
  assert_failure
  assert_output --partial "no PIV cards detected"
}
```

**Step 2: Run, verify failure**

```
just test-bats-file zz-tests_bats/t0610-recipients-add-attached.bats
```

Expected: the four new tests fail.

**Step 3: Add the unsupported gate**

In `src/piggy.sh`, insert the gate **after** the parsing block (after `if [[ ${#supported_ids[@]} -eq 0 && ${#unsupported_lines[@]} -eq 0 ]]; then ... fi`) and **before** the dedup block:

```bash
  if [[ ${#unsupported_lines[@]} -gt 0 ]]; then
    {
      echo "Cannot encrypt to ${#unsupported_lines[@]} attached card(s) (slot 9D is not P-256 ECDH):"
      for line in "${unsupported_lines[@]}"; do
        # line is "<guid>  <reason>" (two-space separator from helper)
        local guid="${line%%  *}"
        local reason="${line#*  }"
        echo "  $guid: $reason"
      done
    } >&2

    if [[ $assume_yes -ne 1 ]]; then
      if [[ -t 0 ]]; then
        echo -n "Continue and add the ${#supported_ids[@]} supported card(s)? [y/N] " >&2
        local reply
        IFS= read -r reply || reply=""
        case "$reply" in
        y | Y | yes | Yes | YES) : ;;
        *) die "aborted" ;;
        esac
      else
        die "aborted: unsupported cards detected and stdin is not a TTY; pass --yes to proceed"
      fi
    fi
  fi
```

**Step 4: Run, verify tests pass**

```
just test-bats-file zz-tests_bats/t0610-recipients-add-attached.bats
```

Expected: all 7 tests pass.

**Step 5: Commit**

```
git add zz-tests_bats/t0610-recipients-add-attached.bats src/piggy.sh
git commit -m "src/piggy.sh: unsupported-card gate for recipients add --all-attached

When detect-all-pubkeys reports any unsupported cards, prints a
single multi-line dialog on stderr listing them by GUID and reason,
then either:
- proceeds when --yes was passed,
- prompts and reads y/N from /dev/tty when stdin is a TTY,
- aborts otherwise with a directive to pass --yes.

Also wires no-cards-detected to a hard error.

:clown: Designed with [Clown](https://github.com/amarbel-llc/clown)."
```

---

### Task 9: Tier-1 bats — `-p subfolder` scoping

**Promotion criteria:** N/A.

**Files:**
- Modify: `zz-tests_bats/t0610-recipients-add-attached.bats`

**Step 1: Write the test (no implementation change expected)**

Append:

```bash
function add_attached_respects_p_subfolder { # @test
  # Init a subfolder with its own piggy-ids and assert add --all-attached
  # operates on that subfolder, not the root.
  mkdir -p "$PIGGY_STORE_DIR/sub"
  "$PIGGY" pass init -p sub -k "$RECIPIENT_SECONDARY"

  export PIGGY_TEST_DETECT_ALL_SUPPORTED=$"$RECIPIENT_PRIMARY\tdeadbeef00000000aabbccddeeff0011"
  run "$PIGGY" pass recipients add --all-attached -p sub
  assert_success

  run cat "$PIGGY_STORE_DIR/sub/piggy-ids"
  assert_output --partial "$RECIPIENT_PRIMARY"
  assert_output --partial "$RECIPIENT_SECONDARY"

  # Root piggy-ids unchanged.
  run cat "$PIGGY_STORE_DIR/piggy-ids"
  refute_output --partial "$RECIPIENT_SECONDARY"  # secondary belongs only to sub
}
```

**Step 2: Run, expect pass**

```
just test-bats-file zz-tests_bats/t0610-recipients-add-attached.bats
```

Expected: pass (no implementation change needed — `find_piggy_ids` already walks correctly).

If it fails: investigate. Most likely cause is a subtle bug in arg parsing where `-p sub` is mis-attributed. Fix before committing.

**Step 3: Commit**

```
git add zz-tests_bats/t0610-recipients-add-attached.bats
git commit -m "zz-tests_bats: cover --all-attached respects -p subfolder

Adds the test for completeness; the flag was already wired through
find_piggy_ids via the existing -p path.

:clown: Designed with [Clown](https://github.com/amarbel-llc/clown)."
```

---

### Task 10: Tier-1 bats — empty after dedup (all already recipients)

**Promotion criteria:** N/A.

This case is partially exercised by Task 7. Add an explicit dedicated test for the "two cards, both already recipients" variant to lock the no-commit semantic.

**Files:**
- Modify: `zz-tests_bats/t0610-recipients-add-attached.bats`

**Step 1: Add the test**

```bash
function add_attached_two_cards_both_already_recipients { # @test
  "$PIGGY" pass recipients add "$RECIPIENT_SECONDARY"
  export PIGGY_TEST_DETECT_ALL_SUPPORTED=$"$RECIPIENT_PRIMARY\tdeadbeef00000000aabbccddeeff0011"$'\n'"$RECIPIENT_SECONDARY\tcafef00d11223344556677889900aabb"

  local before_sha
  before_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"

  run "$PIGGY" pass recipients add --all-attached
  assert_success
  assert_output --partial "already a recipient: $RECIPIENT_PRIMARY"
  assert_output --partial "already a recipient: $RECIPIENT_SECONDARY"
  assert_output --partial "nothing to add"

  local after_sha
  after_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"
  [[ "$before_sha" = "$after_sha" ]] || fail "expected no commit when nothing to add"
}
```

**Step 2: Run, expect pass**

```
just test-bats-file zz-tests_bats/t0610-recipients-add-attached.bats
```

Expected: pass.

**Step 3: Commit**

```
git add zz-tests_bats/t0610-recipients-add-attached.bats
git commit -m "zz-tests_bats: cover --all-attached with multiple already-present cards

Locks the noop semantic: when every attached card is already a
recipient, the command exits 0 with the info lines but no commit.

:clown: Designed with [Clown](https://github.com/amarbel-llc/clown)."
```

---

## Phase D — Tier-2 conformance bats (fib-driven)

### Task 11: Tier-2 fib bats — happy path + already-a-recipient + RSA-in-9D

**Promotion criteria:** N/A.

**Files:**
- Create: `zz-tests_bats/conformance/piggy_recipients_add_attached.bats`
- Modify: `justfile` (add the new recipe at Task 12)

**Step 1: Write the bats file**

Create `zz-tests_bats/conformance/piggy_recipients_add_attached.bats`:

```bash
# Conformance tests: piggy pass recipients add --all-attached on a real
# fib (virtual PIV) card. Requires fib up; lifecycle is managed by the
# matching just recipe (test-bats-conformance-recipients-add-attached).
#
# Multi-card scenarios (mixed supported+unsupported, dedup across N
# cards) are NOT covered here — fib is single-card by construction.
# See amarbel-llc/piggy#83. Those cases live in the tier-1 mock bats
# at zz-tests_bats/t0610-recipients-add-attached.bats.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/../common.bash"
  # Test askpass safety net (per CLAUDE.md):
  askpass="$REPO_ROOT/zz-tests_bats/helpers/piggy-test-askpass.sh"
  export SSH_ASKPASS="$askpass" \
         SSH_ASKPASS_REQUIRE=force \
         DISPLAY="" \
         PIGGY_TEST_FIB_PIN=123456

  # Drop the mock-piggy-ids PATH shim from common.bash so the real
  # binary handles detect-all-pubkeys against the fib card. (The
  # mock would emit canned output instead of probing the card.)
  rm -f "$BATS_TEST_TMPDIR/piggy-ids"
  # Mock-pivy-box stays in place because piggy-ids encrypt under real
  # crypto requires hardware; we only care about the recipient-list
  # mutation here, not the .ebox bytes.
  unset PIGGY_IDS_REAL || true
  unset PIGGY_IDS_PATH || true
  export PATH="$REPO_ROOT/target/debug:$PATH"   # real piggy-ids

  init_test_git

  # Detect the card's actual markl ID once; pin it for later asserts.
  CARD_ID="$(piggy-ids detect-pubkey)"
  [[ -n $CARD_ID ]] || skip "no PIV card available (fib not up?)"
  export CARD_ID
}

function fib_attached_adds_the_card { # @test
  # Init the store with a *different* recipient (the canonical RFC
  # 0002 vector) so the live card's recipient is genuinely new.
  local foreign="piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu"
  "$PIGGY" pass init -k "$foreign"

  run "$PIGGY" pass recipients add --all-attached
  assert_success
  run cat "$PIGGY_STORE_DIR/piggy-ids"
  assert_output --partial "$CARD_ID"
  assert_output --partial "$foreign"
}

function fib_attached_already_a_recipient_is_noop { # @test
  "$PIGGY" pass init -k "$CARD_ID"
  local before_sha
  before_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"
  run "$PIGGY" pass recipients add --all-attached
  assert_success
  assert_output --partial "already a recipient: $CARD_ID"
  local after_sha
  after_sha="$(git -C "$PIGGY_STORE_DIR" rev-parse HEAD)"
  [[ "$before_sha" = "$after_sha" ]] || fail "expected no commit"
}

function fib_attached_rsa_in_9d_is_unsupported { # @test
  # Re-key slot 9D as RSA. The card is then unsupported for piggy.
  pivy-tool -P "$PIGGY_TEST_FIB_PIN" -K default -a rsa2048 generate 9d >/dev/null

  local foreign="piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu"
  "$PIGGY" pass init -k "$foreign"

  run "$PIGGY" pass recipients add --all-attached --yes
  assert_success
  assert_output --partial "Cannot encrypt to 1 attached card"
  assert_output --partial "Rsa"  # algorithm enum prints as Rsa2048 or similar
  assert_output --partial "nothing to add"
}
```

Note: the `setup()` removes the mock symlink for this conformance lane — we want real `piggy-ids` against real PCSC. The base `common.bash` installs the mock by default; we undo that here.

**Step 2: Smoke (with fib up, manually)**

```
just fib-up
eval "$(cat .fib/env)"
pivy-tool -P 123456 -K default -a eccp256 generate 9d >/dev/null
cargo build
bats --allow-unix-sockets --allow-local-binding --tap \
  zz-tests_bats/conformance/piggy_recipients_add_attached.bats
just fib-down
```

Expected: 3 tests pass. If any fail, debug before continuing — these are the load-bearing end-to-end checks.

**Step 3: Commit**

```
git add zz-tests_bats/conformance/piggy_recipients_add_attached.bats
git commit -m "zz-tests_bats/conformance: fib-driven --all-attached coverage

Three real-PCSC tests against the fib virtual card:
- happy path: foreign-recipient init → add --all-attached → card landed
- already-a-recipient: init with card → add is noop
- RSA-in-9D: unsupported dialog + nothing-to-add

Multi-card permutations are covered by the tier-1 mock bats; see
amarbel-llc/piggy#83 for the fib upgrade that would let us cover
them end-to-end.

:clown: Designed with [Clown](https://github.com/amarbel-llc/clown)."
```

---

### Task 12: Justfile recipe for the conformance lane

**Promotion criteria:** N/A.

**Files:**
- Modify: `justfile`

**Step 1: Add the recipe**

In `justfile`, after `test-bats-conformance-interop`, add:

```just
# Bring up fib, generate a P-256 key in 9D, and run the
# piggy_recipients_add_attached.bats conformance lane against the
# real PCSC stack. Linux-only (fib is Linux-only). Opt-in — not
# part of the default `just test` lane.
[group('test')]
test-bats-conformance-recipients-add-attached: build-rust
    #!/usr/bin/env bash
    set -euo pipefail
    trap 'just fib-down' EXIT
    just fib-up
    eval "$(cat .fib/env)"
    pivy-tool -P 123456 -K default -a eccp256 generate 9d >/dev/null
    askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
    SSH_ASKPASS="$askpass" \
      SSH_ASKPASS_REQUIRE=force \
      DISPLAY="" \
      PIGGY_TEST_FIB_PIN=123456 \
      BATS_TEST_TIMEOUT=30 bats --allow-unix-sockets --allow-local-binding --tap \
      zz-tests_bats/conformance/piggy_recipients_add_attached.bats
```

**Step 2: Smoke-test the recipe**

```
just test-bats-conformance-recipients-add-attached
```

Expected: 3 tests pass, fib torn down cleanly via the trap.

**Step 3: Commit**

```
git add justfile
git commit -m "justfile: opt-in test-bats-conformance-recipients-add-attached recipe

Manages fib lifecycle, generates a P-256 9D key, and runs the new
conformance bats with --allow-unix-sockets --allow-local-binding +
the test askpass safety net (per CLAUDE.md). Linux-only because
fib is Linux-only. Not on the default \`just test\` lane.

:clown: Designed with [Clown](https://github.com/amarbel-llc/clown)."
```

---

## Phase E — Docs and roadmap

### Task 13: Update `doc/piggy.1.scd` and rebuild manpage

**Promotion criteria:** N/A.

**Files:**
- Modify: `doc/piggy.1.scd` (the `recipients` subcommand description)

**Step 1: Find the existing `recipients add` description**

```
just test-bats-file /dev/null  # noop; just to keep your shell context
rg -n "recipients" doc/piggy.1.scd
```

Expected: locates the `recipients` section under `## SUBCOMMANDS` or similar.

**Step 2: Update the manpage text**

In `doc/piggy.1.scd`, find the `recipients` add description and replace with:

```
*recipients add* [-A | --all-attached] [--yes] [-p _subfolder_] [_markl-id_...]
	Append recipients to the store's *piggy-ids* and re-encrypt.

	With one or more _markl-id_ arguments, append each as a literal
	recipient.

	With *-A* / *--all-attached*, enumerate every attached PIV card
	and add the supported ones (slot 9D, P-256 ECDH). Cards already
	present are reported on stdout as
	"_already a recipient: <markl-id>  # GUID <guid>_" and skipped.
	Cards with an unsupported algorithm in slot 9D are listed in a
	single stderr dialog; the command then prompts on /dev/tty
	or, when stdin is not a TTY, aborts unless *--yes* was passed.

	*--all-attached* and explicit _markl-id_ arguments are mutually
	exclusive.
```

**Step 3: Rebuild and inspect**

```
just build-nix
```

Expected: manpage compiles. Visually inspect with `man -l` against the produced `man1/piggy.1.gz` if you want a render check.

**Step 4: Commit**

```
git add doc/piggy.1.scd
git commit -m "doc/piggy.1.scd: document recipients add --all-attached / --yes

:clown: Designed with [Clown](https://github.com/amarbel-llc/clown)."
```

---

### Task 14: Update roadmap tracker #26

**Promotion criteria:** N/A.

**Files:**
- N/A (GitHub comment + edit on issue body)

**Step 1: Read the current state of #26**

```
mcp__plugin_moxy_moxy__get-hubbed_issue-get number=26
```

Look for the "Recommended next" pointer and the recipients track.

**Step 2: Post a comment on #26 announcing the work**

Use `mcp__plugin_moxy_moxy__get-hubbed_issue-comment` (or the existing pattern in `/eng:file-issue`) with body:

```markdown
Landed `piggy pass recipients add --all-attached` — design at
`docs/plans/2026-05-12-recipients-add-attached-design.md`,
implementation tracked in this PR ([PR-LINK]). Follow-up
amarbel-llc/piggy#83 for multi-card fib coverage.

:clown: Filed by [Clown](https://github.com/amarbel-llc/clown).
```

Don't edit the #26 body inline — the user maintains the triage list manually and prefers comments per the CLAUDE.md guidance.

**Step 3: No commit** (this is a GitHub action, not a code change).

---

### Task 15: Open the PR via spinclass `merge-this-session`

**Promotion criteria:** N/A.

**Step 1: Verify a clean tree**

```
mcp__plugin_moxy_moxy__grit_status
```

Expected: clean — every change committed in tasks 1–14.

**Step 2: Run the full test lane**

```
just test
```

Expected: green. (The new tier-2 conformance lane is opt-in and won't run here; it was smoke-tested at Task 12.)

**Step 3: Run linters**

```
just lint-rust
just codemod-fmt
mcp__plugin_moxy_moxy__grit_status
```

Expected: clean. If `codemod-fmt` produced changes, commit them as a single follow-up: `chore: codemod-fmt sweep`.

**Step 4: Merge the session**

Call `mcp__spinclass__merge-this-session` with `git_sync: true`. This runs the pre-merge hook (`just build-nix`), merges into the default branch, and (with `git_sync`) pushes.

A non-error return is success. Per CLAUDE.md, do **not** create a new worktree — stay on the existing spinclass branch for any follow-up work.

---

## Verification checklist (post-merge)

- [ ] `piggy pass recipients add --help` mentions `--all-attached`.
- [ ] `piggy pass recipients add --all-attached --yes` on a real card adds it.
- [ ] Running the same command twice shows the "already a recipient" line on the second run.
- [ ] `piggy pass recipients add --all-attached` on a card with an unsupported 9D algorithm shows the dialog and aborts (or proceeds with `--yes`).
- [ ] `just test-bats-conformance-recipients-add-attached` passes locally.
- [ ] doc/piggy.1.scd renders correctly under `man piggy`.

Real-hardware verification (user post-merge): bring up a real YubiKey on the workstation and run through the verification list above.
