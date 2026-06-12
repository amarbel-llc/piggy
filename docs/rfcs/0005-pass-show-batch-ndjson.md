---
status: accepted
date: 2026-05-26
accepted: 2026-05-27
provenance: |
  Drafted alongside amarbel-llc/eng FDR-0004 (rcm piggy ebox decryption
  hook). The hook needs a single-PIN-per-batch decrypt primitive that
  emits per-ebox progress so the caller (rcm's `2-piggy.bash`, but also
  hand-driven users) can bridge each event into TAP, structured logs, or
  a UI. The wire format here is the contract that bridging tooling pins
  against; the subcommand's flags and behaviour are implementation and
  live in piggy's man page.
---

# `pass show-batch` NDJSON Event Stream (piggy normative)

## Abstract

This RFC specifies a newline-delimited JSON (NDJSON) wire format for the
event stream emitted by `piggy pass show-batch --format ndjson`. The
subcommand decrypts one or more eboxes inside a single PIV-card session
(single PIN prompt) and emits one JSON record per terminator and per
ebox attempt on stdout, in source order. Consumers stream-read the
records and act per event without re-invoking piggy.

This format is **not** TAP. It is modelled on the typed-record pattern
of amarbel-llc/tap RFC 0001 (NDJSON encoding of TAP) but uses
piggy-native vocabulary (`plan`, `decrypt`, `summary`) because
decryption events are not test points. Mapping piggy events to TAP test
points is a consumer concern — see §Bridging to TAP below.

## Status and Provenance

This document is the normative spec for the `--format ndjson` event
stream produced by `piggy pass show-batch`. It applies from piggy 2.x
onward; earlier piggy releases do not implement `pass show-batch`.

The subcommand's CLI surface (positional arguments, `--out-dir`,
`--all-or-nothing`, exit-code semantics, `human` format) is documented
in `piggy(1)` under `pass show-batch`. Only the NDJSON wire format is
normatively pinned here.

The amarbel-llc/eng `rcm/hooks/post-up/2-piggy.bash` is the first
production consumer; see eng FDR-0004 for the bridging design.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## Specification

### Document Format

A conforming producer of `--format ndjson` MUST emit a stream of one
or more JSON records, each on its own line terminated by LF (U+000A).
Each record MUST be a JSON object per RFC 8259. The stream MUST NOT
contain blank lines, comments, JSON-text-prefix BOMs, or any non-JSON
content interleaved with the records.

Consumers MUST treat the stream as forward-only: a record's meaning is
fully determined by the record itself and the records before it; later
records MUST NOT retroactively change the meaning of earlier records.

### Record Type Discrimination

Every record MUST carry a `"type"` field whose value is one of the
type strings defined below. Consumers MUST discriminate solely on
`"type"`; producers MUST emit `"type"` as the first field of each
record for human readability (see §Field Ordering).

The defined types are:

- `plan`
- `decrypt`
- `summary`
- `bail-out`

Producers MUST NOT emit records with an unrecognised `"type"` value.
Consumers MUST ignore records whose `"type"` value they do not
recognise (forward-compatible expansion).

### `plan` Record

Emitted exactly once, as the **first** record of the stream. It
declares how many `decrypt` records the producer intends to emit.

  Field         Type      Required    Description
  ------------  --------  ----------  -----------------------------------------------------------------------
  `type`        string    MUST        Constant `"plan"`.
  `count`       integer   MUST        Number of `decrypt` records that follow in this stream. MUST equal the
                                      number of pass-names supplied to `show-batch` (after `--names-from`
                                      expansion). MUST be >= 0; 0 is valid and represents an empty batch.

A producer that intends to emit zero `decrypt` records (empty batch)
MUST still emit a `plan` record with `count: 0`.

#### Example

```json
{"type":"plan","count":3}
```

### `decrypt` Record

Emitted exactly once per ebox attempted, in source order matching the
order of pass-names supplied to `show-batch`.

  Field           Type            Required          Description
  --------------  --------------  ----------------  ---------------------------------------------------------
  `type`          string          MUST              Constant `"decrypt"`.
  `n`             integer         MUST              1-indexed position of this attempt within the batch.
                                                    MUST be strictly increasing across the `decrypt` records
                                                    of a stream and MUST be in `[1, plan.count]`.
  `name`          string          MUST              Pass-name as supplied to `show-batch` (canonicalised:
                                                    leading `/` stripped, `.ebox` suffix stripped). MUST be
                                                    valid UTF-8.
  `ok`            boolean         MUST              `true` if decryption succeeded AND the plaintext was
                                                    written to the output path. `false` otherwise.
  `out_path`      string \| null  MUST              Absolute path to the written plaintext file when `ok` is
                                                    `true`. `null` when `ok` is `false`. When non-null,
                                                    consumers MAY rely on the file existing with mode 0600
                                                    at this path; producers MUST chmod 0600 before this
                                                    record is emitted.
  `diagnostic`    object \| null  MUST              `null` when `ok` is `true`. Otherwise an object describing
                                                    the failure (see §Diagnostic Object).
  `skipped`       boolean         OPTIONAL          `true` when the producer rendered no new plaintext because an
                                                    up-to-date file already existed at `out_path` (a freshness
                                                    skip, e.g. piggy's `--update` flag: the plaintext's mtime is
                                                    at least as new as the ebox's). When present and `true`, `ok`
                                                    MUST be `true` and `out_path` MUST reference the existing
                                                    plaintext. Producers MUST omit the field (rather than emit
                                                    `false`) for entries that were actually decrypted; consumers
                                                    MUST treat absence as `false`.

Producers MUST emit the `decrypt` record for ebox N before beginning
work on ebox N+1. This sequencing guarantee allows consumers to
overlap downstream work (`mv` into final position, TAP emission)
with piggy's next decrypt.

#### Example (success)

```json
{"type":"decrypt","n":1,"name":"config/ssh/rcm/config-user-secret","ok":true,"out_path":"/tmp/show-batch-XYZ/config/ssh/rcm/config-user-secret","diagnostic":null}
```

#### Example (failure)

```json
{"type":"decrypt","n":2,"name":"missing/secret","ok":false,"out_path":null,"diagnostic":{"kind":"not-found","message":"no ebox at $PIGGY_STORE_DIR/missing/secret.ebox"}}
```

#### Example (freshness skip)

```json
{"type":"decrypt","n":3,"name":"config/ssh/rcm/config-user-secret","ok":true,"out_path":"/tmp/show-batch-XYZ/config/ssh/rcm/config-user-secret","diagnostic":null,"skipped":true}
```

### `summary` Record

Emitted exactly once, as the **last** record of the stream, after
all `decrypt` records.

  Field          Type      Required    Description
  -------------  --------  ----------  -------------------------------------------------------------------
  `type`         string    MUST        Constant `"summary"`.
  `ok`           integer   MUST        Count of `decrypt` records in this stream with `ok: true`.
  `failed`       integer   MUST        Count of `decrypt` records in this stream with `ok: false`.

The invariant `ok + failed == plan.count` MUST hold. Consumers MAY
verify it as a sanity check; producers MUST NOT emit a `summary` whose
counts violate it.

#### Example

```json
{"type":"summary","ok":2,"failed":1}
```

### `bail-out` Record

Emitted at most once, as the **last** record of the stream, in place
of `summary`, when the producer terminates mid-batch without completing
the planned decrypts (e.g. user interrupt, fatal card error, internal
panic). A stream that emits `bail-out` MUST NOT also emit `summary`,
and vice versa.

  Field       Type      Required    Description
  ----------  --------  ----------  -------------------------------------------------------------------
  `type`      string    MUST        Constant `"bail-out"`.
  `reason`    string    MUST        Human-readable, single-line description of why the batch was
                                    aborted. MUST be valid UTF-8. SHOULD be terse enough to surface
                                    in a TAP `Bail out!` directive.

The subcommand's exit code also signals the bail-out (non-zero); the
record exists so consumers reading the NDJSON stream alone can
distinguish a deliberate bail-out from a stream that was truncated by
an external pipe failure.

#### Example

```json
{"type":"bail-out","reason":"SIGINT received after decrypt n=3 of 5"}
```

### Diagnostic Object

The `diagnostic` field of a failing `decrypt` record is an object with:

  Field         Type      Required    Description
  ------------  --------  ----------  ----------------------------------------------------------------------
  `kind`        string    MUST        Short machine-readable failure category. Defined values: `not-found`
                                      (no ebox at the expected store path), `pin-cancelled` (user dismissed
                                      the PIN prompt or the askpass returned non-zero), `pin-incorrect`
                                      (card rejected the PIN), `card-locked` (card refused with retries
                                      exhausted), `card-absent` (no PIV card available), `decrypt-failed`
                                      (cryptographic failure unwrapping the ebox, OR the selected card/slot
                                      is not a recipient of this ebox — see §Single-card Operation),
                                      `io-error` (write to `out_path` failed), `internal` (any other error).
                                      Producers MUST emit one of these values; consumers MUST treat any
                                      unrecognised value as `internal`.
  `message`     string    MUST        Human-readable error message. MUST be valid UTF-8. SHOULD be a single
                                      line; MAY contain LF if multi-line context is essential.
  `retryable`   boolean   OPTIONAL    `true` if a fresh `show-batch` invocation against the same pass-name
                                      MAY succeed (e.g. `card-locked` after card unlock; `pin-cancelled`).
                                      `false` or absent for terminal failures (`not-found`, `decrypt-
                                      failed`, `io-error`, `internal`).

### Ordering and Completeness

A conforming stream MUST take exactly one of these shapes:

1. **Empty-batch shape**: `plan` (`count: 0`), then `summary`
   (`ok: 0, failed: 0`). No `decrypt` records, no `bail-out`.
2. **Non-empty shape**: `plan` (`count: N` where N >= 1), then N
   `decrypt` records in source order, then `summary`. No `bail-out`.
3. **Bail-out shape**: `plan`, then 0..N-1 `decrypt` records, then
   a `bail-out` record in place of `summary`. The producer was
   unable to complete the batch (e.g. user interrupt, fatal card
   error, internal panic). The subcommand's exit code also carries
   the terminal-failure signal; the `bail-out` record is the in-band
   indicator. Consumers MUST detect this case and MUST NOT assume
   any record that was not emitted.

A stream truncated by an external failure (broken pipe, killed
process) is **not** a bail-out shape — it lacks both `summary` and
`bail-out`. Consumers MUST detect "neither terminator emitted" as a
distinct, malformed condition, treat the batch as failed in its
entirety, and SHOULD log that the stream was truncated rather than
deliberately aborted.

Other streams that do not match one of these shapes (e.g. multiple
`plan` records, `decrypt` records before `plan`, or post-terminator
records) are malformed; consumers SHOULD log the malformation and
treat the batch as failed in its entirety.

### Field Ordering

For human-readability, producers SHOULD emit fields in the order
listed in each record's table above. Consumers MUST NOT depend on
field order — JSON object semantics per RFC 8259 — but MAY warn on
disorder when human-grepping is a primary use case.

### Encoding

All strings MUST be valid UTF-8 per RFC 3629. Producers MUST escape
non-printable octets in JSON strings per RFC 8259. Pass-names
containing characters that require JSON escaping MUST be escaped and
MUST round-trip back to the original byte sequence on consumer
unescape.

### Stable Identifiers

The `name` field of a `decrypt` record is the stable identifier for
correlating an attempt back to the input. Consumers MUST NOT rely on
`n` for cross-stream correlation (a future invocation against a
different argument list will renumber). Consumers MAY use `n` for
intra-stream ordering only.

### Streaming Guarantee

Producers MUST flush stdout after every emitted record (no buffering
beyond one line). This guarantee enables stream-readers to react to
each event with bounded latency rather than waiting for the
subcommand to exit.

### Single-card Operation

A `show-batch` invocation operates against exactly one (card, slot)
pair, selected at pre-flight before the PIN prompt:

1. Producers MUST enumerate attached PIV cards via PC/SC.
2. Producers MUST select the first attached card that holds a slot
   capable of decrypting the first ebox in the batch. The slot used
   for that decryption MUST then be reused for every subsequent ebox
   in the batch.
3. If no attached card has a usable slot for the first ebox, producers
   MUST emit `bail-out` with a `reason` identifying the missing card or
   slot. They MUST NOT prompt for a PIN.
4. If no PIV cards are attached at all, producers MUST emit `bail-out`
   with a `reason` such as `"no PIV cards attached"`. They MUST NOT
   prompt for a PIN.
5. For each subsequent ebox in the batch, producers MUST attempt
   decryption against the selected (card, slot). If the ebox is not
   encrypted to a recipient present on that (card, slot), producers
   MUST emit a `decrypt` record with `ok: false` and
   `diagnostic.kind: "decrypt-failed"`, whose `diagnostic.message`
   SHOULD distinguish "wrong recipient for selected card/slot" from a
   cryptographic failure.

This rule preserves the single-PIN-prompt-per-batch guarantee against
the realistic deployment where multiple PIV cards may be attached but
the user only intends one of them to satisfy this batch. Consumers
that need to drive multiple cards SHOULD re-invoke `show-batch` per
card; this RFC does not define a multi-card batch shape.

## Bridging to TAP

The amarbel-llc/eng `rcm/hooks/post-up/2-piggy.bash` consumer
translates this stream into TAP via amarbel-llc/tap's tap-dancer-bash
library. The mapping is:

| Piggy event              | TAP emission                                                 |
|--------------------------|--------------------------------------------------------------|
| `plan {count: N}`        | `tap_plan N`                                                 |
| `decrypt {ok: true}`     | `tap_ok "<description>"` after `mv` of `out_path`            |
| `decrypt {ok: false}`    | `tap_not_ok "<description>"` with `diagnostic.message`       |
| `summary`                | (ignored — TAP's plan + per-test directives already encode)  |
| `bail-out {reason}`      | `tap_bail_out "<reason>"`                                    |
| Stream truncated (no terminator) | `tap_bail_out "show-batch stream truncated"`         |

The `<description>` is consumer-chosen (typically `"render
<rel-path>"`). The TAP test point numbering follows the `n` from the
piggy stream when used 1-to-1, but consumers MAY renumber if their
TAP plan covers more than just the show-batch output.

## Security Considerations

1. **Plaintext on disk.** A successful `decrypt` record means
   plaintext was written to `out_path` with mode 0600. The consumer
   is responsible for moving that plaintext to its final location and
   for ensuring no third party reads it in the interim. Producers
   SHOULD write to a caller-supplied `--out-dir` so the caller can
   guarantee directory permissions; producers MUST chmod 0600 before
   emitting the `decrypt` record so consumers do not race with a
   wider mode.

2. **Pass-names in events may be sensitive.** Pass-names ("foo/auth-
   token") leak the store's structure even without exposing
   plaintext. Consumers piping the NDJSON to logs MUST consider
   whether the log destination is appropriate for that level of
   detail; producers MUST NOT redact the `name` field — that is the
   consumer's policy choice.

3. **Diagnostics may carry sensitive context.** A `diagnostic.message`
   for an `io-error` may include filesystem paths or system errno
   text. Producers SHOULD avoid embedding plaintext bytes in
   diagnostic messages, but MAY include any non-secret metadata
   useful for debugging.

4. **Single-PIN-prompt is the design intent.** Consumers MUST NOT
   issue multiple overlapping `show-batch` invocations against the
   same card to compose batches — each invocation prompts for PIN
   afresh. The single-PIN promise of this RFC is per-invocation, not
   per-process-tree.

5. **Stream is forward-only.** A producer that reaches a card-level
   failure mid-batch (e.g. `card-locked` on attempt 3 of 5) emits
   `decrypt` records 3, 4, 5 as failures and then `summary` — it
   does NOT re-prompt or retry. Consumers wanting retry semantics
   re-invoke `show-batch` against the failed names.

## Conformance Testing

The piggy reference implementation ships bats conformance tests as
`zz-tests_bats/conformance/piggy_pass_show_batch.bats` (matching the
existing `piggy_<topic>.bats` naming pattern of `piggy_box_interop.bats`,
`piggy_recipients_add_attached.bats`, etc.). They cover:

- Empty-batch shape (plan + summary, no decrypts).
- Non-empty shape (plan + N decrypts + summary), with N in {1, 2, 5}.
- Bail-out shape (SIGINT mid-batch; no summary; non-zero exit).
- Bail-out shape on pre-flight failure (no card attached; no card has
  a usable slot for the first ebox). MUST NOT prompt for a PIN.
- `decrypt` failure paths for every defined `kind` value, asserting
  the field invariants above. Includes the "wrong recipient for
  selected card/slot" path under `decrypt-failed`.
- Field-ordering hint (producer emits `type` first).
- `n` strictly increasing within a stream and bounded by `plan.count`.
- `summary.ok + summary.failed == plan.count` invariant.
- Stdout flush per record (a consumer reading line-by-line observes
  events with bounded latency, not buffered to exit).

A conformance harness for third-party consumers (or the
`2-piggy.bash` bridge) re-runs the same fixtures and asserts the
consumer's downstream output matches its own contract (e.g. the TAP
stream this consumer emits).

## Compatibility

This is a new wire format. piggy 2.x with `pass show-batch` is the
first producer; no prior format exists to be compatible with.

Future revisions of this RFC MAY add new `type` values and new
optional fields. Consumers MUST already ignore unrecognised types and
ignore unrecognised fields per RFC 8259's object semantics, so
forward-compatible expansion is safe by default. A change that adds
a REQUIRED field to an existing record type is a breaking change and
MUST bump this RFC to a new number.

## Implementation

The piggy reference implementation is a Rust handler at
`crates/piggy/src/show_batch.rs`, sibling to the existing pass-* handlers
(`find.rs`, `grep.rs`, `git.rs`, `rm.rs`, `verify.rs`, `recipients.rs`,
`reencrypt.rs`). Tracked at amarbel-llc/piggy#121. The NDJSON encoder is
a thin wrapper around `serde_json::to_string` with the field-ordering
hint encoded via `#[serde]` attribute ordering and a post-serialize
newline append.

The `2-piggy.bash` consumer in amarbel-llc/eng reads the stream via
a `while IFS= read -r line` loop with `jq` for field extraction,
bridged to TAP via amarbel-llc/tap's tap-dancer-bash library.

## References

### Normative

- RFC 2119 — Key words for use in RFCs to Indicate Requirement Levels
- RFC 7464 — JavaScript Object Notation (JSON) Text Sequences (the
  formal NDJSON ancestor; this RFC follows the same record-per-line
  shape but does NOT use the RS sentinel)
- RFC 8259 — The JavaScript Object Notation (JSON) Data Interchange
  Format
- RFC 3629 — UTF-8, a transformation format of ISO 10646

### Informative

- amarbel-llc/tap RFC 0001 — TAP Test-Result NDJSON Schema (the
  pattern this RFC borrows; not literally reused because piggy
  events ≠ test points)
- amarbel-llc/eng FDR-0004 — RCM Piggy Ebox Decryption Hook (the
  first consumer's design)
- amarbel-llc/piggy#119 — vendored-pivy `ecdh@joyent.com` extension
  name-echo bug. Independent of this RFC; informative because it
  motivates the single-PIV-session design over relying on the
  agent's PIN cache.
