#! /usr/bin/env bats
#
# Conformance tests for `piggy pass show-batch` — RFC 0005's NDJSON
# event stream, usage validation, and the non-card error surface.
#
# Card-required cases (single-ebox happy path, N>1 single-PIN, wrong-
# card, SIGINT mid-batch) need a real PIV stack and live in the
# `# bats file_tags=hardware` companion file (TODO; piggy#121 task #5
# covers the sandboxable surface — the hardware surface lands when
# the fib-driven `test-bats-conformance-show-batch` recipe does).
#
# Uses `run -N` to assert specific exit codes; that syntax requires
# bats 1.5.0+.
bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output
  # show-batch's atomic-write step is mode 0o600; tests look at the
  # presence/absence of out_dir contents, so we hand it a fresh dir
  # per test.
  OUT_DIR="$BATS_TEST_TMPDIR/show-batch-out"
  # Safety net for PIN prompts — show-batch's setup steps run before
  # any decrypt and should never reach askpass for the cases this
  # file covers, but the global policy (CLAUDE.md "Test harness
  # safety net for PIN prompts" / piggy#35) applies here too.
  export SSH_ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
}

# --- usage validation (exit code 2) ---

function show_batch_no_names_exits_2 { # @test
  run -2 "$PIGGY" pass show-batch
  assert_output --partial "no pass-names supplied"
}

function show_batch_empty_positional_name_exits_2 { # @test
  # An empty string in argv (e.g. shell expansion of an unset var)
  # must be rejected before any decrypt attempt.
  run -2 "$PIGGY" pass show-batch ""
  assert_output --partial "empty pass-name"
}

function show_batch_missing_names_from_file_exits_2 { # @test
  run -2 "$PIGGY" pass show-batch --names-from /nonexistent/path
  assert_output --partial "--names-from"
}

function show_batch_empty_names_from_file_exits_2 { # @test
  # Empty file → zero parsed names; if no positional names either,
  # this is a usage error.
  local nf="$BATS_TEST_TMPDIR/empty.txt"
  : >"$nf"
  run -2 "$PIGGY" pass show-batch --names-from "$nf"
  assert_output --partial "no pass-names"
}

function show_batch_names_from_only_comments_exits_2 { # @test
  # Per RFC 0005-companion convention, `#` lines and blanks don't
  # contribute names. A file with only those is equivalent to empty.
  local nf="$BATS_TEST_TMPDIR/only-comments.txt"
  cat >"$nf" <<'EOF'
# header
   # indented comment
   
EOF
  run -2 "$PIGGY" pass show-batch --names-from "$nf"
  assert_output --partial "no pass-names"
}

# --- non-card error surface (NDJSON) ---

function show_batch_missing_ebox_emits_not_found { # @test
  # No ebox at $PIGGY_STORE_DIR/missing.ebox → `decrypt-failed` with
  # `kind: not-found`. Card enumeration never runs because every
  # preflight fails; the run short-circuits with summary {ok:0, failed:1}.
  mkdir -p "$PIGGY_STORE_DIR"
  run "$PIGGY" pass show-batch --format ndjson --out-dir "$OUT_DIR" missing
  assert_failure
  # First record MUST be `plan` with count=1.
  assert_line --index 0 --partial '"type":"plan"'
  assert_line --index 0 --partial '"count":1'
  # Then `decrypt` with the not-found diagnostic.
  assert_line --index 1 --partial '"type":"decrypt"'
  assert_line --index 1 --partial '"ok":false'
  assert_line --index 1 --partial '"kind":"not-found"'
  # And a summary closing the stream.
  assert_output --partial '"type":"summary"'
  assert_output --partial '"ok":0'
  assert_output --partial '"failed":1'
}

function show_batch_malformed_ebox_emits_decrypt_failed { # @test
  # A non-empty file that isn't a valid EboxStream → EboxStream::
  # from_bytes errors → preflight Failed with kind `decrypt-failed`.
  mkdir -p "$PIGGY_STORE_DIR"
  printf 'not an ebox at all' >"$PIGGY_STORE_DIR/bogus.ebox"
  run "$PIGGY" pass show-batch --format ndjson --out-dir "$OUT_DIR" bogus
  assert_failure
  assert_line --index 0 --partial '"type":"plan"'
  assert_line --index 1 --partial '"type":"decrypt"'
  assert_line --index 1 --partial '"ok":false'
  assert_line --index 1 --partial '"kind":"decrypt-failed"'
}

function show_batch_canonical_name_strips_prefix_and_suffix { # @test
  # Per RFC 0005 §Decrypt Record, `name` is canonicalised: leading
  # `/` stripped, trailing `.ebox` stripped. Verified on a missing
  # ebox so we don't have to fixture a real wire format.
  mkdir -p "$PIGGY_STORE_DIR"
  run "$PIGGY" pass show-batch --format ndjson --out-dir "$OUT_DIR" /missing.ebox
  assert_failure
  assert_output --partial '"name":"missing"'
}

function show_batch_plan_count_matches_args { # @test
  # plan.count MUST equal the total pass-names supplied, regardless
  # of how many preflight successfully. Three missing eboxes → plan
  # count 3, three decrypt records, summary {ok:0, failed:3}.
  mkdir -p "$PIGGY_STORE_DIR"
  run "$PIGGY" pass show-batch --format ndjson --out-dir "$OUT_DIR" a b c
  assert_failure
  assert_line --index 0 --partial '"count":3'
  # Three `decrypt` records, in source order.
  assert_line --index 1 --partial '"n":1'
  assert_line --index 1 --partial '"name":"a"'
  assert_line --index 2 --partial '"n":2'
  assert_line --index 2 --partial '"name":"b"'
  assert_line --index 3 --partial '"n":3'
  assert_line --index 3 --partial '"name":"c"'
  assert_output --partial '"ok":0,"failed":3'
}

function show_batch_names_from_appended_to_positional { # @test
  # Positional names come first, --names-from contents appended.
  mkdir -p "$PIGGY_STORE_DIR"
  local nf="$BATS_TEST_TMPDIR/names.txt"
  cat >"$nf" <<'EOF'
# leading comment
file-from-list
EOF
  run "$PIGGY" pass show-batch --format ndjson --out-dir "$OUT_DIR" \
    positional-first --names-from "$nf"
  assert_failure
  assert_line --index 0 --partial '"count":2'
  assert_line --index 1 --partial '"name":"positional-first"'
  assert_line --index 2 --partial '"name":"file-from-list"'
}

# --- --update freshness skip ---

function show_batch_update_skips_fresh_plaintext { # @test
  # With --update, an entry whose plaintext at <out-dir>/<name> is at
  # least as new as the ebox is skipped: no decrypt, no card session,
  # no PIN prompt, exit 0. The fixture ebox is deliberately NOT valid
  # wire format — a skip must not even parse it.
  mkdir -p "$PIGGY_STORE_DIR" "$OUT_DIR"
  printf 'bogus ebox' >"$PIGGY_STORE_DIR/fresh.ebox"
  printf 'rendered plaintext' >"$OUT_DIR/fresh"
  # Ebox strictly older than the plaintext.
  touch -t 200101010000 "$PIGGY_STORE_DIR/fresh.ebox"
  run -0 "$PIGGY" pass show-batch --update --format ndjson --out-dir "$OUT_DIR" fresh
  assert_line --index 0 --partial '"count":1'
  assert_line --index 1 --partial '"ok":true'
  assert_line --index 1 --partial '"skipped":true'
  assert_output --partial '"ok":1,"failed":0'
  # The pre-existing plaintext is untouched.
  assert [ "$(cat "$OUT_DIR/fresh")" = "rendered plaintext" ]
}

function show_batch_update_decrypts_stale_plaintext { # @test
  # Plaintext older than the ebox → no skip; the decrypt proceeds and
  # (with this bogus fixture) fails at parse with `decrypt-failed`.
  mkdir -p "$PIGGY_STORE_DIR" "$OUT_DIR"
  printf 'bogus ebox' >"$PIGGY_STORE_DIR/stale.ebox"
  printf 'old plaintext' >"$OUT_DIR/stale"
  touch -t 200101010000 "$OUT_DIR/stale"
  run "$PIGGY" pass show-batch --update --format ndjson --out-dir "$OUT_DIR" stale
  assert_failure
  assert_line --index 1 --partial '"ok":false'
  assert_line --index 1 --partial '"kind":"decrypt-failed"'
  refute_output --partial '"skipped"'
}

function show_batch_without_update_ignores_freshness { # @test
  # The skip is opt-in: without --update, a fresh plaintext does not
  # suppress the decrypt (which fails at parse on this fixture).
  mkdir -p "$PIGGY_STORE_DIR" "$OUT_DIR"
  printf 'bogus ebox' >"$PIGGY_STORE_DIR/fresh.ebox"
  printf 'rendered plaintext' >"$OUT_DIR/fresh"
  touch -t 200101010000 "$PIGGY_STORE_DIR/fresh.ebox"
  run "$PIGGY" pass show-batch --format ndjson --out-dir "$OUT_DIR" fresh
  assert_failure
  assert_line --index 1 --partial '"kind":"decrypt-failed"'
  refute_output --partial '"skipped"'
}

function show_batch_update_human_format_marks_skip { # @test
  # Human format flags the skip so a terminal user can tell a no-op
  # from a real decrypt.
  mkdir -p "$PIGGY_STORE_DIR" "$OUT_DIR"
  printf 'bogus ebox' >"$PIGGY_STORE_DIR/fresh.ebox"
  printf 'rendered plaintext' >"$OUT_DIR/fresh"
  touch -t 200101010000 "$PIGGY_STORE_DIR/fresh.ebox"
  run -0 "$PIGGY" pass show-batch --update --format human --out-dir "$OUT_DIR" fresh
  assert_output --partial "up-to-date"
  assert_output --partial "Summary: 1 ok, 0 failed"
}

function show_batch_update_conflicts_with_all_or_nothing { # @test
  # piggy#172: --update and --all-or-nothing encode contradictory
  # out-dir models (incremental freshen vs. roll-back-to-empty), so
  # the combination has no coherent failure semantics and clap rejects
  # it at parse time — before any store read or card session. (An
  # earlier revision allowed the pair and tried to preserve skipped
  # files through the wipe; see git history of this file and #172 for
  # why that was replaced with a hard conflict.)
  run -2 "$PIGGY" pass show-batch --update --all-or-nothing --out-dir "$OUT_DIR" anyname
  assert_output --partial "cannot be used with"
  assert_output --partial "--update"
  assert_output --partial "--all-or-nothing"
}

# --- human format ---

function show_batch_human_format_renders_brackets_and_arrows { # @test
  # Human format is implementation-defined per RFC 0005; pin the
  # current shape so a refactor that drops the friendly output is
  # flagged. Asserts presence rather than exact equality so the
  # message text can evolve.
  mkdir -p "$PIGGY_STORE_DIR"
  run "$PIGGY" pass show-batch --format human --out-dir "$OUT_DIR" missing
  assert_failure
  # The plan banner.
  assert_output --partial "Decrypting 1 ebox"
  # Per-ebox failure line shape: "[1/1] missing FAIL ..."
  assert_output --partial "[1/1]"
  assert_output --partial "missing FAIL"
  # Summary footer.
  assert_output --partial "Summary: 0 ok, 1 failed"
}

function show_batch_human_format_is_default { # @test
  # No --format flag → human (matches the clap default_value_t in
  # crates/piggy/src/main.rs). Distinguishable from ndjson because
  # the first byte of stdout is `D` for human ("Decrypting...")
  # vs `{` for NDJSON.
  mkdir -p "$PIGGY_STORE_DIR"
  run "$PIGGY" pass show-batch --out-dir "$OUT_DIR" missing
  assert_failure
  # If the format were ndjson, line 0 would be the JSON plan record.
  refute_line --index 0 --partial '"type":"plan"'
  assert_line --index 0 --partial "Decrypting 1 ebox"
}

# --- out-dir handling ---

function show_batch_creates_out_dir_when_missing { # @test
  # Per the implementation: out_dir is created with 0o700 if it
  # doesn't exist. Use a fresh non-existent path; show-batch must
  # not 500 just because the parent dir is missing.
  mkdir -p "$PIGGY_STORE_DIR"
  local fresh="$BATS_TEST_TMPDIR/fresh-out-dir-$RANDOM"
  assert [ ! -d "$fresh" ]
  run "$PIGGY" pass show-batch --format ndjson --out-dir "$fresh" missing
  # Exit is 1 because the ebox was missing, but the out-dir must exist now.
  assert [ -d "$fresh" ]
}
