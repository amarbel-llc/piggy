
default: lint build test

[group('pre-build')]
lint: lint-fmt lint-rust lint-piggy-piv-portable lint-worktree lint-closure-no-pivy lint-fibby-holder lint-pigtrough-stack-isolated _lint-hogtie-linux-only

# --- build ---

[group('build')]
build: build-nix build-rust build-go build-pigpen

# Build the default piggy nix package, plus the .#fibby and .#piggy-test-sshd
# packages that aren't transitive deps of .#default, so flake.nix regressions
# in those surface at the merge gate.
#
# build the default piggy nix package plus .#fibby, .#piggy-test-sshd, .#piggy-agent-conformance and .#pigtrough
[group('build')]
build-nix:
    nix build --show-trace
    # Also build the standalone fibby package — `nix build` (no args)
    # defaults to `.#default` (= piggy), which doesn't transitively
    # depend on `.#fibby`. Without an explicit second build, a broken
    # flake.nix change to the fibby package would only surface the
    # next time someone ran `nix build .#fibby` directly or
    # `just load-fibby` (#129).
    nix build .#fibby --no-link --show-trace
    # Same rationale for the Go piggy-test-sshd binary (piggy#135): it's
    # not a transitive dep of `.#default`, so build it explicitly here to
    # catch flake.nix / vendorHash regressions at the merge gate rather
    # than only when `just debug-piggy-test-sshd` or the Phase D bats run.
    nix build .#piggy-test-sshd --no-link --show-trace
    # And piggy-agent-conformance: a godyn build (buildGoAuto) that
    # self-consumes go-pkgs-test, so a source-filter regression or a stale
    # go/gomod2nix.toml fails the merge gate here (piggy#183). The whole-module
    # vet + tests are `just test-go` (checks.go-vet / go-tests, piggy#340).
    nix build .#piggy-agent-conformance --no-link --show-trace
    # And pigtrough (FDR 0009): its own narrow package, not a dep of
    # `.#default`; building it also runs its tests in the sandbox.
    nix build .#pigtrough --no-link --show-trace
    # And hogtie(8): its own narrow package; building it also runs every
    # hogtie test, the binary tests included, in the sandbox.
    {{ if os() == "linux" { "nix build .#hogtie --no-link --show-trace" } else { "true" } }}

# Cargo-build the workspace; on Linux with no ARGS, also build fibby with
# --features hardware-proxy so pcsc-sys's link-time pkg-config runs at the gate.
#
# cargo-build the workspace, forwarding ARGS
[group('build')]
build-rust *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build {{ARGS}}
    # Linux-only second pass: build fibby with --features hardware-proxy
    # so pcsc-sys's build.rs (which pkg-configs for libpcsclite at
    # compile time) runs in the merge gate. Clippy doesn't link, so a
    # missing/wrong libpcsclite-dev would slip past `lint-rust`. Same
    # Linux gating rationale as `lint-rust`'s second pass (flake.nix:166
    # adds pcsclite to rustBuildInputs only on isLinux). Skipped when
    # ARGS is set on the assumption that the caller is specifying a
    # narrower build scope on purpose.
    if [ -z "{{ARGS}}" ] && [ "$(uname -s)" = Linux ]; then
      cargo build -p fibby --features hardware-proxy
    fi

[group('build')]
build-release: build-rust-release

# cargo-build the workspace in release mode (cargo build --release)
[group('build')]
build-rust-release:
    cargo build --release

# go/ module (#183): the registry/codec Go library (module
# code.linenisgreat.com/piggy/go) that madder depends on (inverting today's
# Rust-port-of-madder relationship). build-go + test-go are wired
# into the build/test aggregates so the pre-merge `just` hook exercises the
# module. Per the maintainer ruling (#183/#188) the nix-level gate is the
# dagnabit export facade check, NOT a buildGoModule derivation — the go/
# library is consumed, not a piggy-shipped binary (the two cmd/ binaries
# build via buildGoApplication; see flake.nix).
#
# The facade check/repair now runs through conformist's dewey-facade-export
# lane (the conformist migration the old comment here deferred): drift is
# REPAIRED at commit time by the `conformist-pre-commit` hook (regenerate +
# stage the pkgs/ facades) and CHECKED at the merge gate by `just lint-worktree`
# (in the `lint` aggregate). The standalone `codemod-facades` / `lint-facades`
# recipes were retired in favor of those lanes; `nix run …#conform`-style ad-hoc
# `dagnabit export` is still possible (bare dagnabit is on the devShell PATH).
# Refresh the go/ module's go.mod/go.sum (`go mod tidy`). Run after adding or
# dropping an import in the module.
#
# refresh the go/ module's go.mod and go.sum
[group('build')]
update-go:
    cd go && go mod tidy

# Regenerate go/gomod2nix.toml from go/go.mod|go.sum after a dep change (run
# right after `update-go`, the sibling lockfile update). gomod2nix is on the
# devShell PATH; `nix run .#gomod2nix` is the reload-independent fallback. A
# maintenance leaf (not a `build`-verb aggregate member): the nix Go builds are
# the freshness GATE (a stale toml fails the piggy-agent-conformance /
# piggy-test-sshd builds in build-nix and test-go), so this is the manual REPAIR. The
# conformist subdir freshness lane is deferred to conformist#79 (the stock
# gomod2nix linter is tree-root-only).
#
# regenerate go/gomod2nix.toml from go/go.mod and go.sum
[group('maintenance')]
update-gomod2nix:
    cd go && gomod2nix

# Compile the go/ module (`go build ./...`). Wired into the `build`
# aggregate so the pre-merge `just` hook exercises it.
#
# compile the go/ module
[group('build')]
build-go:
    cd go && go build ./...

# The go/ module's tests and vet in the nix sandbox, one cached run per
# package (godyn(7) TESTS and VET; checks.<system>.go-tests and go-vet,
# piggy#189): only an edited package's cone re-runs. Built with `-tags
# test`, which activates dewey's
# test_ui harness (dewey/pkgs/test_ui is behind //go:build test, mirroring
# madder's own `go test -tags test` convention). Prints one ok/FAIL line per
# package.
#
# run the go/ module's test suite
[group('post-build')]
test-go:
    #!/usr/bin/env bash
    set -euo pipefail
    system=$(nix eval --raw --impure --expr 'builtins.currentSystem')
    nix build ".#checks.${system}.go-vet" --no-link --print-build-logs
    out=$(nix build ".#checks.${system}.go-tests" --no-link --print-out-paths --print-build-logs)
    cat "$out"

# piggy-pigpen (RFC 0008/0009 prototype): a pure-RustCrypto, wasm-buildable
# crate INTENTIONALLY excluded from the cargo workspace (root Cargo.toml
# `exclude`), so `build-rust`/`test-rust` (which operate on the workspace) do
# not reach it. These recipes give it a paved build/test path and are wired
# into the build/test aggregates so the pre-merge `just` hook exercises it,
# mirroring the go/ satellite-module treatment above.
#
# build the standalone piggy-pigpen crate, which the workspace excludes
[group('build')]
build-pigpen:
    cd crates/piggy-pigpen && cargo build

# Every feature on, so the `agent` oracle's stub-agent tests run in the gate.
#
# test the standalone piggy-pigpen crate with every feature on
[group('post-build')]
test-pigpen:
    cd crates/piggy-pigpen && cargo test --all-features

# Regenerate the go/ module's pkgs/ facades in place — the apply-mode inverse of
# `just lint-worktree`'s facade CHECK, and the codemod sibling of
# `codemod-rfc0002-fixture` (both regenerate committed artifacts). Runs
# conformist's dewey-facade-export lane off the SAME impure config as the CHECK
# (the shared conformistFacadeModule, pinning one `dagnabit`), so its output
# matches the merge-gate CHECK byte-for-byte — unlike a bare devShell
# `dagnabit export`, which can drift on generator version. Part of the `codemod`
# aggregate, so a routine `just codemod` keeps the facades current; also the
# explicit standalone repair when committed drift reaches the merge gate.
#
# Facade drift is normally REPAIRED automatically at commit time by the
# `conformist-pre-commit` hook (spinclass installs it per session; it runs
# `conformist --staged`, so it only acts on staged content — a clean tree with
# already-committed drift slips past it). The loud backstop is `just
# lint-worktree`, in the `lint` aggregate. This recipe rewrites the facades in
# place; `git add` them yourself. Re-added after the conformist migration
# retired the standalone facade recipes and left no paved repair path. See the
# go/ block above and flake.nix conformistFacadeModule.
#
# regenerate the go/ module's pkgs/ facades in place
[group('codemod')]
codemod-facades:
    #!/usr/bin/env bash
    set -euo pipefail
    cfg=$(nix build --no-link --print-out-paths '.#conformist-impure-config')
    conformist --config-file "$cfg" --tree-root .

# Regenerate the piggy-scoped RFC 0002 conformance fixture under
# go/internal/charlie/markl_registrations/testdata/. Run after changing a
# registered format or purpose. The committed JSON is the canonical artifact;
# test-go's TestRFC0002VectorsRoundTrip verifies every entry on every run.
# Scope is piggy-only (piggy purposes + every registered format incl. the #86
# ssh formats); cross-domain fixture assembly is the #187 RFC. Mirrors madder's
# codemod-rfc0002-fixture. #183 (#9). Also copies it to
# crates/piggy-markl/testdata/, which the Rust conformance test replays (the
# crate's nix source holds only crates/, so it cannot be a symlink);
# lint-worktree fails when the two copies differ (piggy#235).
#
# regenerate the piggy-scoped RFC 0002 conformance fixture
[group('codemod')]
codemod-rfc0002-fixture:
    cd go && go test -count=1 -tags 'test rfc0002_generate' -run TestGenerateRFC0002Vectors ./internal/charlie/markl_registrations/...
    cp go/internal/charlie/markl_registrations/testdata/0002-markl-id-format-vectors.json crates/piggy-markl/testdata/0002-markl-id-format-vectors.json

# Regenerate the normative pigpen-v1 vector file, docs/rfcs/0008-pigpen-vectors.txt
# (RFC 0008 §10, RFC 0009 §8), from the fixed public test secrets in the Go
# generator. Run after an intended pigpen wire or reader change. The committed
# file is the normative artifact: test-go replays it in Go and test-pigpen
# replays the SAME file in Rust, so the two implementations cannot drift from
# it or from each other. Output is deterministic; a no-op run leaves no diff.
# `-count=1` defeats the go test cache: the generator's effect is the file it
# writes, and a cached "ok" would skip the write and leave a stale or
# hand-edited file in place. The generator writes the go/ testdata copy
# (go/ is its own nix source, so it cannot be a symlink, piggy#189); this
# copies it to the normative file, and lint-worktree fails when they differ.
#
# regenerate the normative pigpen-v1 vector file
[group('codemod')]
codemod-pigpen-vectors:
    cd go && go test -count=1 -tags 'test pigpen_vectors_generate' -run TestGeneratePigpenVectors ./internal/delta/pigpen/...
    cp go/internal/delta/pigpen/testdata/0008-pigpen-vectors.txt docs/rfcs/0008-pigpen-vectors.txt

# Regenerate pigtrough's fake-upstream TLS fixtures (FDR 0009 pilot):
# a P-256 test CA and an api.github.com leaf it signs, valid for a century.
# tests/wire.rs trusts only the CA, so the real roots never apply in a test.
# These are public test material, not secrets: the CA key is discarded and
# the leaf key verifies nothing outside the test.
#
# regenerate pigtrough's fake-upstream test CA and leaf certificate
[group('codemod')]
codemod-pigtrough-test-cert:
    #!/usr/bin/env bash
    set -euo pipefail
    out=crates/pigtrough/testdata
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    mkdir -p "$out"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout "$work/ca.key" -out "$out/fake-upstream-ca.pem" -days 36500 \
      -subj "/CN=pigtrough test CA" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign"
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout "$out/fake-upstream-leaf.key.pem" -out "$work/leaf.csr" \
      -subj "/CN=api.github.com"
    printf '%s\n' "subjectAltName=DNS:api.github.com" \
      "basicConstraints=critical,CA:FALSE" \
      "keyUsage=critical,digitalSignature" \
      "extendedKeyUsage=serverAuth" > "$work/leaf.ext"
    openssl x509 -req -in "$work/leaf.csr" -CA "$out/fake-upstream-ca.pem" \
      -CAkey "$work/ca.key" -set_serial 2 -days 36500 \
      -extfile "$work/leaf.ext" -out "$out/fake-upstream-leaf.pem"

# Capture the pivy-oracle differential corpus (piggy#164 Phase 1 item 2).
# Encrypt a matrix of plaintexts to fibby's RFC 5903 slot-9D key with the
# Rust `piggy-ids encrypt`, decrypt each ebox with BOTH the C `pivy-box
# stream decrypt` and the Rust in-process `piggy box stream decrypt`
# against the same fibby card, assert all three (the two decrypts and the
# input) agree byte-for-byte, then freeze the ebox + plaintext under
# crates/piggy-box/tests/fixtures/oracle-box/. The committed fixtures are
# replayed OFFLINE (no card, no C) by crates/piggy-box/tests/
# oracle_box_corpus.rs, so they outlive the C pivy-box this recipe uses as
# the capture-time oracle. Re-run after any piggy-box wire-format change.
# Linux-only (needs fibby's AF_UNIX pcsc socket); runs on flac (fibby is a
# virtual card, no hardware).
#
# capture the C pivy-box oracle fixtures replayed by piggy-box's offline corpus
[group('codemod')]
[linux]
codemod-capture-pivy-oracle-box: build-rust
    #!/usr/bin/env bash
    set -uo pipefail
    pivy_out=$(nix build .#pivy --no-link --print-out-paths) || exit 1
    real_pivy_box="$pivy_out/bin/pivy-box"
    pivy_tool="$pivy_out/bin/pivy-tool"
    piggy="$PWD/target/debug/piggy"
    piggy_ids="$PWD/target/debug/piggy-ids"
    fibby="$PWD/target/debug/fibby"
    for b in "$real_pivy_box" "$piggy" "$piggy_ids" "$fibby"; do
      [[ -x $b ]] || { echo "missing $b (build-rust / nix build .#pivy)"; exit 1; }
    done

    workdir=$(mktemp -d /tmp/oracle-box-XXXXXX)
    fibby_sock="$workdir/pcscd.comm"
    fibby_log="$workdir/fibby.log"
    fibby_pid=""
    cleanup() { [[ -n "$fibby_pid" ]] && kill "$fibby_pid" 2>/dev/null || true; rm -rf "$workdir"; }
    trap cleanup EXIT

    echo "=== fibby (virtual, --seed-rfc5903-slot-9d-cert) ==="
    FIBBY_LOG=wire "$fibby" --socket "$fibby_sock" --backend virtual \
      --seed-rfc5903-slot-9d-cert >"$fibby_log" 2>&1 &
    fibby_pid=$!
    for _ in $(seq 1 50); do [[ -S $fibby_sock ]] && break; sleep 0.1; done
    [[ -S $fibby_sock ]] || { echo "fibby socket never appeared"; cat "$fibby_log"; exit 1; }

    # The card path only (no agent), PIN via the refusing-by-default test
    # askpass (piggy-testing(7) PIN PROMPT SAFETY NET).
    askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
    export PCSCLITE_CSOCK_NAME="$fibby_sock" \
      SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force DISPLAY="" \
      PIGGY_TEST_FIB_PIN=123456
    unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK

    card_recipient=$("$piggy_ids" detect-pubkey) || { echo "detect-pubkey failed"; cat "$fibby_log"; exit 1; }
    [[ $card_recipient == piggy-recipient-v1@pivy_ecdh_p256_pub-* ]] || {
      echo "unexpected card recipient: $card_recipient"; exit 1; }
    # A second, cardless recipient (the P-256 generator point) for the
    # any-of-N case: fibby cannot open its part, so C and the offline
    # replay both open the card part — which is exactly what we assert.
    gen_recipient="piggy-recipient-v1@pivy_ecdh_p256_pub-qd43050juykyy3lchnnw2caygre8wqmasyk7kvaq7jsnj3wcnrpfve2jwdn"

    outdir="$PWD/crates/piggy-box/tests/fixtures/oracle-box"
    rm -rf "$outdir"; mkdir -p "$outdir"

    # emit_case <name> <plaintext-file> <recipient...>
    fail=0
    emit_case() {
      local name="$1" plain="$2"; shift 2
      local ids="$workdir/$name.ids" ebox="$workdir/$name.ebox"
      printf '%s\n' "$@" >"$ids"
      "$piggy_ids" encrypt "$ids" <"$plain" >"$ebox" || { echo "  [$name] encrypt failed"; fail=1; return; }

      local out_c="$workdir/$name.c" out_rust="$workdir/$name.rust"
      "$real_pivy_box" stream decrypt <"$ebox" >"$out_c" 2>/dev/null || { echo "  [$name] C decrypt failed"; fail=1; return; }
      "$piggy" box stream decrypt "$ebox" >"$out_rust" 2>/dev/null || { echo "  [$name] Rust decrypt failed"; fail=1; return; }
      cmp -s "$plain" "$out_c"    || { echo "  [$name] C decrypt != plaintext"; fail=1; return; }
      cmp -s "$plain" "$out_rust" || { echo "  [$name] Rust decrypt != plaintext"; fail=1; return; }

      cp "$ebox" "$outdir/$name.ebox"
      cp "$plain" "$outdir/$name.plaintext"
      echo "  [$name] ok ($(wc -c <"$plain") B plaintext -> $(wc -c <"$ebox") B ebox, $# recipient(s))"
    }

    # Plaintext matrix: empty, single byte, short text, a full 0x00..0xFF
    # byte range, and 128 KiB + 1 to cross the 128 KiB stream chunk boundary
    # (multi-chunk framing). Deterministic so a re-capture diffs cleanly.
    : >"$workdir/empty.plain"
    printf 'x' >"$workdir/one-byte.plain"
    printf 'oracle-box corpus: rust encrypt, C+rust decrypt agree' >"$workdir/short-text.plain"
    for i in $(seq 0 255); do printf "\\x$(printf %02x "$i")"; done >"$workdir/binary-256.plain"
    head -c 131073 /dev/zero | tr '\0' 'M' >"$workdir/multi-chunk.plain"

    echo "=== capturing corpus ==="
    emit_case empty          "$workdir/empty.plain"       "$card_recipient"
    emit_case one-byte       "$workdir/one-byte.plain"    "$card_recipient"
    emit_case short-text     "$workdir/short-text.plain"  "$card_recipient"
    emit_case binary-256     "$workdir/binary-256.plain"  "$card_recipient"
    emit_case multi-chunk    "$workdir/multi-chunk.plain" "$card_recipient"
    emit_case two-recipients "$workdir/short-text.plain"  "$card_recipient" "$gen_recipient"

    [[ $fail -eq 0 ]] || { echo "=== FAILED: some cases did not round-trip ==="; exit 1; }
    echo "=== corpus captured under crates/piggy-box/tests/fixtures/oracle-box/ ==="
    echo "    git add it; oracle_box_corpus.rs replays it offline in test-rust."

# Render docs/diagrams/*.puml to SVG in place via plantuml (on PATH). The
# .puml is the source of truth and the only thing committed; the .svg
# beside it is a local-only, gitignored render. Re-run after editing any
# diagram. Serves the design-doc loop (piggy FDR 0001's SSH-agent
# topology, eng#295).
#
# render docs/diagrams/*.puml to local-only, gitignored SVGs (the .puml is what is committed)
[group('codemod')]
codemod-diagrams:
    plantuml -tsvg docs/diagrams/*.puml

# gofmt the hand-written go/ sources: the internal/ core + the public
# sub-packages (agent, age, pigpen). The pkgs/ facades are EXCLUDED: they are
# formatted by dagnabit's own conformist pass (the dewey-facade-export lane), so
# reformatting them with plain gofmt would risk drift against the facade CHECK
# (`just lint-worktree`). conformist's `nix fmt` does not cover Go, so this
# recipe is the canonical go/ formatter for the hand-written sources.
#
# gofmt the hand-written go/ sources
[group('codemod')]
codemod-fmt-go:
    # `internal` + `cmd` are the hand-written roots. The former arg list
    # (`internal agent age pigpen`) predated the dagnabit re-layout that
    # moved those three under internal/delta/ — gofmt formatted
    # `internal` and then exited 2 on the stale paths (piggy#226).
    cd go && gofmt -w internal cmd

# run the nix-built piggy package (nix run . --), forwarding ARGS
run-nix *ARGS:
    nix run . -- {{ARGS}}

# --- test ---

[group('post-build')]
test: validate-grammar test-grammar-vectors test-bats-default test-bats-conformance test-bats-conformance-x509-profile test-rust test-pin-cache-table-checks test-go test-pigpen test-nix-hm-module test-nix-hm-secrets-module _test-conformance-linux-only _test-vm-linux-only

[group('post-build')]
test-optional: test-bats-file test-bats-piggy-local test-bats-conformance-protocol test-bats-conformance-pivy-agent-hardware test-bats-conformance-pivy-tool-admin-key _test-optional-linux-only

# The C pivy-agent smoke over fibby, out of the merge gate since piggy#364.
[linux]
_test-optional-linux-only: test-bats-conformance-fibby-pivy-agent-smoke

[macos]
_test-optional-linux-only:

[linux]
_test-conformance-linux-only: test-bats-conformance-ca-root-cert test-bats-conformance-ca-root-cert-fibby test-bats-conformance-ca-issue-fibby test-bats-conformance-piggy-ssh-via-fibby test-bats-conformance-box-agentless-fibby test-bats-conformance-agent-pin-on-demand test-bats-conformance-agent-concurrent-sign test-bats-conformance-agent-ed25519 test-bats-conformance-holder-mint-fibby test-bats-conformance-ca-csr-fibby test-bats-conformance-root-cert-guard test-bats-conformance-tool-admin-store-fibby test-bats-conformance-card-rotate-admin-fibby test-bats-conformance-tool-attest-verify-fibby test-bats-conformance-pigpen-open-fibby test-bats-conformance-agent-upstream test-bats-conformance-agent-multicard test-bats-conformance-fibby-hotplug test-bats-conformance-age-plugin-piggy test-bats-conformance-sign-bytes-fibby test-bats-conformance-agentless-fallback-fibby test-bats-conformance-card-init-fibby test-bats-conformance-card-add-key-fibby test-bats-conformance-operator-act test-bats-conformance-init-fibby test-bats-conformance-box-interop-fibby test-bats-conformance-tool-fibby test-bats-conformance-tool-pin-fibby test-bats-conformance-tool-admin-fibby test-bats-conformance-tool-keys-fibby test-bats-conformance-tool-factory-reset-fibby test-bats-conformance-list-blank-fibby test-bats-conformance-manage-fibby test-bats-conformance-recipients-add-attached-fibby test-rust-integration-fibby test-bats-conformance-show-batch-fibby test-bats-conformance-secrets-reconcile-fibby test-bats-conformance-recipients-sync-fibby test-bats-conformance-pass-ls-recipients-fibby test-bats-conformance-health-fibby

[macos]
_test-conformance-linux-only:

# NixOS VM lanes (nix/vm-tests/), part of the merge gate via `test`. The
# shared Linux build host has no /dev/kvm (its cloud provider exposes no
# nested virt on any server type, per circus 2026-09-14), so each run is
# a TCG boot: measured 2026-09-14 at 2-3 minutes per lane once the guest
# closure is cached, which the operator accepted for every merge. A KVM
# builder (a bare-metal fleet host, a circus follow-up) would only make
# them faster.
[linux]
_test-vm-linux-only: test-vm-luks test-vm-zfs test-vm-agent test-vm-holder

[macos]
_test-vm-linux-only:

# Sandboxed bats lane: runs every top-level t*.bats NOT tagged
# `# bats file_tags=hardware` inside the nix build sandbox. See
# ./bats.nix for the lane builder and piggy-testing(7) for the tag
# convention. This replaces the previous `test-bats-piggy` recipe as the
# authoritative gate for the core suite; the bare-`bats` fallback lives
# at `test-bats-piggy-local` for fast iteration. `test-bats-conformance`
# also runs the non-hardware conformance files outside the sandbox; the
# dual coverage is intentional (piggy#117, piggy-testing(7)).
#
# run the sandboxed bats lane via nix build .#bats-default
[group('post-build')]
test-bats-default:
    nix build .#bats-default --no-link --print-build-logs

# Local-iteration shortcut: re-runs the same t*.bats files outside the
# nix sandbox against `target/debug/piggy`. Faster than `nix build` on
# small edits; CI / pre-merge should use `test-bats-default` instead.
#
# Bats tests route through the rust `piggy` binary so the full
# rust → bash dispatch path is exercised; `build-rust` is a hard
# prerequisite — `zz-tests_bats/common.bash` aborts if
# `target/debug/piggy` is missing.
#
# re-run the default bats files outside the sandbox against target/debug/piggy
[group('post-build')]
test-bats-piggy-local: build-rust
  BATS_TEST_TIMEOUT=30 bats --jobs {{num_cpus()}} --tap zz-tests_bats/t*.bats

# TMPDIR override sidestepping the fence bridge-socket sun_path
# overflow under a long session $TMPDIR: fence's Linux network policy
# is enforced via socat bridges to AF_UNIX sockets under
# $TMPDIR/nix-shell.XXXXXX/. When $TMPDIR is a long path — as it is
# under a spinclass session worktree's per-session scratch dir
# (<repo>/.worktrees/<name>/.tmp) — the full socket path can reach the
# kernel's 108-byte sockaddr_un sun_path limit, silently truncating or
# dropping the socket file while fence polls for the untruncated path,
# hanging until "failed to initialize Linux bridge: timeout waiting
# for bridge sockets to be created". Forcing a short TMPDIR sidesteps
# it; the real fix belongs upstream in fence. Root-caused and tracked
# at linenisgreat/bats#37. Mirrors the same sun_path-short discipline
# this repo's fibby PCSC loopback already applies (see flake.nix).
# Linux-only: Darwin's fence sandbox uses sandbox-exec/Seatbelt
# instead and never hits this Linux-only socat bridge. Shared across
# every fence-sandboxed bats recipe below rather than duplicated per
# recipe; interpolates to an empty string (no-op) on Darwin.
fence-tmpdir-linux := if os() == "linux" { "TMPDIR=/tmp" } else { "" }

# Every fence-sandboxed lane whose fibby is spawned by the recipe (socket
# under a /tmp `$workdir`) passes this to the bats wrapper: since fence
# 0.1.66 the Linux sandbox mounts a private tmpfs over /tmp, so a
# host-created AF_UNIX socket there is invisible unless its directory is
# exposed (bats 2de2b9e; piggy#253). Accepted by fence 0.1.60 too. The
# string is spliced into the recipe's shell verbatim, so `$workdir` is
# the recipe's own variable.
bats-expose-fibby-workdir := '--expose-host-path-rw "$workdir"'

# The flake exports the VM checks for every Linux system eachDefaultSystem
# covers; the `[linux]` recipes below must ask for the host's own, or a
# gate run on an aarch64-linux host would request a foreign guest.
vm-check-system := arch() + "-linux"

# Run the conformance bats glob outside the sandbox: the non-pty tests under
# batman (with fibby/pivy redirect on Linux) plus the pty-tagged tests
# unsandboxed (fence blocks /dev/ptmx).
#
# run the conformance bats glob outside the sandbox
[group('post-build')]
test-bats-conformance: build-rust
  #!/usr/bin/env bash
  set -euo pipefail
  # On Linux, hand the glob a fibby binary (FIBBY_BIN) so a test that stands
  # up a virtual card routes its PC/SC context at it instead of the host's
  # system pcscd, which denies SCardEstablishContext
  # (SCARD_W_SECURITY_VIOLATION) in headless/polkit sessions. macOS ignores
  # PCSCLITE_CSOCK_NAME, so there's nothing to redirect — run the glob
  # unchanged and skip the (pointless) fibby build. The agent-backed fibby
  # tests still skip here: they gate on PIVY_AGENT/PIGGY_BIN, left unset so
  # they run only via their dedicated [linux] recipes. The `c-pivy` files
  # run the C binaries and are left to test-optional (piggy#364), so this
  # recipe never builds C.
  fibby_env=()
  if [[ "$(uname -s)" == Linux ]]; then
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    fibby_env=(FIBBY_BIN="$fibby_out/bin/fibby")
  fi
  # The fenced (batman) glob excludes `pty`-tagged tests: fence (the
  # third-party Use-Tusk/fence sandbox) denies PTY allocation
  # (open(/dev/ptmx) → EPERM), which breaks the two SSH_ASKPASS_REQUIRE
  # tty tests that need a real terminal. They run unsandboxed below
  # instead. Tracked at piggy#167 (fence-profile fix is upstream:
  # amarbel-llc/igloo + Use-Tusk/fence).
  env "${fibby_env[@]}" {{ fence-tmpdir-linux }} BATS_TEST_TIMEOUT=30 \
    bats --jobs {{ num_cpus() }} --filter-tags '!pty,!c-pivy' --tap zz-tests_bats/conformance/*.bats
  # The pty-tagged tests need a real /dev/ptmx, which fence blocks — run
  # them outside the sandbox (the same escape the pcscd/hardware lanes
  # use). pty-spawn.py surfaces the true errno if a future sandbox change
  # ever re-blocks them here.
  env "${fibby_env[@]}" BATS_TEST_TIMEOUT=30 \
    bats --no-sandbox --filter-tags 'pty,!c-pivy' --tap zz-tests_bats/conformance/*.bats

# The C pivy-tool `-K default` parse regression (piggy#23) against a fresh
# .#pivy, routed at a fibby virtual card on Linux (see the file's header).
# Outside the merge gate since piggy#364: C pivy is test-only and the gate
# no longer builds it. Leaves with the C build at piggy#289 Phase 5.
#
# run the C pivy-tool admin-key bats against a fresh .#pivy
[group('post-build')]
test-bats-conformance-pivy-tool-admin-key:
  #!/usr/bin/env bash
  set -euo pipefail
  pivy_out=$(nix build .#pivy --no-link --print-out-paths)
  env_args=(PIVY_TOOL="$pivy_out/bin/pivy-tool")
  if [[ "$(uname -s)" == Linux ]]; then
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    env_args+=(FIBBY_BIN="$fibby_out/bin/fibby")
  fi
  env "${env_args[@]}" {{ fence-tmpdir-linux }} BATS_TEST_TIMEOUT=30 \
    bats --tap zz-tests_bats/conformance/pivy_tool_admin_key.bats

# Run the SSH-agent wire-protocol conformance bats against a freshly built
# piggy-agent-conformance binary (the .#piggy.tests.conformance package).
#
# run the SSH-agent wire-protocol conformance bats
[group('post-build')]
test-bats-conformance-protocol: build-rust
  #!/usr/bin/env bash
  set -euo pipefail
  # Build the conformance binary on demand and resolve its store path
  # without creating a `./result-conformance` symlink in the worktree.
  # The binary is exposed as piggy.tests.conformance (see passthru in
  # flake.nix). nix caches aggressively, so repeat invocations are free.
  out=$(nix build .#piggy.tests.conformance --no-link --print-out-paths)
  env {{ fence-tmpdir-linux }} \
    CONFORMANCE_BIN="$out/bin/piggy-agent-conformance" \
    BATS_TEST_TIMEOUT=30 bats --allow-local-binding \
    --tap zz-tests_bats/conformance/piggy_agent_protocol.bats


# Agentless box decrypt against FIBBY (the Rust VirtualCard). Brings up fibby
# with a seeded slot-9D ECDH key, then runs the card-agnostic
# piggy_box_decrypt_agentless bats test against it: Rust `piggy-ids encrypt` ->
# `piggy box stream decrypt` with no agent -> Rust CardEcdhOracle -> fibby's
# 9D ECDH (piggy#57). Pure-Rust card-under-test, no Java/jcardsim/hardware, so
# it runs in the default `just test` lane.
#
# run the fibby-backed agentless box decrypt bats gate
[group('post-build')]
[linux]
test-bats-conformance-box-agentless-fibby: build-rust
  #!/usr/bin/env bash
  set -uo pipefail
  fibby_bin="$PWD/target/debug/fibby"
  piggy_bin="$PWD/target/debug/piggy"
  [[ -x $fibby_bin ]] || { echo "missing $fibby_bin (build-rust)"; exit 1; }

  workdir=$(mktemp -d /tmp/pbox-agentless-fibby-XXXXXX)
  fibby_sock="$workdir/pcscd.comm"
  fibby_log="$workdir/fibby.log"
  fibby_pid=""
  cleanup() { [[ -n "$fibby_pid" ]] && kill "$fibby_pid" 2>/dev/null || true; rm -rf "$workdir"; }
  trap cleanup EXIT

  echo "=== Starting fibby (virtual, --seed-rfc5903-slot-9d-cert) ==="
  FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
    --seed-rfc5903-slot-9d-cert >"$fibby_log" 2>&1 &
  fibby_pid=$!
  for _ in $(seq 1 50); do [[ -S $fibby_sock ]] && break; sleep 0.1; done
  [[ -S $fibby_sock ]] || { echo "fibby socket never appeared"; cat "$fibby_log"; exit 1; }

  echo "=== discover fibby GUID via piggy tool -j list ==="
  guid=$(PCSCLITE_CSOCK_NAME="$fibby_sock" "$piggy_bin" tool -j list | grep -oE '"guid":"[0-9A-Fa-f]{32}"' | head -1 | cut -d'"' -f4)
  [[ -n $guid ]] || { echo "no GUID from fibby"; cat "$fibby_log"; exit 1; }
  echo "  guid: $guid"

  askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
  INTEROP_GUID="$guid" \
    PIGGY="$piggy_bin" \
    PCSCLITE_CSOCK_NAME="$fibby_sock" \
    SSH_ASKPASS="$askpass" \
    SSH_ASKPASS_REQUIRE=force \
    DISPLAY="" \
    PIGGY_TEST_FIB_PIN=123456 \
    {{ fence-tmpdir-linux }} \
    BATS_TEST_TIMEOUT=30 bats --allow-local-binding {{ bats-expose-fibby-workdir }} --tap \
    zz-tests_bats/conformance/piggy_box_decrypt_agentless.bats

# Byte-identical to test-bats-conformance-box-agentless-fibby except for
# batman's --no-sandbox. Isolates the fence sandbox as the barrier that
# stops the test's libpcsclite reaching fibby's AF_UNIX socket.
#
# Context (piggy#253): the igloo bump carried nixpkgs 567a49d -> f13ff45
# into `pkgs` — igloo/default.nix resolves nixpkgs from igloo's OWN
# flake.lock, so piggy's igloo.inputs.nixpkgs-master.follows does not
# govern it (igloo#37). After that, the gate lane fails with "The Smart
# card resource manager is not running" while the pivy-tool call in the
# same recipe, which runs OUTSIDE the sandbox, reaches the same socket.
#
# Bisected and narrowed by experiment:
#   - passes at 3a65727, fails on the bump          -> a real regression
#   - reverting only nixpkgs-master still fails     -> piggy's pin is not the lever
#   - reverting only igloo passes                   -> igloo b13d154 is the trigger
#   - THIS recipe (--no-sandbox) passes             -> the fence is the barrier
#   - dropping TMPDIR=/tmp does NOT help            -> not the bats#37 workaround
#   - fibby-pivy-agent-smoke passes sandboxed       -> not every fibby lane
#
# So the open question is narrower than "fence broke": what does a
# sandboxed process connecting DIRECTLY to fibby's PCSC socket depend on
# that the agent-mediated lanes do not. Still unidentified inside f13ff45.
#
# run the agentless box decrypt lane with the fence sandbox disabled
[group('debug')]
[linux]
debug-box-agentless-fibby-nosandbox: build-rust
  #!/usr/bin/env bash
  set -uo pipefail
  fibby_bin="$PWD/target/debug/fibby"
  piggy_bin="$PWD/target/debug/piggy"
  [[ -x $fibby_bin ]] || { echo "missing $fibby_bin (build-rust)"; exit 1; }

  workdir=$(mktemp -d /tmp/pbox-agentless-nosandbox-XXXXXX)
  fibby_sock="$workdir/pcscd.comm"
  fibby_log="$workdir/fibby.log"
  fibby_pid=""
  cleanup() { [[ -n "$fibby_pid" ]] && kill "$fibby_pid" 2>/dev/null || true; rm -rf "$workdir"; }
  trap cleanup EXIT

  echo "=== Starting fibby (virtual, --seed-rfc5903-slot-9d-cert) ==="
  FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
    --seed-rfc5903-slot-9d-cert >"$fibby_log" 2>&1 &
  fibby_pid=$!
  for _ in $(seq 1 50); do [[ -S $fibby_sock ]] && break; sleep 0.1; done
  [[ -S $fibby_sock ]] || { echo "fibby socket never appeared"; cat "$fibby_log"; exit 1; }

  echo "=== discover fibby GUID via piggy tool -j list ==="
  guid=$(PCSCLITE_CSOCK_NAME="$fibby_sock" "$piggy_bin" tool -j list | grep -oE '"guid":"[0-9A-Fa-f]{32}"' | head -1 | cut -d'"' -f4)
  [[ -n $guid ]] || { echo "no GUID from fibby"; cat "$fibby_log"; exit 1; }
  echo "  guid: $guid"

  askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
  INTEROP_GUID="$guid" \
    PIGGY="$piggy_bin" \
    PCSCLITE_CSOCK_NAME="$fibby_sock" \
    SSH_ASKPASS="$askpass" \
    SSH_ASKPASS_REQUIRE=force \
    DISPLAY="" \
    PIGGY_TEST_FIB_PIN=123456 \
    {{ fence-tmpdir-linux }} \
    BATS_TEST_TIMEOUT=30 bats --no-sandbox --tap \
    zz-tests_bats/conformance/piggy_box_decrypt_agentless.bats

# Template-format interop between `piggy box tpl create/show` and C pivy-box
# against FIBBY: the template piggy writes is one C read, and piggy reads
# the one C writes (fibby's 9D pubkey, local-guid, PIN-free). C's side is
# frozen fixtures under zz-tests_bats/fixtures/pivy-oracle/box-interop-fibby/
# (piggy#285), so the lane needs no C binary.
#
# run the fibby-backed pivy-box template interop bats gate
[group('post-build')]
[linux]
test-bats-conformance-box-interop-fibby: (_lane-pivy-oracle "box-interop-fibby" "piggy_box_interop.bats" "replay")

# Re-record the C pivy-box templates and verdicts the box-interop-fibby lane
# replays (piggy#285): the same lane with the live C binary.
#
# re-record the C pivy-box oracle fixtures for the box-interop-fibby lane
[group('codemod')]
[linux]
codemod-capture-pivy-oracle-box-interop-fibby: (_lane-pivy-oracle "box-interop-fibby" "piggy_box_interop.bats" "capture")

# Differential `piggy tool` conformance against C pivy-tool over FIBBY
# (piggy#289 Phase 3, milestone 3.1a). Brings up fibby seeded with slot
# 9A (RFC 6979 cert), 9D (RFC 5903 cert) and PINFO, then runs each op
# through the Rust `piggy tool` and compares it with C `pivy-tool`'s answer
# for the same card — C is the external contract. C's answers are frozen
# fixtures under zz-tests_bats/fixtures/pivy-oracle/tool-fibby/ (piggy#285),
# so this lane needs no C binary. Pure-Rust card-under-test, no hardware.
#
# run the fibby-backed differential piggy tool bats gate
[group('post-build')]
[linux]
test-bats-conformance-tool-fibby: (_lane-tool-fibby "replay")

# Re-record the C pivy-tool answers the tool-fibby lane replays (piggy#285):
# the same lane with the live C binary from .#pivy, writing
# zz-tests_bats/fixtures/pivy-oracle/tool-fibby/. Only for a deliberate
# change of what the port is held to; the recorded files are the contract.
#
# re-record the C pivy-tool oracle fixtures for the tool-fibby lane
[group('codemod')]
[linux]
codemod-capture-pivy-oracle-tool-fibby: (_lane-tool-fibby "capture")

[linux]
_lane-tool-fibby mode: build-rust
  #!/usr/bin/env bash
  set -uo pipefail
  fibby_bin="$PWD/target/debug/fibby"
  piggy_bin="$PWD/target/debug/piggy"
  [[ -x $fibby_bin ]] || { echo "missing $fibby_bin (build-rust)"; exit 1; }

  workdir=$(mktemp -d /tmp/tool-fibby-XXXXXX)
  fibby_sock="$workdir/pcscd.comm"
  fibby_log="$workdir/fibby.log"
  fibby_pid=""
  cleanup() { [[ -n "$fibby_pid" ]] && kill "$fibby_pid" 2>/dev/null || true; rm -rf "$workdir"; }
  trap cleanup EXIT

  echo "=== Starting fibby (virtual, slots 9A + 9D + PINFO seeded) ==="
  FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
    --seed-rfc6979-slot-9a-cert --seed-rfc5903-slot-9d-cert --seed-pinfo >"$fibby_log" 2>&1 &
  fibby_pid=$!
  for _ in $(seq 1 50); do [[ -S $fibby_sock ]] && break; sleep 0.1; done
  [[ -S $fibby_sock ]] || { echo "fibby socket never appeared"; cat "$fibby_log"; exit 1; }

  # Capture runs the live C pivy-tool and records into $workdir (exposed to
  # the sandbox), copied into the repo only after the lane passes.
  capture_env=()
  if [[ {{ mode }} == capture ]]; then
    pivy_out=$(nix build .#pivy --no-link --print-out-paths) || exit 1
    capture_env=(PIGGY_ORACLE_MODE=capture REAL_PIVY_TOOL="$pivy_out/bin/pivy-tool"
      PIVY_ORACLE_CAPTURE_DIR="$workdir/oracle")
  fi

  # sign/ecdh are PIN-gated; the test askpass supplies fibby's PIN to BOTH
  # piggy tool and C pivy-tool (both honour SSH_ASKPASS).
  askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
  env "${capture_env[@]}" \
    PIGGY="$piggy_bin" \
    PCSCLITE_CSOCK_NAME="$fibby_sock" \
    SSH_ASKPASS="$askpass" \
    SSH_ASKPASS_REQUIRE=force \
    DISPLAY="" \
    PIGGY_TEST_FIB_PIN=123456 \
    {{ fence-tmpdir-linux }} \
    BATS_TEST_TIMEOUT=30 bats --allow-local-binding {{ bats-expose-fibby-workdir }} --tap \
    zz-tests_bats/conformance/piggy_tool_fibby.bats || exit 1

  if [[ {{ mode }} == capture ]]; then
    dest="$PWD/zz-tests_bats/fixtures/pivy-oracle/tool-fibby"
    rm -rf "$dest"
    mkdir -p "$(dirname "$dest")"
    cp -r "$workdir/oracle/tool-fibby" "$dest"
    echo "recorded $(find "$dest" -name '*.out' | wc -l) cases into $dest"
  fi

# Differential `piggy tool change-pin`/`change-puk` against C pivy-tool
# (piggy#289 Phase 3, milestone 3.2a). These rotate card credentials, so
# each test brings up its OWN fresh fibby (the bats file calls fibby_up in
# setup, like the in-sandbox t0980 spike); the recipe just supplies the
# binaries and the test askpass env. --allow-local-binding is for the
# per-test pcsc socket. No host-path exposure: fibby runs in-sandbox as a
# child of the test, so it and the test share the sandbox /tmp.
#
# C's answers are frozen fixtures under
# zz-tests_bats/fixtures/pivy-oracle/tool-pin-fibby/ (piggy#285), so the lane
# needs no C binary.
#
# run the fibby-backed differential piggy tool PIN/PUK bats gate
[group('post-build')]
[linux]
test-bats-conformance-tool-pin-fibby: (_lane-pivy-oracle "tool-pin-fibby" "piggy_tool_pin_fibby.bats" "replay")

# Re-record the C pivy-tool answers the tool-pin-fibby lane replays
# (piggy#285), each on a fresh card: the same lane with the live C binary.
#
# re-record the C pivy-tool oracle fixtures for the tool-pin-fibby lane
[group('codemod')]
[linux]
codemod-capture-pivy-oracle-tool-pin-fibby: (_lane-pivy-oracle "tool-pin-fibby" "piggy_tool_pin_fibby.bats" "capture")

# One fibby-backed frozen-oracle lane (piggy#285): run conformance/FILE in
# MODE replay (no C binary) or capture (live C pivy-tool, then copy the
# recordings into fixtures/pivy-oracle/LANE). Each test brings up its own
# fibby in-sandbox; the capture writes under the exposed workdir because the
# sandboxed lane cannot write the repo.
[linux]
_lane-pivy-oracle lane file mode: build-rust
  #!/usr/bin/env bash
  set -uo pipefail
  fibby_bin="$PWD/target/debug/fibby"
  piggy_bin="$PWD/target/debug/piggy"
  [[ -x $fibby_bin ]] || { echo "missing $fibby_bin (build-rust)"; exit 1; }
  workdir=$(mktemp -d /tmp/{{ lane }}-XXXXXX)
  trap 'rm -rf "$workdir"' EXIT
  capture_env=()
  if [[ {{ mode }} == capture ]]; then
    pivy_out=$(nix build .#pivy --no-link --print-out-paths) || exit 1
    capture_env=(PIGGY_ORACLE_MODE=capture REAL_PIVY_TOOL="$pivy_out/bin/pivy-tool"
      REAL_PIVY_BOX="$pivy_out/bin/pivy-box" PIVY_ORACLE_CAPTURE_DIR="$workdir/oracle")
  fi
  askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
  env "${capture_env[@]}" \
    FIBBY_BIN="$fibby_bin" \
    PIGGY="$piggy_bin" \
    SSH_ASKPASS="$askpass" \
    SSH_ASKPASS_REQUIRE=force \
    DISPLAY="" \
    PIGGY_TEST_FIB_PIN=123456 \
    {{ fence-tmpdir-linux }} \
    BATS_TEST_TIMEOUT=60 bats --allow-local-binding {{ bats-expose-fibby-workdir }} --tap \
    zz-tests_bats/conformance/{{ file }} || exit 1
  if [[ {{ mode }} == capture ]]; then
    dest="$PWD/zz-tests_bats/fixtures/pivy-oracle/{{ lane }}"
    rm -rf "$dest"
    cp -r "$workdir/oracle/{{ lane }}" "$dest"
    echo "recorded $(find "$dest" -name '*.out' | wc -l) cases into $dest"
  fi

# `piggy tool factory-reset` conformance (piggy#289 Phase 3 Tier 2 /
# piggy#291): the YubicoPIV RESET (INS 0xFB) that wipes the PIV applet. Each
# test brings up its OWN fresh fibby (fibby_up in setup), some seeded with the
# PIN+PUK already blocked (--seed-pin-puk-blocked) so the reset is permitted.
# Piggy sends the RESET command C sends (from fibby's wire log) and the card
# reads blank, plus precondition + confirmation-gate checks. `expect` (on the
# devShell PATH) drives the interactive /dev/tty `YES` prompt, C's tty-only
# one included. --allow-local-binding is for the per-test pcsc socket; the
# askpass net is set per piggy#35 though factory-reset needs no PIN (its
# precondition is a BLOCKED PIN).
#
# C's RESET command is a frozen fixture under
# zz-tests_bats/fixtures/pivy-oracle/tool-factory-reset-fibby/ (piggy#285),
# so the lane needs no C binary.
#
# run the fibby-backed piggy tool factory-reset bats gate
[group('post-build')]
[linux]
test-bats-conformance-tool-factory-reset-fibby: (_lane-pivy-oracle "tool-factory-reset-fibby" "piggy_tool_factory_reset_fibby.bats" "replay")

# Re-record the C pivy-tool RESET command the tool-factory-reset-fibby lane
# replays (piggy#285), on a fresh card: the same lane with the live C binary.
#
# re-record the C pivy-tool oracle fixtures for the tool-factory-reset-fibby lane
[group('codemod')]
[linux]
codemod-capture-pivy-oracle-tool-factory-reset-fibby: (_lane-pivy-oracle "tool-factory-reset-fibby" "piggy_tool_factory_reset_fibby.bats" "capture")

# Differential `piggy tool set-admin` against C pivy-tool (piggy#289 Phase
# 3, milestone 3.3a). Rotates the card's PIV management key, so each test
# brings up its OWN fresh fibby (fibby_up in setup). set-admin needs no PIN
# (mgmt-key mutual auth, not the PIN), but the askpass safety net is set
# anyway per piggy#35. --allow-local-binding is for the per-test pcsc
# socket; fibby runs in-sandbox as a child of the test.
#
# C's answers and the bytes it wrote to the card are frozen fixtures under
# zz-tests_bats/fixtures/pivy-oracle/tool-admin-fibby/ (piggy#285), so the
# lane needs no C binary.
#
# run the fibby-backed differential piggy tool set-admin bats gate
[group('post-build')]
[linux]
test-bats-conformance-tool-admin-fibby: (_lane-pivy-oracle "tool-admin-fibby" "piggy_tool_admin_fibby.bats" "replay")

# Re-record the C pivy-tool answers and wire bytes the tool-admin-fibby lane
# replays (piggy#285), each on a fresh card: the same lane with the live C
# binary.
#
# re-record the C pivy-tool oracle fixtures for the tool-admin-fibby lane
[group('codemod')]
[linux]
codemod-capture-pivy-oracle-tool-admin-fibby: (_lane-pivy-oracle "tool-admin-fibby" "piggy_tool_admin_fibby.bats" "capture")

# Differential `piggy tool` key-surface ops (write-cert, generate, import)
# against C pivy-tool (piggy#289 Phase 3.4). These mutate slot material, so
# each test brings up its OWN fresh fibby (fibby_up in setup, seeded 9D
# cert). --allow-local-binding is for the per-test pcsc socket; fibby runs
# in-sandbox as a child of the test.
#
# C's answers and the bytes it wrote to the card are frozen fixtures under
# zz-tests_bats/fixtures/pivy-oracle/tool-keys-fibby/ (piggy#285), so the
# lane needs no C binary.
#
# run the fibby-backed differential piggy tool key-surface bats gate
[group('post-build')]
[linux]
test-bats-conformance-tool-keys-fibby: (_lane-pivy-oracle "tool-keys-fibby" "piggy_tool_keys_fibby.bats" "replay")

# Re-record the C pivy-tool answers and wire bytes the tool-keys-fibby lane
# replays (piggy#285), each on a fresh card: the same lane with the live C
# binary.
#
# re-record the C pivy-tool oracle fixtures for the tool-keys-fibby lane
[group('codemod')]
[linux]
codemod-capture-pivy-oracle-tool-keys-fibby: (_lane-pivy-oracle "tool-keys-fibby" "piggy_tool_keys_fibby.bats" "capture")

# recipients add --all-attached against FIBBY (the retired fib card's lane
# moved here, piggy#365; docs/plans/2026-06-15-retire-fib-for-fibby.md).
# Brings up fibby (virtual backend, seeded slot 9D + canonical CHUID/GUID)
# and runs piggy_recipients_add_attached.bats against it: the live
# card is added on top of an existing foreign recipient, and the already-a-
# recipient case is a no-op. The RSA-9D "unsupported" case was dropped (fibby
# is P-256-only; that path is unit-tested — see the bats file's note).
# Pure-Rust card-under-test, no Java/jcardsim/hardware.
#
# run the fibby-backed recipients add --all-attached bats gate
[group('post-build')]
[linux]
test-bats-conformance-recipients-add-attached-fibby: build-rust
  #!/usr/bin/env bash
  set -uo pipefail
  fibby_bin="$PWD/target/debug/fibby"
  [[ -x $fibby_bin ]] || { echo "missing $fibby_bin (build-rust)"; exit 1; }

  workdir=$(mktemp -d /tmp/recipients-add-fibby-XXXXXX)
  fibby_sock="$workdir/pcscd.comm"
  fibby_log="$workdir/fibby.log"
  fibby_pid=""
  cleanup() { [[ -n "$fibby_pid" ]] && kill "$fibby_pid" 2>/dev/null || true; rm -rf "$workdir"; }
  trap cleanup EXIT

  echo "=== Starting fibby (virtual, --seed-rfc5903-slot-9d-cert) ==="
  FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
    --seed-rfc5903-slot-9d-cert >"$fibby_log" 2>&1 &
  fibby_pid=$!
  for _ in $(seq 1 50); do [[ -S $fibby_sock ]] && break; sleep 0.1; done
  [[ -S $fibby_sock ]] || { echo "fibby socket never appeared"; cat "$fibby_log"; exit 1; }

  askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
  PCSCLITE_CSOCK_NAME="$fibby_sock" \
    SSH_ASKPASS="$askpass" \
    SSH_ASKPASS_REQUIRE=force \
    DISPLAY="" \
    PIGGY_TEST_FIB_PIN=123456 \
    {{ fence-tmpdir-linux }} \
    BATS_TEST_TIMEOUT=30 bats --allow-local-binding {{ bats-expose-fibby-workdir }} --tap \
    zz-tests_bats/conformance/piggy_recipients_add_attached.bats

# Fibby-backed `piggy pass init` auto-detect lane (it replaced the retired
# fib card's init lane, piggy#365). Drives
# `piggy pass init` (no-args + explicit -g) against fibby's seeded slot
# 9D (which also installs the canonical CHUID/GUID). PIN-free, no agent.
# [linux]-only like the other fibby lanes (PCSCLITE_CSOCK_NAME redirect
# is a no-op on macOS's PCSC.framework).
#
# run the fibby-backed piggy pass init bats gate
[group('post-build')]
[linux]
test-bats-conformance-init-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_pass_init_fibby.bats

# show-batch against FIBBY (the retired fib card's lane moved here,
# piggy#365). Brings up fibby
# (virtual backend, seeded slot 9D + canonical CHUID/GUID) and runs the
# card-agnostic piggy_pass_show_batch_hardware.bats against it: single-ebox
# decrypt, the single-PIN-across-N guarantee, wrong-card bail-out, and the
# heterogeneous per-ebox failure path — all through show-batch's agentless
# BatchOracle → fibby's 9D ECDH. The wrong-card case seals to a foreign
# *recipient* (a valid off-card P-256 point), so single-card fibby suffices.
# The SIGINT bail-out case is a Rust unit test (#176), not part of this lane.
# Pure-Rust card-under-test, no Java/jcardsim/hardware.
#
# run the fibby-backed pass show-batch bats gate
[group('post-build')]
[linux]
test-bats-conformance-show-batch-fibby: build-rust
  #!/usr/bin/env bash
  set -uo pipefail
  fibby_bin="$PWD/target/debug/fibby"
  piggy_bin="$PWD/target/debug/piggy"
  [[ -x $fibby_bin ]] || { echo "missing $fibby_bin (build-rust)"; exit 1; }

  workdir=$(mktemp -d /tmp/show-batch-fibby-XXXXXX)
  fibby_sock="$workdir/pcscd.comm"
  fibby_log="$workdir/fibby.log"
  fibby_pid=""
  cleanup() { [[ -n "$fibby_pid" ]] && kill "$fibby_pid" 2>/dev/null || true; rm -rf "$workdir"; }
  trap cleanup EXIT

  echo "=== Starting fibby (virtual, --seed-rfc5903-slot-9d-cert) ==="
  FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
    --seed-rfc5903-slot-9d-cert >"$fibby_log" 2>&1 &
  fibby_pid=$!
  for _ in $(seq 1 50); do [[ -S $fibby_sock ]] && break; sleep 0.1; done
  [[ -S $fibby_sock ]] || { echo "fibby socket never appeared"; cat "$fibby_log"; exit 1; }

  echo "=== discover fibby GUID via piggy tool -j list ==="
  guid=$(PCSCLITE_CSOCK_NAME="$fibby_sock" "$piggy_bin" tool -j list | grep -oE '"guid":"[0-9A-Fa-f]{32}"' | head -1 | cut -d'"' -f4)
  [[ -n $guid ]] || { echo "no GUID from fibby"; cat "$fibby_log"; exit 1; }
  echo "  guid: $guid"

  askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
  # Hermetic: an inherited agent socket would let show-batch's agent fallback
  # reach the operator's real agent (and turn the wrong-card bail-out into an
  # agent decrypt failure).
  unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK
  INTEROP_GUID="$guid" \
    PCSCLITE_CSOCK_NAME="$fibby_sock" \
    SSH_ASKPASS="$askpass" \
    SSH_ASKPASS_REQUIRE=force \
    DISPLAY="" \
    PIGGY_TEST_FIB_PIN=123456 \
    {{ fence-tmpdir-linux }} \
    BATS_TEST_TIMEOUT=60 bats --allow-local-binding {{ bats-expose-fibby-workdir }} --tap \
    zz-tests_bats/conformance/piggy_pass_show_batch_hardware.bats

# `piggy secrets reconcile` against FIBBY (FDR 0003): brings up fibby
# (virtual backend, seeded slot 9D + CHUID/GUID) and runs the card-facing
# reconcile contract — one PIN per batch, a card-free steady state, rotation,
# locked-card survival of the old file, ownership conflicts/adopt, --check,
# and orphan release. Hermetic: inherited agent sockets are unset so the
# agent fallback can't reach the operator's real agent.
#
# run the fibby-backed piggy secrets reconcile bats gate
[group('post-build')]
[linux]
test-bats-conformance-secrets-reconcile-fibby: build-rust
  #!/usr/bin/env bash
  set -uo pipefail
  fibby_bin="$PWD/target/debug/fibby"
  piggy_bin="$PWD/target/debug/piggy"
  [[ -x $fibby_bin ]] || { echo "missing $fibby_bin (build-rust)"; exit 1; }

  workdir=$(mktemp -d /tmp/secrets-reconcile-fibby-XXXXXX)
  fibby_sock="$workdir/pcscd.comm"
  fibby_log="$workdir/fibby.log"
  fibby_pid=""
  cleanup() { [[ -n "$fibby_pid" ]] && kill "$fibby_pid" 2>/dev/null || true; rm -rf "$workdir"; }
  trap cleanup EXIT

  echo "=== Starting fibby (virtual, --seed-rfc5903-slot-9d-cert) ==="
  FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
    --seed-rfc5903-slot-9d-cert >"$fibby_log" 2>&1 &
  fibby_pid=$!
  for _ in $(seq 1 50); do [[ -S $fibby_sock ]] && break; sleep 0.1; done
  [[ -S $fibby_sock ]] || { echo "fibby socket never appeared"; cat "$fibby_log"; exit 1; }

  guid=$(PCSCLITE_CSOCK_NAME="$fibby_sock" "$piggy_bin" tool -j list | grep -oE '"guid":"[0-9A-Fa-f]{32}"' | head -1 | cut -d'"' -f4)
  [[ -n $guid ]] || { echo "no GUID from fibby"; cat "$fibby_log"; exit 1; }

  unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK
  INTEROP_GUID="$guid" \
    PCSCLITE_CSOCK_NAME="$fibby_sock" \
    SSH_ASKPASS="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh" \
    SSH_ASKPASS_REQUIRE=force \
    DISPLAY="" \
    PIGGY_TEST_FIB_PIN=123456 \
    {{ fence-tmpdir-linux }} \
    BATS_TEST_TIMEOUT=60 bats --allow-local-binding {{ bats-expose-fibby-workdir }} --tap \
    zz-tests_bats/conformance/piggy_secrets_reconcile_fibby.bats

# Hardware-free Phase 0 smoke for piggy#135: stand up fibby (virtual
# backend, empty slots) and pivy-agent against it, run ssh-add -L,
# assert the substrate works. Runs the C pivy-agent, so it is in
# `test-optional`, not the merge gate (piggy#364); the bats file skips
# if PIVY_AGENT / FIBBY_BIN aren't supplied.
#
# Both binaries come from nix derivations (.#pivy + .#fibby) rather
# than the workspace's target/debug/. This is the same pattern as the
# hardware lane recipes and matches what production users would run;
# the cached store paths are free on repeat invocations.
#
# run the fibby + pivy-agent smoke bats gate
[group('post-build')]
[linux]
test-bats-conformance-fibby-pivy-agent-smoke:
    #!/usr/bin/env bash
    set -euo pipefail
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    # The wrapped piggy (.#default) bakes the real pivy-box on its PATH and
    # the real piggy-ids via PIGGY_IDS_PATH, so the agent-rebox decrypt test
    # (piggy_rebox_decrypts_via_seeded_fibby_slot_9d, the piggy#138 gate)
    # exercises the real crypto path even though common.bash puts mock
    # pivy-box/piggy-ids on PATH.
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIVY_AGENT="$pivy_out/bin/pivy-agent" \
      PIVY_TOOL="$pivy_out/bin/pivy-tool" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_fibby_pivy_agent_smoke.bats

# piggy#135 Phase D: end-to-end SSH-forwarded decrypt lane. Stands up
# fibby + `piggy agent` + piggy-test-sshd and drives a "remote" `piggy pass
# show` over `ssh -A` so the decrypt routes through the forwarded agent
# socket back to piggy agent <-> fibby. No hardware. The wrapped piggy
# (.#default) bypasses common.bash's mock crypto (see the smoke recipe);
# .#piggy-test-sshd is the Go fixture server (#135 Phase A/B). The
# `just debug-ssh-decrypt-via-fibby` recipe is the non-bats scaffold.
#
# run the fibby-backed SSH-forwarded decrypt bats gate
[group('post-build')]
[linux]
test-bats-conformance-piggy-ssh-via-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    sshd_out=$(nix build .#piggy-test-sshd --no-link --print-out-paths)
    FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      SSHD_BIN="$sshd_out/bin/piggy-test-sshd" \
      BATS_TEST_TIMEOUT=90 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_ssh_via_fibby.bats

# piggy#58: prompt-on-demand PIN entry. Drives a slot-9D decrypt at the
# Rust `piggy agent` (via PIGGY_AUTH_SOCK) WITHOUT pushing a PIN first, so
# the agent must fork SSH_ASKPASS on demand. No C binary (piggy#285). Uses
# the wrapped piggy (.#default) over fibby — no hardware,
# no SSH forwarding (unlike piggy-ssh-via-fibby). Agent dev-loop: this is
# the CI gate for the #58 prompt-on-demand work. [linux]-only like the
# other fibby lanes (fibby's PCSCLITE_CSOCK_NAME redirect is ignored by
# macOS's PCSC.framework).
#
# run the fibby-backed prompt-on-demand PIN entry bats gate
[group('post-build')]
[linux]
test-bats-conformance-agent-pin-on-demand:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_agent_pin_on_demand.bats

# piggy#213: N-wide concurrent SSH SIGN burst against the Rust `piggy
# agent` over fibby's seeded slot 9A. Every member of the burst must
# succeed — before the fix, unserialized per-request card sessions raced
# each other and most of the burst got "agent refused operation" (the
# parallel-git-pull storm from the field report). Rust agent only; no
# pivy-agent baseline (the C agent serializes at pcscd's txn lock and is
# tracked separately by piggy#110). [linux]-only like the other fibby
# lanes (PCSCLITE_CSOCK_NAME redirect is a no-op on macOS).
#
# run the fibby-backed concurrent SSH sign burst bats gate
[group('post-build')]
[linux]
test-bats-conformance-agent-concurrent-sign:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    # socat captures the agent's statsd datagrams (piggy#144).
    socat_out=$(nix build --inputs-from . nixpkgs#socat --no-link --print-out-paths)
    # PIGGY satisfies the parent common.bash loader without a cargo build;
    # the test itself drives PIGGY_BIN only.
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      SOCAT_BIN="$socat_out/bin/socat" \
      BATS_TEST_TIMEOUT=120 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_agent_concurrent_sign_fibby.bats

# FDR 0006 phase (c), piggy#382 item 2: the Rust agent lists and signs with
# an Ed25519 PIV key (alg E0) seeded into fibby's yk5.7 model, and the
# sshsig verifies; on the yk5 model the same key is refused, as pre-5.7
# silicon refuses E0. Answers FDR 0006's "does the agent's Ed25519 PIV path
# work end to end". Also mints an Ed25519 card at runtime over fibby's
# control socket (`fibby ctl create`, item 6) and has the agent find it,
# sign with it, and piggy export its attestation. [linux]-only like the
# other fibby lanes.
#
# run the fibby-backed agent Ed25519 PIV sign bats gate
[group('post-build')]
[linux]
test-bats-conformance-agent-ed25519:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_agent_ed25519_fibby.bats

# FDR 0006 phase (d), piggy#383: the holder agent mode over fibby. A
# `piggy agent --holder` mints a key on a fresh virtual card bound to the
# caller's cgroup (`--scope piggy-mint-v1=caller`), the key signs with no
# PIN (the slot is PIN never, item 4), refusals are by name (scope-unbound,
# unknown-scope, not-bound-scope, cap-reached, no-such-key), a retire
# destroys the card, and a bound cgroup directory removed from under the
# staged `--cgroup-root` tears the card down. The sibling-scope refusal
# needs a second cgroup: `just explore-fdr0006-d` and the VM lane.
#
# run the fibby-backed holder mint/retire bats gate
[group('post-build')]
[linux]
test-bats-conformance-holder-mint-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=180 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_holder_mint_fibby.bats

# piggy#397 over fibby: `piggy tool attest-verify <slot>` (the attestation
# checked: F9 signature, chain to a root, key, policy, saved compare) and
# `card export-attestation` for any key slot. fibby attests only generated
# keys and its F9 is self-signed, so the lane generates keys and passes the
# F9 certificate as --root; without --root the embedded Yubico root fails
# the chain point, which the lane asserts too.
#
# run the fibby-backed piggy tool attest-verify bats gate
[group('post-build')]
[linux]
test-bats-conformance-tool-attest-verify-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=120 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_tool_attest_verify_fibby.bats

# piggy#396: the management key off argv, over fibby: `piggy tool
# auth-test` (mutual authentication only, nothing written), `set-admin -`
# (the new key on stdin) and `-K @store` (the current key from the store's
# sealed entry, decrypted through the card under the askpass safety net).
# No C counterpart, so not in the differential admin lane.
#
# run the fibby-backed piggy tool auth-test / set-admin - / -K @store bats gate
[group('post-build')]
[linux]
test-bats-conformance-tool-admin-store-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=120 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_tool_admin_store_fibby.bats

# `piggy card rotate-admin` over fibby (docs/plans/2026-11-19-card-rotate-admin-design.md,
# circus#448): the management-key rotation as one verb. The first rotation
# off the factory key, a later one through the pending entry and its
# promotion, the typed word refused, a refused PIN at the read-back rolled
# back; `-K @store auth-test` is the proof. The word comes on stdin, the
# PIN from the test askpass.
#
# run the fibby-backed piggy card rotate-admin bats gate
[group('post-build')]
[linux]
test-bats-conformance-card-rotate-admin-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=120 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_card_rotate_admin_fibby.bats

# FDR 0007: the guards of `explore-fdr0007-root-cert` with fake tools on
# PATH and no card: CARD=real required, module and provider checked before
# any card read, and a failed step-1 read (rollback or evidence) bails out
# before the card is asked to sign. Shell and just only, no nix build.
#
# run the explore-fdr0007-root-cert guard bats (fake tools, no card)
[group('post-build')]
[linux]
test-bats-conformance-root-cert-guard:
    # The test is told which justfile to drive: a path derived from the test
    # file's own location can point at a store snapshot of the tree.
    PIGGY_JUSTFILE="$PWD/justfile" BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/explore_fdr0007_root_cert_guard.bats

# FDR 0007: the guards of `explore-fdr0007-chain-holder` and
# `explore-fdr0007-chain-card` with fake tools on PATH and no card: the
# card half refuses without CARD=real, a bad GUID, a missing request or no
# agent socket before any call, bails out on a failed S0 read before the
# Enter prompt, and on a good run writes the two profiles and drives sign,
# issue, the act checks and the read-back in order; the holder half's
# dry-run calls nothing. Shell and just only, no nix build.
#
# run the explore-fdr0007-chain guard bats (fake tools, no card)
[group('post-build')]
[linux]
test-bats-conformance-chain-guard:
    PIGGY_JUSTFILE="$PWD/justfile" BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/explore_fdr0007_chain_guard.bats

# FDR 0007 phase (ii), piggy#391: `piggy ca root-cert` off the card: the
# profile is the only input and every refusal answers from the `ca` exit
# table (2 usage, 3 profile, 6 issuer card absent), with nothing on stdout
# and no PIN prompt. The signature itself runs against fibby's slot 82
# (modelled since piggy#399) in the fibby-backed lane; the unit tests sign
# in software.
#
# run the `piggy ca root-cert` refusals bats gate (no card)
[group('post-build')]
[linux]
test-bats-conformance-ca-root-cert:
    #!/usr/bin/env bash
    set -euo pipefail
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIGGY="$piggy_out/bin/piggy" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_ca_root_cert.bats

# FDR 0007 phase (ii), piggy#391, over fibby's slot 82 (piggy#399): a P-256
# key generated PIN-always/touch-always signs its own root, and the card's
# 9C seals the piggy-certificate-v1 act through a card agent (RFC 0012
# §3.2); openssl checks the root, `piggy act` the act, write-cert puts it
# back. fibby's F9 is self-signed, so the profile's attestation_root names
# it. Refused before any prompt: no attestation_root, an empty slot, an
# imported key, a wrong policy, a P-384 key, a plain ssh-agent or none; a
# cancelled act prompt drops the certificate.
#
# run the fibby-backed `piggy ca root-cert` slot-82 bats gate
[group('post-build')]
[linux]
test-bats-conformance-ca-root-cert-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=120 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_ca_root_cert_fibby.bats

# The SSH certificate authority, slot 83, over fibby and a card agent (lane 1
# of the delegation sprint): `ssh-keygen -U -s` signs an OpenSSH user
# certificate behind a PIN dialog of kind ssh-certificate that says what it
# certifies; the signature verifies against a cert-authority line; slot 83's
# PIN is asked every time while 9A's stays cached; a lifetime over 24 hours,
# no end, a host certificate and no principal are refused before any prompt;
# slot 82 refuses an OpenSSH certificate and slot 83 an sshsig.
#
# run the fibby-backed SSH certificate authority (slot 83) bats gate
[group('post-build')]
[linux]
test-bats-conformance-ssh-ca-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=120 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_ssh_ca_fibby.bats

# FDR 0007 phase (ii), piggy#391, over fibby's slot 82 (piggy#399): the root
# `piggy ca root-cert` makes is written back, then `piggy ca issue` signs a
# leaf and `piggy ca sign` an intermediate under it, each with its
# piggy-certificate-v1 act sealed by the card's 9C through a card agent
# (RFC 0012 §3.2); openssl checks the chain, `piggy act` the act, and the
# rate-limit stamp and audit line are read back. Refused before any prompt,
# nothing written: an unknown profile (3), a profile of the wrong kind (2),
# an empty, junk or Ed25519 request (4), names outside the profile (5), a
# P-384 request (1), a taken act path (1), a second run in the window (7).
#
# run the fibby-backed `piggy ca sign` and `piggy ca issue` bats gate
[group('post-build')]
[linux]
test-bats-conformance-ca-issue-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=180 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_ca_issue_fibby.bats

# FDR 0007 phase (iii-b), piggy#392: the whole chain on virtual cards with
# the holder issuing the leaf. fibby #1 is the operator's card (root-cert
# in slot 82, 9C for the acts, a card agent), fibby #2 a holder bound to
# the test's cgroup: holder mint + `ca csr`, the card's `ca sign` under a
# one-hour intermediate profile, `ca leaf-csr`, then `ca issue` with a
# holder profile through the holder: no PIN, no act, leaf + intermediate
# out, notAfter the intermediate's, `ca verify` and openssl agreeing.
# Refused, nothing written: a non-holder agent or no agent (6), an
# unserved key (6), --act-out (2), `sign` with the holder profile (3), a
# profile naming outside the intermediate's constraints (3).
#
# run the fibby-backed holder-issued leaf bats gate (`piggy ca issue` through the holder)
[group('post-build')]
[linux]
test-bats-conformance-ca-issue-holder-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=240 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_ca_issue_holder_fibby.bats

# FDR 0007 phase (iii-a), piggy#392: `piggy ca csr` for a holder-held
# intermediate key. A holder agent over fibby with the intermediate scope
# as a fixed cgroup (the test's own, standing in for the issuance unit),
# a P-256 mint under it, the request signed through the agent with no PIN
# and verified by openssl, its key equal to the minted key; an Ed25519 key
# and an unserved key refused by name.
#
# run the fibby-backed `piggy ca csr` bats gate
[group('post-build')]
[linux]
test-bats-conformance-ca-csr-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=120 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_ca_csr_fibby.bats

# FDR 0007: `piggy ca leaf-csr`, the card-free leaf key and request for a
# host with no holder and no card: a fresh P-256 key file (PKCS#8 PEM,
# 0600, never written over) and the one-CN PKCS#10 request, openssl the
# oracle for the self-signature and the key equality. Refused with nothing
# written: a key file that exists (1), a CN that is not a plain DNS name
# (2); a request that cannot be written takes the new key with it.
#
# run the `piggy ca leaf-csr` bats gate (no card)
[group('post-build')]
[linux]
test-bats-conformance-ca-leaf-csr:
    #!/usr/bin/env bash
    set -euo pipefail
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIGGY="$piggy_out/bin/piggy" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_ca_leaf_csr.bats

# FDR 0007: `piggy ca verify` and `piggy cert show` over chains openssl
# makes (root with name constraints, intermediate, leaf): a good chain
# passes as TAP, also from a chain file; a foreign name, a wrong key and a
# tampered leaf fail with the check named; junk is exit 4; `cert show`
# prints the fields and the DER sha256 openssl computes. No card.
#
# run the `piggy ca verify` and `piggy cert show` bats gate (no card)
[group('post-build')]
[linux]
test-bats-conformance-ca-verify:
    #!/usr/bin/env bash
    set -euo pipefail
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIGGY="$piggy_out/bin/piggy" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_ca_verify.bats

# piggy#299: a sealed pigpen document opens through the real Rust `piggy
# agent` over fibby's slot 9D, driven by the Go surface a consumer uses
# (pigpen.Document.Open + agent.AgentECDHOracle, via the conformance
# binary's `pigpen-open` mode). The Go unit tests only reach an in-process
# stand-in agent. [linux]-only like the other fibby lanes.
#
# run the fibby-backed pigpen Open-through-the-agent bats gate
[group('post-build')]
[linux]
test-bats-conformance-pigpen-open-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    conformance_out=$(nix build .#piggy.tests.conformance --no-link --print-out-paths)
    # PIGGY satisfies the parent common.bash loader without a cargo build;
    # the test itself drives PIGGY_BIN only.
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      CONFORMANCE_BIN="$conformance_out/bin/piggy-agent-conformance" \
      BATS_TEST_TIMEOUT=120 bats --no-sandbox --tap \
      zz-tests_bats/conformance/pigpen_open_agent_fibby.bats

# piggy#215 step 3: `piggy agent --upstream` end to end — fibby-backed
# native 9A keys AND a proxied stock OpenSSH ssh-agent on one socket.
# Merged listing order, native vs routed signs, a mixed concurrent
# burst, dead-upstream degradation, and add_identity routing/refusal.
# [linux]-only like the other fibby lanes (PCSCLITE_CSOCK_NAME redirect
# is a no-op on macOS).
#
# run the fibby-backed piggy agent --upstream bats gate
[group('post-build')]
[linux]
test-bats-conformance-agent-upstream:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    # PIGGY satisfies the parent common.bash loader without a cargo build;
    # the test itself drives PIGGY_BIN only.
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=120 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_agent_upstream_fibby.bats

# piggy#242/#177 multi-card gate: ONE fibby serving TWO virtual cards
# (--card groups), fronted by `piggy agent -A`. Both cards' identities
# enumerate with distinct GUIDs; signs route to the right card; the PIN
# is prompted once PER card (the per-GUID PinCache) with no wrong-PIN
# VERIFY on the wire. [linux]-only like the other fibby lanes.
#
# run the fibby-backed multi-card piggy agent bats gate
[group('post-build')]
[linux]
test-bats-conformance-agent-multicard:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    # PIGGY satisfies the parent common.bash loader without a cargo build;
    # the test itself drives PIGGY_BIN only.
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=120 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_agent_multicard_fibby.bats

# run the fibby runtime hot-plug (control socket + `fibby ctl`) bats gate (piggy#130)
[group('post-build')]
[linux]
test-bats-conformance-fibby-hotplug:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=120 bats --no-sandbox --tap \
      zz-tests_bats/conformance/fibby_hotplug_fibby.bats

# Fibby-backed end-to-end gate for `age-plugin-piggy`: derive the age
# recipient/identity from fibby's seeded slot-9D key (`generate`), encrypt a
# secret with `age`, then decrypt it back through piggy-agent's ecdh@joyent.com
# against fibby with on-demand PIN. Confirms on real card-side crypto the X-coordinate
# assumption the Rust unit tests pin only in software. Serves the
# age-plugin-piggy dev loop (Phase 2).
#
# run the fibby-backed age-plugin-piggy bats gate
[group('post-build')]
[linux]
test-bats-conformance-age-plugin-piggy:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    age_out=$(nix build .#age --no-link --print-out-paths)
    FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      AGE_BIN="$age_out/bin/age" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/age_plugin_piggy_fibby.bats

# Fibby-backed gate for `piggy sign-bytes` (piggy#190): seed slot 9A on fibby,
# sign a message direct-PCSC, and verify the signature with openssl against the
# slot-9A pubkey (read back via `piggy list --format=ssh`). Confirms real card
# crypto + the DER framing (the fibby DER confirmation from the papi#15
# co-design). sign-bytes is agentless, so no pivy-agent is needed. [linux]-only
# like the other fibby lanes (PCSCLITE_CSOCK_NAME redirect is a no-op on macOS).
#
# run the fibby-backed piggy sign-bytes bats gate
[group('post-build')]
[linux]
test-bats-conformance-sign-bytes-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    # The jsonrpc-frontend lane supplies the PIN via the scripted
    # card-frontend-server test helper (cargo-built, mirroring fibby-wait-ready).
    cargo build -p card-frontend-server --quiet
    # PIGGY satisfies the parent common.bash loader without a cargo build.
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      CARD_FRONTEND_BIN="$PWD/target/debug/card-frontend-server" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_sign_bytes_fibby.bats

# Fibby-backed gate for the agentless-host fallback: with NO local PCSC (dead
# PCSCLITE_CSOCK_NAME) but a forwarded piggy-agent holding fibby, both
# `piggy sign-bytes` and `piggy pass show-batch` must fall back to the agent
# instead of failing. Drives the agent's on-demand PIN via the test askpass.
# [linux]-only like the other fibby lanes (PCSCLITE_CSOCK_NAME redirect).
#
# run the fibby-backed agentless-host fallback bats gate
[group('post-build')]
[linux]
test-bats-conformance-agentless-fallback-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_agentless_fallback_fibby.bats

# Fibby-backed gate for `piggy list` blank-card discovery (piggy#193): a no-seed
# yk5 fibby card presents as uninitialized (no CHUID); assert `piggy list`
# surfaces it as a card-level `uninitialized` ndjson record with serial, and that
# a seeded card is NOT mislabelled; plus (piggy#87) `piggy list` and `piggy pass
# recipients list-available` with no card, their record shape, the recipient
# subset and sort order. Agentless; [linux]-only like the fibby lanes.
#
# run the fibby-backed piggy list blank-card discovery bats gate
[group('post-build')]
[linux]
test-bats-conformance-list-blank-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_list_blank_fibby.bats \
      zz-tests_bats/conformance/piggy_list_fibby.bats

# Fibby-backed gate for `piggy health`'s healthy path (piggy#158): fibby
# seeded 9A + 9D + CHUID and a Rust `piggy agent` on it give no failing
# point and an all-green ndjson summary; an agent serving a blank card beside
# the provisioned one fails the cross-check with its restart hint. The
# degraded paths are t0800-health.bats in the default lane. [linux]-only like
# the other fibby lanes.
#
# run the fibby-backed piggy health all-green bats gate
[group('post-build')]
[linux]
test-bats-conformance-health-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    # PIGGY satisfies the parent common.bash loader without a cargo build;
    # the test itself drives PIGGY_BIN only.
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=120 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_health_fibby.bats

# Fibby-backed gate for `piggy card init` (piggy#194): provision a blank yk5
# fibby end to end through BOTH interaction frontends — the tty/askpass default
# and the JSON-RPC binding driven by the scripted `card-frontend-server` test
# helper (cargo-built on demand, mirroring `fibby-wait-ready`). Asserts `piggy
# list` then shows the card provisioned (CHUID GUID + 9D recipient). [linux]-
# only like the other fibby lanes (PCSCLITE_CSOCK_NAME redirect is a no-op on
# macOS's PCSC.framework).
#
# run the fibby-backed piggy card init bats gate
[group('post-build')]
[linux]
test-bats-conformance-card-init-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    cargo build -p card-frontend-server --quiet
    # PIGGY satisfies the parent common.bash loader without a cargo build.
    # PIGGY_IDS_BIN reads the backup card's 9D recipient; `piggy tool
    # set-admin` proves a recovered management key admin-authenticates
    # (piggy#258 seal cases), so the gate needs no C pivy (piggy#364).
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      PIGGY_IDS_BIN="$piggy_out/libexec/piggy/piggy-ids" \
      CARD_FRONTEND_BIN="$PWD/target/debug/card-frontend-server" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_card_init_fibby.bats

# Fibby-backed gate for `piggy card add-key` (piggy#303, FDR 0006): against an
# already-provisioned virtual card (seeded CHUID + 9A + 9D, `--auto-touch`),
# add the 9C operator-act key and regenerate 9A through the tty/askpass
# frontend and through `card.add_key` over `piggy manage --jsonrpc` (the
# scripted `manage-client`, cargo-built on demand), asserting the policy each
# new key reads back with, the occupied-slot and never-9D refusals, and that
# the other slots keep their keys. [linux]-only like the other fibby lanes
# (PCSCLITE_CSOCK_NAME redirect is a no-op on macOS's PCSC.framework).
#
# run the fibby-backed piggy card add-key bats gate
[group('post-build')]
[linux]
test-bats-conformance-card-add-key-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    cargo build -p manage-client --quiet
    # PIGGY satisfies the parent common.bash loader without a cargo build.
    # PIGGY_IDS_BIN reads the backup card's 9D recipient for the
    # --management-key-from-store case.
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      PIGGY_IDS_BIN="$piggy_out/libexec/piggy/piggy-ids" \
      MANAGE_CLIENT_BIN="$PWD/target/debug/manage-client" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_card_add_key_fibby.bats

# Fibby-backed gate for `operator-act@piggy` and `piggy operator-sign`
# (piggy#303, RFC 0012): the Rust agent over a virtual card whose 9C key was
# generated on the card (so fibby attests it PIN always, touch always), asked
# for operator acts by the CLI and by the raw `operator-act-probe` (cargo-built
# on demand). One bats file per row of the RFC's conformance table; FILES
# narrows the run to some of them. [linux]-only like the other fibby lanes.
#
# run the fibby-backed operator-act bats gate
[group('post-build')]
[linux]
test-bats-conformance-operator-act *FILES:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    cargo build -p operator-act-probe --quiet
    files="{{ FILES }}"
    # PIGGY satisfies the parent common.bash loader without a cargo build.
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      OPERATOR_ACT_PROBE_BIN="$PWD/target/debug/operator-act-probe" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      ${files:-zz-tests_bats/conformance/operator_act_*.bats zz-tests_bats/conformance/attestation_bundle.bats}

# FDR 0007 phase (i), piggy#393: the X.509 profile builders in piggy-piv
# (root, intermediate, leaf) checked with `openssl verify`, including the
# negative name, IP and widened/unconstrained-intermediate cases. The
# certificates come from the test-only `x509-profile-probe` (cargo-built on
# demand, never shipped). No card, no PIN prompt.
#
# run the X.509 profile openssl bats gate
[group('post-build')]
test-bats-conformance-x509-profile:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build -p x509-profile-probe --quiet
    X509_PROFILE_PROBE_BIN="$PWD/target/debug/x509-profile-probe" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/x509_profile_openssl.bats

# The operator-act lanes against the cargo-built piggy and fibby instead of the
# nix-built ones: the fast loop while changing the agent or the lanes. The gate
# is test-bats-conformance-operator-act.
#
# run the operator-act bats lanes against target/debug binaries
[group('debug')]
[linux]
debug-operator-act-local *FILES: build-rust
    #!/usr/bin/env bash
    set -euo pipefail
    files="{{ FILES }}"
    PIGGY="$PWD/target/debug/piggy" \
      FIBBY_BIN="$PWD/target/debug/fibby" \
      PIGGY_BIN="$PWD/target/debug/piggy" \
      OPERATOR_ACT_PROBE_BIN="$PWD/target/debug/operator-act-probe" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      ${files:-zz-tests_bats/conformance/operator_act_*.bats zz-tests_bats/conformance/attestation_bundle.bats}

# Fibby-backed gate for `piggy manage --jsonrpc` (piggy#201, RFC 0007): drive
# the headless command server end to end against a virtual fibby card through
# the scripted `manage-client` test peer (cargo-built on demand, mirroring
# `card-frontend-server`) — card.init over BOTH stdio and an AF_UNIX socket,
# a real slot-9A sign_bytes whose DER output openssl verifies, and card.list.
# [linux]-only like the other fibby lanes (PCSCLITE_CSOCK_NAME redirect is a
# no-op on macOS's PCSC.framework).
#
# run the fibby-backed piggy manage --jsonrpc bats gate
[group('post-build')]
[linux]
test-bats-conformance-manage-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    cargo build -p manage-client --quiet
    FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      MANAGE_CLIENT_BIN="$PWD/target/debug/manage-client" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_manage_fibby.bats

# Fibby-backed gate for `recipients sync` with NO file: re-encrypt the store
# (whole or `-p` subtree) to the current piggy-ids recipients, then prove the
# result still decrypts through the agent <-> fibby slot-9D rebox path. The
# wrapped piggy (.#default, real pivy-box + piggy-ids) bypasses common.bash's
# mock crypto so the re-encrypt produces real fresh ciphertext. No hardware.
# [linux]-only like the other fibby lanes (PCSCLITE_CSOCK_NAME redirect is a
# no-op on macOS's PCSC.framework).
#
# run the fibby-backed recipients sync bats gate
[group('post-build')]
[linux]
test-bats-conformance-recipients-sync-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_recipients_sync_fibby.bats

# Fibby-backed proof that `piggy pass show -r` annotates each ebox with its
# REAL recipient, read offline from the ebox wire header (no card/PIN). The
# wrapped piggy (.#default, real pivy-box + piggy-ids) writes genuine eboxes via
# init/insert so the rendered markl prefix can be cross-checked against the
# card's recipient in piggy-ids. Mock-mode coverage (the [?] degrade path) lives
# in t0020-show.bats. [linux]-only like the other fibby lanes (PCSCLITE_CSOCK_NAME
# redirect is a no-op on macOS's PCSC.framework).
#
# run the fibby-backed piggy pass show -r recipients bats gate
[group('post-build')]
[linux]
test-bats-conformance-pass-ls-recipients-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_pass_ls_recipients_fibby.bats

# Hardware lane for the C pivy-agent built from vendor/pivy/. Runs
# pivy_agent_hardware.bats against the user's plugged-in PIV card.
# Read-only PIN-free operations (REQUEST_IDENTITIES). Verifies the
# piggy#107 (piggy#105 step 3) state-machine plumbing doesn't break
# the simple identity-listing case. Opt-in — not part of the default
# `just test` lane. Requires a real card plugged in.
#
# run the C pivy-agent hardware bats lane against a plugged-in PIV card
[group('post-build')]
test-bats-conformance-pivy-agent-hardware: build-rust
    #!/usr/bin/env bash
    set -euo pipefail
    # Build the C pivy-agent binary (and its wrapper) on demand and
    # resolve its store path without creating a `./result-pivy`
    # symlink in the worktree. The package is exposed as
    # `pivy` (see flake.nix); nix caches aggressively so repeat
    # invocations are free.
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
    # PIGGY_TEST_REAL_CARD gates the entire lane (see the bats
    # setup()). PIGGY_TEST_FIB_PIN is DELIBERATELY NOT set — these
    # tests assert no PIN prompt occurs, so the askpass helper must
    # refuse rather than supply a PIN.
    PIVY_AGENT="$pivy_out/bin/pivy-agent" \
      PIGGY_TEST_REAL_CARD=1 \
      SSH_ASKPASS="$askpass" \
      SSH_ASKPASS_REQUIRE=force \
      DISPLAY="" \
      BATS_TEST_TIMEOUT=30 bats --no-sandbox --tap \
      zz-tests_bats/conformance/pivy_agent_hardware.bats

# Run the given bats FILES outside the sandbox against target/debug/piggy —
# the fast single-file iteration path.
#
# run the given bats FILES outside the sandbox
[group('post-build')]
test-bats-file *FILES: build-rust
    BATS_TEST_TIMEOUT=30 bats --no-sandbox --tap {{FILES}}

# Survey (and optionally kill) bats / fibby / piggy processes left over from
# a wedged local bats run — a background fibby that keeps bats' fd 3 open
# makes bats wait forever (piggy#164 harness-card bring-up). KILL=1 kills them.
#
# list leftover bats/fibby/piggy processes from a wedged local bats run; KILL=1 kills them
[group('debug')]
debug-stale-bats-procs KILL="0":
    #!/usr/bin/env bash
    set -uo pipefail
    ps -eo pid,ppid,etimes,stat,cmd | grep -E '(^|/)(bats|bats-exec|fibby|piggy) |fibby --socket|bats-exec-test' | grep -v grep || true
    if [[ "{{KILL}}" == 1 ]]; then
      ps -eo pid,cmd | grep -E 'bats-exec-(test|file|suite)|fibby --socket /tmp/pf\.' | grep -v grep | awk '{print $1}' | xargs -r kill
      echo "killed"
    fi

# run the Rust test suite (cargo test), forwarding ARGS
[group('post-build')]
test-rust *ARGS:
    cargo test {{ARGS}}

# hogtie's whole suite, the binary tests included (they need the
# `test-harness` feature, so plain `test-rust` skips them); the merge gate
# runs the same suite inside `nix build .#hogtie`.
#
# run every hogtie test, the binary tests with the test harness, forwarding ARGS
[group('post-build')]
test-rust-hogtie *ARGS:
    cargo test -p hogtie --features test-harness {{ARGS}}

# Mutation pass over hogtie's refusals: apply each mutant in
# crates/hogtie/testdata/mutants.tsv (a literal one-place edit) to a scratch
# copy of the crate and run every hogtie test; each mutant must turn a test
# red. Prints TAP; a SURVIVED mutant is an untested refusal, a STALE one no
# longer matches the source, NOCOMPILE is a mutant that needs rewriting.
#
# break each hogtie refusal on purpose and check a test goes red (ONLY: an
# extended regex over mutant ids, to run some of them)
[group('explore')]
explore-hogtie-mutants only="":
    #!/usr/bin/env bash
    set -uo pipefail
    only='{{ only }}'
    src=crates/hogtie
    work=$(mktemp -d "$PWD/.tmp/hogtie-mutants.XXXXXX")
    export CARGO_TARGET_DIR="$PWD/target/hogtie-mutants"
    nl=$'\n'
    n=0 killed=0 survived=() stale=() nocompile=()
    while IFS=$'\t' read -r id file from to; do
      [[ -z $id || $id == \#* ]] && continue
      [[ -n $only && ! $id =~ $only ]] && continue
      n=$((n + 1))
      from=${from//\\n/$nl} to=${to//\\n/$nl}
      rm -rf "$work/hogtie"
      cp -r "$src" "$work/hogtie"
      printf '\n[workspace]\n' >>"$work/hogtie/Cargo.toml"
      cp Cargo.lock "$work/hogtie/Cargo.lock"
      f="$work/hogtie/$file"
      text=$(<"$f")
      rest=${text//"$from"/}
      count=$(((${#text} - ${#rest}) / ${#from}))
      if [[ $count != 1 ]]; then
        echo "not ok $n - $id # STALE: $count matches"
        stale+=("$id")
        continue
      fi
      printf '%s\n' "${text/"$from"/"$to"}" >"$f"
      log="$work/$id.log"
      if (cd "$work/hogtie" && cargo test --offline -q --features test-harness) >"$log" 2>&1; then
        echo "not ok $n - $id # SURVIVED"
        survived+=("$id")
      elif grep -q '^error\[E\|^error: could not compile' "$log"; then
        echo "not ok $n - $id # NOCOMPILE (see $log)"
        nocompile+=("$id")
      else
        echo "ok $n - $id killed"
        killed=$((killed + 1))
      fi
    done <"$src/testdata/mutants.tsv"
    echo "1..$n"
    echo "# $n mutants: $killed killed; survived: ${survived[*]:-none}; stale: ${stale[*]:-none}; nocompile: ${nocompile[*]:-none}"
    [[ ${#survived[@]} == 0 && ${#stale[@]} == 0 && ${#nocompile[@]} == 0 ]]

# Mutation pass over the SSH CA slot gate (lane 1): apply each mutant in
# crates/piggy/testdata/ca-gate-mutants.tsv (a literal one-place edit) to a
# scratch copy of the workspace and run that mutant's crate tests (lib and
# integration, not the bats lanes); each should turn a test red. Prints TAP;
# a SURVIVED mutant is a refusal no unit test pins (it may still be pinned by
# the fibby lane: run that for the survivors), STALE no longer matches the
# source, NOCOMPILE needs rewriting. Modelled on explore-hogtie-mutants.
#
# break each SSH CA slot refusal on purpose and check a test goes red
[group('explore')]
explore-ca-gate-mutants:
    #!/usr/bin/env bash
    set -uo pipefail
    tsv=crates/piggy/testdata/ca-gate-mutants.tsv
    work=$(mktemp -d "$PWD/.tmp/ca-gate-mutants.XXXXXX")
    export CARGO_TARGET_DIR="$PWD/target/ca-gate-mutants"
    nl=$'\n'
    n=0 killed=0 survived=() stale=() nocompile=()
    while IFS=$'\t' read -r id crate file from to; do
      [[ -z $id || $id == \#* ]] && continue
      n=$((n + 1))
      from=${from//<NL>/$nl} to=${to//<NL>/$nl}
      rm -rf "$work/ws"
      mkdir "$work/ws"
      cp -r crates Cargo.toml Cargo.lock version.env "$work/ws/"
      f="$work/ws/$file"
      text=$(<"$f")
      rest=${text//"$from"/}
      count=$(((${#text} - ${#rest}) / ${#from}))
      if [[ $count != 1 ]]; then
        echo "not ok $n - $id # STALE: $count matches"
        stale+=("$id")
        continue
      fi
      printf '%s\n' "${text/"$from"/"$to"}" >"$f"
      log="$work/$id.log"
      if (cd "$work/ws" && cargo test --offline -q -p "$crate") >"$log" 2>&1; then
        echo "not ok $n - $id # SURVIVED"
        survived+=("$id")
      elif grep -q '^error\[E\|^error: could not compile' "$log"; then
        echo "not ok $n - $id # NOCOMPILE (see $log)"
        nocompile+=("$id")
      else
        echo "ok $n - $id killed"
        killed=$((killed + 1))
      fi
    done <"$tsv"
    echo "1..$n"
    echo "# $n mutants: $killed killed; survived: ${survived[*]:-none}; stale: ${stale[*]:-none}; nocompile: ${nocompile[*]:-none}"
    [[ ${#survived[@]} == 0 && ${#stale[@]} == 0 && ${#nocompile[@]} == 0 ]]

# The PIN cache table's build-time checks, in the gate (piggy#404): a scratch
# copy of the workspace is `cargo check`ed with a fleet's own table swapped in
# (pin_cache_override.rs): a good one must compile, and one that makes slot 83
# cacheable, one that names a slot twice, and one that is not a table at all
# must each FAIL, the first two on the const check's own message. Cheap (check,
# not build or test); `explore-pin-cache-override` is the same through nix and
# the checkPhase, and slower.
#
# cargo check a scratch copy with good and refused PIN cache tables
[group('test')]
test-pin-cache-table-checks:
    #!/usr/bin/env bash
    set -uo pipefail
    mkdir -p .tmp
    work="$(mktemp -d "$PWD/.tmp/pin-cache-checks.XXXXXX")"
    trap 'rm -rf "$work"' EXIT
    export CARGO_TARGET_DIR="$PWD/target/pin-cache-checks"
    cp -r crates Cargo.toml Cargo.lock version.env "$work/"
    over="$work/crates/piggy/src/cmd/agent/pin_cache_override.rs"
    attempt() { # BODY -> status, output in $out
      printf 'use super::CacheRule;\npub const PIN_CACHE_OVERRIDE: Option<&[(u8, CacheRule)]> = %s;\n' "$1" >"$over"
      out=$(cd "$work" && cargo check --offline -q -p piggy 2>&1)
    }
    n=0 bad=0
    ok() { n=$((n + 1)); echo "ok $n - $1"; }
    no() { n=$((n + 1)); bad=1; echo "not ok $n - $1"; echo "$out" | tail -n 12 | sed 's/^/# /'; }
    attempt 'Some(&[(0x9A, CacheRule::idle_secs(3600))])' && ok "a good table compiles" || no "a good table compiles"
    attempt 'Some(&[(0x83, CacheRule::idle_secs(60))])' \
      && no "slot 83 cacheable is refused" \
      || { grep -q 'makes slot 82 or 83 cacheable' <<<"$out" && ok "slot 83 cacheable fails the build on the check" || no "slot 83 cacheable fails on the check"; }
    attempt 'Some(&[(0x9A, CacheRule::idle_secs(60)), (0x9A, CacheRule::Never)])' \
      && no "a slot named twice is refused" \
      || { grep -q 'names a slot twice' <<<"$out" && ok "a slot named twice fails the build on the check" || no "a slot named twice fails on the check"; }
    attempt 'Some(&[(0x9A, 60)])' \
      && no "a table of the wrong shape is refused" \
      || { grep -q 'E0308' <<<"$out" && ok "a table of the wrong shape fails the build on a type error" || no "a table of the wrong shape fails on a type error"; }
    echo "1..$n"
    exit $bad

# Build piggy-rs for real with a fleet's own PIN cache table (piggy#404, the
# Nix package argument pinCachePolicy): a throwaway table (9A for an hour) must
# build and pass the crate's tests, and a table that makes slot 83 cacheable,
# or names a slot twice, must FAIL the build with the const check's message.
# New files must be tracked (git add) for nix to see them.
#
# build piggy-rs with a throwaway pinCachePolicy, and with two refused ones
[group('explore')]
[linux]
explore-pin-cache-override:
    #!/usr/bin/env bash
    set -uo pipefail
    mkdir -p .tmp
    dir="$(mktemp -d "$PWD/.tmp/pin-cache-override.XXXXXX")"
    attr() {
      nix build --impure --no-link --print-out-paths --expr \
        "(builtins.getFlake \"git+file://$PWD\").packages.\${builtins.currentSystem}.piggy-rs.withPinCachePolicy $1"
    }
    cat >"$dir/ok.rs" <<'EOF'
    use super::CacheRule;
    pub const PIN_CACHE_OVERRIDE: Option<&[(u8, CacheRule)]> =
        Some(&[(0x9A, CacheRule::idle_secs(3600))]);
    EOF
    cat >"$dir/ca.rs" <<'EOF'
    use super::CacheRule;
    pub const PIN_CACHE_OVERRIDE: Option<&[(u8, CacheRule)]> =
        Some(&[(0x83, CacheRule::idle_secs(60))]);
    EOF
    cat >"$dir/twice.rs" <<'EOF'
    use super::CacheRule;
    pub const PIN_CACHE_OVERRIDE: Option<&[(u8, CacheRule)]> =
        Some(&[(0x9A, CacheRule::idle_secs(60)), (0x9A, CacheRule::Never)]);
    EOF
    echo "# the good table: must build and pass its tests"
    attr "$dir/ok.rs" || { echo "not ok - the good table did not build"; exit 1; }
    echo "ok - the good table builds and passes the crate's tests"
    for bad in ca twice; do
      if out=$(attr "$dir/$bad.rs" 2>&1); then
        echo "not ok - the $bad table BUILT"; exit 1
      fi
      grep -qE "makes slot 82 or 83 cacheable|names a slot twice" <<<"$out" \
        || { echo "not ok - the $bad table failed, but not on the check: $out"; exit 1; }
      echo "ok - the $bad table fails the build on the const check"
    done

# The mutants explore-ca-gate-mutants leaves alive because only the fibby lane
# can see them: apply each named mutant (ids from the same TSV) to a scratch
# copy of the tree (no .git, target or .tmp, so nix treats it as a path
# flake) and run the SSH CA lane there; each must turn a lane test red.
#
# run the fibby SSH CA lane against the named CA gate mutants
[group('explore')]
explore-ca-gate-lane-mutants +IDS:
    #!/usr/bin/env bash
    set -uo pipefail
    tsv=crates/piggy/testdata/ca-gate-mutants.tsv
    nl=$'\n'
    work=$(mktemp -d "$PWD/.tmp/ca-gate-lane-mutants.XXXXXX")
    survived=() stale=() killed=()
    for want in {{IDS}}; do
      line=$(grep -P "^\Q$want\E\t" "$tsv") || { echo "no mutant $want"; stale+=("$want"); continue; }
      IFS=$'\t' read -r id crate file from to <<<"$line"
      from=${from//<NL>/$nl} to=${to//<NL>/$nl}
      rm -rf "$work/tree"
      mkdir "$work/tree"
      tar --exclude=./.git --exclude=./target --exclude=./.tmp --exclude=./.worktrees --exclude=./.spinclass --exclude=./result -cf - . | tar -xf - -C "$work/tree"
      f="$work/tree/$file"
      text=$(<"$f")
      rest=${text//"$from"/}
      count=$(((${#text} - ${#rest}) / ${#from}))
      if [[ $count != 1 ]]; then
        echo "not ok - $id # STALE: $count matches"
        stale+=("$id")
        continue
      fi
      printf '%s\n' "${text/"$from"/"$to"}" >"$f"
      # Its own git repository, so nix sees the scratch tree (not the worktree's
      # untracked-path error) and the mutant is what gets built.
      (cd "$work/tree" && git init -q && git add -A >/dev/null 2>&1) || { echo "not ok - $id # scratch repo failed"; stale+=("$id"); continue; }
      if (cd "$work/tree" && just test-bats-conformance-ssh-ca-fibby) >"$work/$id.log" 2>&1; then
        echo "not ok - $id # SURVIVED the lane"
        survived+=("$id")
      else
        echo "ok - $id killed by the lane (see $work/$id.log)"
        killed+=("$id")
      fi
    done
    echo "# killed: ${killed[*]:-none}; survived: ${survived[*]:-none}; stale: ${stale[*]:-none}"
    [[ ${#survived[@]} == 0 && ${#stale[@]} == 0 ]]

# Flake hunt (piggy#344): build fibby's loopback test once, then run it RUNS
# times and count the failures. Exits non-zero if any run failed.
#
# run fibby's loopback test RUNS times in a loop and count the failures
[group('debug')]
debug-fibby-loopback-loop runs="50":
    #!/usr/bin/env bash
    set -uo pipefail
    cargo test -q -p fibby --test loopback --no-run || exit 1
    failed=0
    for ((i = 1; i <= {{runs}}; i++)); do
      if ! out=$(cargo test -q -p fibby --test loopback 2>&1); then
        failed=$((failed + 1))
        echo "run $i FAILED:"
        grep -E 'panicked|FAILED|refused' <<<"$out" | head -n 5
      fi
    done
    echo "{{runs}} runs, $failed failed"
    ((failed == 0))

# Smoke-test for the `services.piggy-agent` home-manager module (#52).
# Evaluates the module against synthetic configs and verifies the option
# schema, both platform code paths, and every assertion. Reports
# pass/fail per case.
#
# smoke-test the services.piggy-agent home-manager module
[group('post-build')]
test-nix-hm-module:
  #!/usr/bin/env bash
  set -euo pipefail
  expr='let
    flake = builtins.getFlake ("git+file://" + toString ./.);
    pkgs = flake.inputs.igloo.legacyPackages.${builtins.currentSystem};
    test = import ./nix/hm/eval-test.nix {
      inherit pkgs;
      module = flake.homeManagerModules.piggy-agent;
    };
  in test'
  json="$(nix eval --impure --json --expr "$expr")"
  printf '%s\n' "$json" | jq -r '"\(.summary)"'
  if [[ "$(printf '%s\n' "$json" | jq -r '.pass')" != "true" ]]; then
    printf '%s\n' "$json" | jq -r '.failures[] | "FAIL: \(.name)\n  got: \(.result.got)"'
    exit 1
  fi

# Evaluate nix/hm/eval-test.nix as test-nix-hm-module does, but with
# abort-on-warn, so the first evaluation warning (piggy#311's stdenv.isLinux
# deprecation) aborts with a trace naming the expression that raised it.
#
# trace the first evaluation warning raised by the hm eval test
[group('debug')]
debug-hm-eval-warning-trace:
  #!/usr/bin/env bash
  set -euo pipefail
  expr='let
    flake = builtins.getFlake ("git+file://" + toString ./.);
    pkgs = flake.inputs.igloo.legacyPackages.${builtins.currentSystem};
    test = import ./nix/hm/eval-test.nix {
      inherit pkgs;
      module = flake.homeManagerModules.piggy-agent;
    };
  in test.summary'
  nix eval --impure --raw --option abort-on-warn true --show-trace --expr "$expr"

# Smoke-test for the `services.piggy-secrets` home-manager module (FDR 0003):
# evaluates it against synthetic configs and checks the manifest, the
# out-of-closure ciphertext handling, the oneshot unit, the non-blocking
# activation step, and the assertions. Serves the module's edit loop.
#
# smoke-test the services.piggy-secrets home-manager module
[group('post-build')]
test-nix-hm-secrets-module:
  #!/usr/bin/env bash
  set -euo pipefail
  expr='let
    flake = builtins.getFlake ("git+file://" + toString ./.);
    pkgs = flake.inputs.igloo.legacyPackages.${builtins.currentSystem};
    test = import ./nix/hm/secrets-eval-test.nix {
      inherit pkgs;
      module = flake.homeManagerModules.piggy-secrets;
    };
  in test'
  json="$(nix eval --impure --json --expr "$expr")"
  printf '%s\n' "$json" | jq -r '"\(.summary)"'
  if [[ "$(printf '%s\n' "$json" | jq -r '.pass')" != "true" ]]; then
    printf '%s\n' "$json" | jq -r '.failures[] | "FAIL: \(.name)\n  got: \(.result.got)"'
    exit 1
  fi

# Smoke-test for the `services.pigtrough` home-manager module (FDR 0009, R3):
# evaluates it against synthetic configs and checks the exec line, the
# restart and fail-closed unit shape, the routes/routesFile mutex and the
# argument escaping. Nothing is deployed or realised.
#
# smoke-test the services.pigtrough home-manager module
[group('post-build')]
test-nix-hm-pigtrough-module:
  #!/usr/bin/env bash
  set -euo pipefail
  # git+file, not a bare path: a path flake copies the whole directory,
  # and a worktree's .tmp can hold sockets ("unsupported type").
  expr='let
    flake = builtins.getFlake ("git+file://" + toString ./.);
    pkgs = flake.inputs.igloo.legacyPackages.${builtins.currentSystem};
    test = import ./nix/hm/pigtrough-eval-test.nix {
      inherit pkgs;
      module = flake.homeManagerModules.pigtrough;
    };
  in test'
  json="$(nix eval --impure --json --show-trace --expr "$expr")"
  printf '%s\n' "$json" | jq -r '"\(.summary)"'
  if [[ "$(printf '%s\n' "$json" | jq -r '.pass')" != "true" ]]; then
    printf '%s\n' "$json" | jq -r '.failures[] | "FAIL: \(.name)\n  got: \(.result.got)"'
    exit 1
  fi

# NixOS VM lane (nix/vm-tests/luks.nix): a guest running the shipped piggy
# package with fibby + the Rust `piggy agent` as systemd units; a store
# secret sealed to the virtual card formats, opens and re-opens a LUKS2
# volume, and a second passphrase keyslot is enrolled beside it (the FDR
# 0003 shape). Runs under TCG on the build host (no KVM): measured 2026-09-14 at
# 168s for the test script (~145s of it guest boot) once the closure is
# built. Lives under `checks`, so `nix flake check` boots it too.
#
# run the LUKS2-from-store NixOS VM test
[group('post-build')]
[linux]
test-vm-luks:
    nix build .#checks.{{ vm-check-system }}.vm-piggy-luks --no-link --print-build-logs --show-trace

# ZFS sibling of test-vm-luks (nix/vm-tests/zfs.nix): an encrypted dataset
# keyed from the store, unload-key / load-key round-tripped through
# `piggy pass show`. Split from the LUKS lane because this guest carries
# the zfs kernel module — run `just debug-vm-dry-run vm-piggy-zfs` first
# if the igloo pin moved; a `linux-*`/`zfs-kernel-*` derivation in the
# "will be built" list means a local kernel-module compile. Measured
# 2026-09-14 at 120s for the test script (kernel module was a cache hit;
# zfs-user, grub, nfs-utils and bind built locally on the first run).
#
# run the ZFS-encrypted-dataset-from-store NixOS VM test
[group('post-build')]
[linux]
test-vm-zfs:
    nix build .#checks.{{ vm-check-system }}.vm-piggy-zfs --no-link --print-build-logs --show-trace

# Agent sibling (nix/vm-tests/agent.nix): the card-backed `piggy agent`
# proxying a stock ssh-agent upstream (workstation shape), a --proxy-only
# front over both (FDR 0001 remote-host shape), a real sshd accepting a
# login with either key via the front, an `ssh -A` forwarded decrypt, and
# dead-upstream degradation. Measured 2026-09-14 at 112s for the test
# script under TCG.
#
# run the multiplexed-agent + sshd NixOS VM test
[group('post-build')]
[linux]
test-vm-agent:
    nix build .#checks.{{ vm-check-system }}.vm-piggy-agent --no-link --print-build-logs --show-trace

# Holder sibling (nix/vm-tests/holder.nix, FDR 0006 phase (d), piggy#383
# item 5): the shipped `services.piggy-holder` module as two hardened
# system units over the fibby HOLDER build; a bound transient service
# mints, signs and retires, a sibling service is refused not-bound-scope,
# and the bound service's exit destroys its card. The hardening is read
# back from the running processes. No store, no card stack.
#
# run the holder-service NixOS VM test
[group('post-build')]
[linux]
test-vm-holder:
    nix build .#checks.{{ vm-check-system }}.vm-piggy-holder --no-link --print-build-logs --show-trace

# Line coverage from the three VM lanes: re-runs them on a `-C
# instrument-coverage` build of piggy (.#vm-piggy-*-cov), then
# merges every guest's .profraw and reports with the rustc-matched
# llvm-cov (nix/vm-tests/coverage-report.nix). Deliberately OUT of the
# merge gate and of `nix flake check` (packages, not checks) until the
# added wall time is measured; the report is the first line-coverage
# number piggy has, and only counts what the VM lanes exercise.
# --max-jobs 1 runs the three guests one at a time (operator decision,
# 2026-09-14): nix has no per-derivation concurrency limit, and three
# TCG guests plus a cargo build on one host is what produced the
# IO-APIC timer panic. The gate lanes are already serial via `just`.
# Measured 2026-09-14: 803s (13.4 min) end to end with the instrumented
# piggy already cached — the number to weigh before this joins the gate.
#
# run the instrumented VM lanes one at a time and print the merged llvm-cov report
[group('post-build')]
[linux]
test-vm-coverage:
    #!/usr/bin/env bash
    set -euo pipefail
    out=$(nix build .#coverage-report --max-jobs 1 --no-link --print-build-logs --show-trace --print-out-paths)
    cat "$out/report.txt"
    echo "lcov: $out/lcov.info"

# Show what a VM check would build vs fetch without running it — the
# cache-miss tripwire for the ZFS lane's kernel module. Serves the
# test-vm-* dev loop.
#
# dry-run a nix/vm-tests check and list what it would build vs fetch
[group('debug')]
[linux]
debug-vm-dry-run check="vm-piggy-luks":
    nix build .#checks.{{ vm-check-system }}.{{ check }} --dry-run --show-trace

# TODO(#408): the pam_piggy design experiments (nix/vm-tests/pam-*-probe.nix),
# no part of the merge gate. PROBE is pam-sandbox (socket paths the polkit
# helper sandbox reaches), pam-socket-move (the moved socket, link and
# fallback), pam-command (what a pam_exec helper sees and shows) or
# pkexec-password (pkexec's agents with the stock stack). The log is
# printed whether the probe passes, fails or was already built. PROBE is
# quoted: this recipe runs without a permission prompt.
#
# run one pam_piggy VM probe and print its log
[group('debug')]
[linux]
debug-vm-probe probe:
    status=0; nix build .#vm-probe-{{ quote(probe) }} --no-link --show-trace || status=$?; nix log .#vm-probe-{{ quote(probe) }}; exit $status

# Re-run one VM lane RUNS times to catch an intermittent failure
# (piggy#296/#300: vm-piggy-agent hangs in an ssh step about once in a
# few dozen runs). Each run is a forced rebuild of the already-built
# check; every log is kept under LOGDIR and a line per run reports
# pass/fail and seconds. A failing log carries the guest's
# "HANG WATCHDOG" dump (nix/vm-tests/agent.nix). The lane's 15-minute
# global timeout bounds a hung run.
#
# re-run a nix/vm-tests check N times and keep the logs of every run
[group('debug')]
[linux]
debug-vm-loop check="vm-piggy-agent" runs="10" logdir="":
    #!/usr/bin/env bash
    set -uo pipefail
    attr=".#checks.{{ vm-check-system }}.{{ check }}"
    logdir="{{ logdir }}"
    [[ -n $logdir ]] || logdir="${TMPDIR:-/tmp}/vm-loop-{{ check }}-$(date +%Y%m%dT%H%M%S)"
    mkdir -p "$logdir"
    echo "logs: $logdir"
    # --rebuild needs the output to exist already.
    nix build "$attr" --no-link --show-trace >"$logdir/run-00-prime.log" 2>&1 \
      || echo "run 00 (prime): FAIL, see $logdir/run-00-prime.log"
    failures=0
    for i in $(seq 1 {{ runs }}); do
      log=$(printf '%s/run-%02d.log' "$logdir" "$i")
      start=$(date +%s)
      if nix build "$attr" --rebuild --no-link --print-build-logs --show-trace >"$log" 2>&1; then
        verdict=pass
      else
        verdict=FAIL
        failures=$((failures + 1))
      fi
      echo "run $(printf '%02d' "$i"): $verdict $(( $(date +%s) - start ))s $(grep -c 'HANG WATCHDOG:.*seconds' "$log" || true) watchdog dump(s)"
    done
    echo "$failures of {{ runs }} runs failed; logs in $logdir"

# Rust card-integration tests against FIBBY — the one lane for the agent
# ECDH, agent unlock and card unlock integration tests since the fib card was
# retired (piggy#365). Boots ONE fibby (virtual backend, seeded slot 9D + CHUID/GUID)
# and runs all three card-agnostic integration tests against it: the agent
# ECDH round-trip, the agent unlock round-trip, and the direct-PCSC
# (CardEcdhOracle) unlock. The agent tests spawn `piggy agent` against the
# FIBBY socket (not the system pcscd) and supply the PIN via the agent
# unlock protocol; card-unlock reads it from the test askpass. fibby's PIN
# is 123456. Pure-Rust card-under-test, no Java/jcardsim/hardware.
#
# run the Rust card-integration tests against fibby
[group('post-build')]
[linux]
test-rust-integration-fibby: build-rust
  #!/usr/bin/env bash
  set -uo pipefail
  fibby_bin="$PWD/target/debug/fibby"
  [[ -x $fibby_bin ]] || { echo "missing $fibby_bin (build-rust)"; exit 1; }

  workdir=$(mktemp -d /tmp/rust-integration-fibby-XXXXXX)
  fibby_sock="$workdir/pcscd.comm"
  fibby_log="$workdir/fibby.log"
  fibby_pid=""
  cleanup() { [[ -n "$fibby_pid" ]] && kill "$fibby_pid" 2>/dev/null || true; rm -rf "$workdir"; }
  trap cleanup EXIT

  echo "=== Starting fibby (virtual, --seed-rfc5903-slot-9d-cert) ==="
  FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
    --seed-rfc5903-slot-9d-cert >"$fibby_log" 2>&1 &
  fibby_pid=$!
  for _ in $(seq 1 50); do [[ -S $fibby_sock ]] && break; sleep 0.1; done
  [[ -S $fibby_sock ]] || { echo "fibby socket never appeared"; cat "$fibby_log"; exit 1; }

  export PCSCLITE_CSOCK_NAME="$fibby_sock"
  export PIGGY_BIN="$PWD/target/debug/piggy"
  # card-unlock reads the PIN from the test askpass; the agent tests
  # supply it via the unlock protocol and ignore these. Setting them
  # globally is harmless and keeps a stray pivy decrypt-path prompt from
  # ever reaching the operator's real askpass (piggy-testing(7) PIN PROMPT
  # SAFETY NET).
  export PIGGY_TEST_FIB_PIN=123456
  askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
  export SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force DISPLAY=""

  set -e
  cargo test --test agent_ecdh_integration -- --nocapture
  cargo test --test unlock_ebox_agent_integration -- --nocapture
  cargo test --test unlock_ebox_card_integration -- --nocapture

[group('pre-build')]
validate: validate-box validate-piggy validate-rust

# `cargo check` type-evals without codegen — a pre-build validation
# (hard failure on type errors), distinct from the `lint-rust` clippy
# opinion pass. `validate-rust` covers the whole workspace; the
# per-crate variants are faster iteration subsets.
#
# cargo check the workspace, forwarding ARGS
[group('pre-build')]
validate-rust *ARGS:
    cargo check {{ARGS}}

# `cargo check` the piggy-box crate only — a fast per-crate type-eval subset of
# validate-rust.
#
# cargo check the piggy-box crate only
[group('pre-build')]
validate-box:
    cargo check -p piggy-box

# `cargo check` the piggy crate only — a fast per-crate type-eval subset of
# validate-rust.
#
# cargo check the piggy crate only
[group('pre-build')]
validate-piggy:
    cargo check -p piggy

# Validate go/internal/bravo/markl/marklid.peg (the markl-id text-form
# grammar, piggy#220) is well-formed under langlang. Mirrors cutting-
# garden's validate-grammar recipe (docs/rfcs/0014-trellis.peg), but
# via the langlang flake input (flake.nix `.#langlang`) rather than a
# hardcoded sibling-checkout path — langlang ships its own flake with a
# buildGoApplication `packages.default`, so there's no reason not to
# consume it hermetically from the start. Well-formedness only — does
# NOT check that real markl-id strings parse via the intended
# production (see test-grammar-vectors for that; hyphence#9's
# "zero-power trap" lesson).
#
# check that marklid.peg is well-formed under langlang
[group('pre-build')]
validate-grammar:
    #!/usr/bin/env bash
    set -euo pipefail
    langlang_bin=$(nix build .#langlang --no-link --print-out-paths)/bin/langlang
    peg="{{ justfile_directory() }}/go/internal/bravo/markl/marklid.peg"
    "$langlang_bin" -grammar "$peg" -grammar-ast -disable-builtins -disable-spaces >/dev/null
    gum log --level info "validate-grammar: ok ($peg parses under langlang)"

# Cross-check both vector corpora against marklid.peg via langlang
# -input (piggy#220, hyphence#9's "zero-power trap" lesson):
# validate-grammar alone only checks the .peg is well-formed, never
# that real markl-id strings parse under it via the intended
# production. Two corpora, two test functions:
#
#   TestGrammarVectors       — the RFC 0011 conformance fixture (the
#                              same vectors the Go/Rust reference
#                              decoders round-trip), whole markl IDs.
#   TestIdentifierVectors    — RFC 0011 §7.3's identifier corpus
#                              (docs/rfcs/0011-identifier-vectors.txt),
#                              purpose slots only. The piggy half of
#                              madder#273 ruling 13's drift guard;
#                              downstream grammars run the same file.
#   TestGrammarImportSurface — marklid.peg's frozen @import contract
#                              (piggy#236): each exported rule is
#                              importable per langlang @import, with a
#                              zero-power negative control. A rename of
#                              an exported rule fails HERE, by design.
#
# Keep the -run alternation in sync when adding a fourth: `-run
# TestGrammarVectors` alone silently skips anything not matching that
# prefix, which is exactly how the identifier corpus shipped unrun on
# its first pass.
#
# Resolves the langlang binary via the flake input and points
# LANGLANG_BIN at it; all three tests skip gracefully outside this
# recipe (plain `just test-go` still passes without LANGLANG_BIN set).
#
# cross-check both vector corpora against marklid.peg via langlang
[group('post-build')]
test-grammar-vectors:
    #!/usr/bin/env bash
    set -euo pipefail
    langlang_bin=$(nix build .#langlang --no-link --print-out-paths)/bin/langlang
    cd go && LANGLANG_BIN="$langlang_bin" go test -count=1 -tags test \
      ./internal/charlie/markl_registrations/... \
      -run 'TestGrammarVectors|TestIdentifierVectors|TestGrammarImportSurface' -v

# --- debug ---

# Dump the recipient pubkey(s) baked into one or more .ebox files, rendered
# as piggy-recipient-v1@pivy_ecdh_p256_pub-… markl IDs so they compare
# byte-for-byte against piggy-ids and `piggy pass recipients list-available`.
# Non-destructive: parses the ebox off-disk, touches no card, prompts for no
# PIN. Diagnoses "card present but cannot decrypt" — if no recipient matches
# an attached card's pubkey, the box was encrypted to a different recipient
# set. Usage: just debug-ebox-recipients ~/.local/share/piggy/foo.ebox …
#
# dump the recipient pubkeys baked into the given EBOXES
[group('debug')]
debug-ebox-recipients *EBOXES:
    cargo run -q -p piggy-box --example dump-recipients -- {{EBOXES}}

# EXPLORE (#task darwin-fibby) — prove/refute whether macOS's PCSC.framework
# honors PCSCLITE_CSOCK_NAME. Starts fibby (virtual, seeded slot 9D) on a temp
# socket, points PCSCLITE_CSOCK_NAME at it, and runs the framework-linked
# `pivy-tool list`. If the card appears, the framework DOES honor the var
# (darwin-fibby is trivial); if it reports no readers / no card, the var is
# ignored (fibby needs a different interpose on darwin). Pure probe, no PIN.
#
# probe whether macOS's PCSC.framework honors PCSCLITE_CSOCK_NAME
[group('explore')]
explore-darwin-fibby-csock: build-rust
    #!/usr/bin/env bash
    set -uo pipefail
    # Short path: AF_UNIX sun_path is 104 bytes on macOS; the worktree
    # .tmp/ prefix overruns it. Use a short /tmp dir (TMPDIR points into
    # the worktree, so override it explicitly).
    workdir="$(TMPDIR=/tmp mktemp -d /tmp/fibcsock.XXXXXX)"
    sock="$workdir/pcscd.comm"
    log="$workdir/fibby.log"
    fibby="$PWD/target/debug/fibby"
    trap 'kill "$fibby_pid" 2>/dev/null; rm -rf "$workdir"' EXIT
    FIBBY_LOG=wire "$fibby" --socket "$sock" --backend virtual \
      --seed-rfc5903-slot-9d-cert >"$log" 2>&1 &
    fibby_pid=$!
    for _ in $(seq 1 50); do [[ -S $sock ]] && break; sleep 0.1; done
    [[ -S $sock ]] || { echo "fibby socket never appeared"; cat "$log"; exit 1; }
    echo "=== fibby up at $sock (pid $fibby_pid) ==="
    echo "=== pivy-tool list WITH PCSCLITE_CSOCK_NAME pointed at fibby ==="
    PCSCLITE_CSOCK_NAME="$sock" pivy-tool list; echo "pivy-tool exit=$?"
    echo "=== fibby wire log (did the framework client ever connect?) ==="
    cat "$log"

# What does `ssh-keygen -Y verify` do, against a `cert-authority`
# allowed-signers line, with the grant certificates hogtie must refuse: an
# expired one, one not yet valid, wildcard principals, a critical option, a
# host certificate? Software keys only; prints every answer, asserts none.
# Feeds hogtie's list of in-process refusals (piggy/rich-oak, hogtie stage 1).
#
# probe ssh-keygen -Y verify against expired, future, wildcard, critical-option and host certificates
[group('explore')]
explore-hogtie-sshsig-grant-edges:
    #!/usr/bin/env bash
    set -uo pipefail
    d=$(mktemp -d "$PWD/.tmp/hogtie-edges.XXXXXX")
    cd "$d"
    ssh-keygen -q -t ecdsa -b 256 -N '' -f ca -C ca
    printf '* cert-authority,namespaces="hogtie-v1" %s\n' "$(cut -d' ' -f1,2 ca.pub)" >allowed
    printf 'nonce action args\n' >msg
    probe() { # NAME PRINCIPAL CERT-FLAGS...
      local name=$1 principal=$2; shift 2
      ssh-keygen -q -t ed25519 -N '' -f "$name" -C "$name"
      ssh-keygen -q -s ca -I "$name" "$@" "$name.pub" || { echo "=== $name: cert NOT issued"; return; }
      cp msg "$name.msg"
      ssh-keygen -Y sign -f "$name-cert.pub" -n hogtie-v1 "$name.msg" 2>/dev/null
      echo "=== $name (verify -I $principal):"
      ssh-keygen -L -f "$name-cert.pub" | grep -E 'Type|Valid|Principals|Critical' -A1 | sed 's/^/    /'
      ssh-keygen -Y verify -f allowed -I "$principal" -n hogtie-v1 -s "$name.msg.sig" <"$name.msg" 2>&1 | sed 's/^/    /'
      echo "    exit ${PIPESTATUS[0]}"
    }
    probe valid       deploy-site      -n deploy-site -V +1h
    probe expired     deploy-site      -n deploy-site -V 20200101:20200102
    probe future      deploy-site      -n deploy-site -V +1d:+2d
    probe star        anything-at-all  -n '*' -V +1h
    probe prefixglob  restic-snapshots -n 'restic-*' -V +1h
    probe question    deploy-sitf      -n 'deploy-sit?' -V +1h
    probe critical    deploy-site      -n deploy-site -V +1h -O force-command=/bin/true
    probe hostcert    deploy-site      -n deploy-site -V +1h -h
    echo "=== expired, with -Overify-time inside its window:"
    ssh-keygen -Y verify -f allowed -I deploy-site -n hogtie-v1 -Overify-time=20200101120000 -s expired.msg.sig <expired.msg 2>&1 | sed 's/^/    /'
    echo "=== ssh-keygen version:"; ssh -V 2>&1

# What sudo itself documents about the state a command inherits: resource
# limits (rlimit_* in sudoers(5)), signal relaying, use_pty. Prints the
# matching passages of nixpkgs' sudo(8) and sudoers(5); for hogtie(8)
# DEPLOYMENT (piggy/rich-oak, hogtie stage 1).
#
# grep sudo(8) and sudoers(5) for rlimits, signal relaying and use_pty
[group('explore')]
explore-sudo-inheritance:
    #!/usr/bin/env bash
    set -uo pipefail
    man=$(nix build --no-link --print-out-paths nixpkgs#sudo.man)
    for page in man8/sudo.8.gz man5/sudoers.5.gz; do
      echo "=== $page"
      zcat "$man/share/man/$page" | sed 's/\\f[BIRP]//g; s/\\-/-/g' |
        grep -n -i -B2 -A8 -E 'relay|rlimit_|^\.It use_pty|resource limit|SIGTSTP|SIGSTOP' | head -400
    done

# Generic driver for exploratory bats files. Each file brings up whatever
# infrastructure it needs in setup_file() / teardown_file(). We pass
# --no-sandbox because explore tests often need to talk to pcscd (Unix
# sockets), bind local ports, or write into CWD, which the narrow-escape
# flag (--allow-local-binding) leaves read-only. Explores are not part of
# the CI gate so the broader trust is fine.
#
# run the given exploratory bats FILES outside the sandbox
[group('explore')]
explore-bats *FILES: build-rust
  BATS_TEST_TIMEOUT=30 bats --no-sandbox --tap {{FILES}}

# Delegation proof (no code under test): a P-256 key generated in fibby's
# slot 83 (PIN always, touch always) signs a forced-command OpenSSH user
# certificate through a card `piggy agent` and `ssh-keygen -U -s`; the lane
# prints ssh-keygen's answer, `ssh-keygen -L` of the certificate and the
# prompt the agent raised, as the code stands. No card, no host.
#
# run the fibby slot-83 SSH-certificate proof and print what it saw
[group('explore')]
[linux]
explore-ssh-cert-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      PROOF_OUT="${PROOF_OUT:-$PWD/.tmp/ssh-cert-proof.txt}" \
      BATS_TEST_TIMEOUT=120 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_ssh_cert_fibby.bats

# The delegation proof's certificates: a fresh fibby with a slot-83 CA signs
# three user certificates for USER_PUB (a public line) into DIR (public
# material only: the CA line, the certificates, their `ssh-keygen -L` and
# the prompts); fibby is torn down with the run, so the CA private key dies.
#
# sign the delegation proof's three certificates for USER_PUB into DIR
[group('explore')]
[linux]
explore-ssh-cert-proof USER_PUB DIR:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIGGY="$piggy_out/bin/piggy" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      PROOF_USER_PUB={{ quote(USER_PUB) }} PROOF_DIR={{ quote(DIR) }} \
      BATS_TEST_TIMEOUT=120 bats --no-sandbox --tap \
      -f the_delegation_proof \
      zz-tests_bats/conformance/piggy_ssh_cert_fibby.bats

# Render the SSH certificate dialog (contrib/piggy-askpass.sh through
# piggy-askpass-gtk) headless on an Xvfb screen to PNGs in DIR: a typical
# certificate and the worst case the parser admits (8 principals, two 256-byte
# option values, every extension). The dialog is shown with the context the
# agent would give it; the text is made up. Needs nixpkgs' xvfb-run and
# imagemagick, fetched with `nix shell`.
#
# render the SSH certificate dialog to PNGs headless
[group('explore')]
[linux]
explore-ssh-cert-dialog-png DIR=".tmp/dialog-png":
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p "{{ DIR }}"
    out="$(cd "{{ DIR }}" && pwd)"
    gtk=$(nix build .#piggy-askpass-gtk --no-link --print-out-paths)
    typical=$'card 191755CF slot 83, the SSH certificate authority\nOpenSSH user certificate\nKey id: goldielocks-tunnel\nPrincipal: tunnel\nCertified key: SHA256:VwTKavMZsIyhTV79SVgMR6phfKlJuiLfnyx6IPIaSdQ\nSigned by CA: SHA256:CyrC9JjEcSecv/WY2LVyRJsUBbRYx1XMVgJC5INNvM0\nSerial: 0\nValid: 2026-11-22T22:07:00Z to 2026-11-23T22:12:00Z\nLifetime: 1d 5m\nCritical options: none\nExtensions: permit-port-forwarding'
    long=$(printf 'W%.0s' $(seq 1 80))
    worst=$'card 191755CF slot 83, the SSH certificate authority\nOpenSSH user certificate\nKey id: grant-with-a-key-id-of-the-longest-length-allowed-by-the-parser-64b\n'
    for p in a b c d e f g h; do worst+="Principal: principal-$p"$'\n'; done
    worst+=$'Certified key: SHA256:VwTKavMZsIyhTV79SVgMR6phfKlJuiLfnyx6IPIaSdQ\nSigned by CA: SHA256:CyrC9JjEcSecv/WY2LVyRJsUBbRYx1XMVgJC5INNvM0\nSerial: 18446744073709551615\nValid: 2026-11-22T22:07:00Z to 2026-11-23T22:12:00Z\nLifetime: 1d 5m\n'
    worst+="Critical option: force-command:"$'\n'"\"$long\""$'\n'
    worst+="Critical option: source-address:"$'\n'"\"$long\""$'\n'
    worst+=$'Critical option: verify-required\nExtensions: permit-X11-forwarding, permit-agent-forwarding, permit-port-forwarding, permit-pty, permit-user-rc'
    helper="$out/.render-one.sh"
    cat >"$helper" <<'RENDER'
    #!/usr/bin/env bash
    # args: GTK_BIN BODY_FILE PNG
    set -euo pipefail
    export GSK_RENDERER=cairo GDK_BACKEND=x11
    "$1" --title "piggy SSH CA: CERTIFICATE" --ok-label "Issue SSH certificate" --timeout 30 \
      --band "✍  SSH CERTIFICATE — certifying a key for logins" \
      --band-background "#0e7490" --band-foreground "#ffffff" <"$2" >/dev/null 2>&1 &
    pid=$!
    sleep 5
    import -window root "$3"
    kill "$pid" 2>/dev/null || true
    RENDER
    chmod +x "$helper"
    for name in typical worst; do
      ctx="${!name}"
      PIGGY_ASKPASS_KIND=ssh-certificate PIGGY_ASKPASS_CONTEXT="$ctx" PIGGY_ASKPASS_DRY_RUN=1 \
        bash contrib/piggy-askpass.sh "Enter PIN for token 191755CF to sign this SSH certificate" \
        2>"$out/$name.body" >/dev/null || true
      nix shell nixpkgs#xvfb-run nixpkgs#imagemagick -c \
        xvfb-run -a -s "-screen 0 1280x1400x24" "$helper" "$gtk/bin/piggy-askpass-gtk" "$out/$name.body" "$out/ssh-certificate-$name.png"
    done
    ls -l "$out"

# Syntax-check (bash -n) and shellcheck FILES, which may sit outside the
# tree; shellcheck is skipped with a note when
# the devshell has none.
#
# bash -n and shellcheck the given shell scripts
[group('debug')]
debug-shell-script *FILES:
    #!/usr/bin/env bash
    set -euo pipefail
    for f in {{ FILES }}; do
      bash -n "$f"
      echo "bash -n ok: $f"
      if command -v shellcheck >/dev/null 2>&1; then
        shellcheck -s bash "$f"
        echo "shellcheck ok: $f"
      else
        echo "shellcheck not in the devshell: $f unchecked"
      fi
    done

# Does `ssh-keygen -Y verify` accept an sshsig made by a user key that holds
# an OpenSSH user certificate, against a `cert-authority` allowed-signers
# line, and what does it say about the certificate's principals? Software
# keys only (no card, no agent, no network); prints every step's answer.
#
# probe sshsig-by-certified-key verification with cert-authority allowed-signers
[group('explore')]
explore-sshsig-cert-verify:
    #!/usr/bin/env bash
    set -uo pipefail
    d=$(mktemp -d "$PWD/.tmp/sshsigcert.XXXXXX")
    cd "$d"
    ssh-keygen -q -t ecdsa -b 256 -N '' -f ca -C ca
    ssh-keygen -q -t ed25519 -N '' -f user -C user
    ssh-keygen -q -s ca -I grant-1 -n deploy-site,restart-service -V +1h user.pub
    echo "--- the grant:"; ssh-keygen -L -f user-cert.pub
    printf 'nonce-123 deploy-site arg=x\n' >msg
    echo "--- sign with the key that has a certificate next to it (-Y sign -f user):"
    ssh-keygen -Y sign -f user -n hogtie-v1 msg; echo "exit $?"
    echo "--- sign naming the certificate (-Y sign -f user-cert.pub):"
    cp msg msg2
    ssh-keygen -Y sign -f user-cert.pub -n hogtie-v1 msg2; echo "exit $?"
    for s in msg.sig msg2.sig; do
      [[ -f $s ]] || continue
      echo "--- $s: public key inside the signature:"
      sed '1d;$d' "$s" | base64 -d | head -c 120 | strings | head -3
      printf '* cert-authority,namespaces="hogtie-v1" %s\n' "$(cut -d' ' -f1,2 ca.pub)" >allowed
      echo "--- verify $s with a cert-authority line (principal deploy-site):"
      ssh-keygen -Y verify -f allowed -I deploy-site -n hogtie-v1 -s "$s" <"${s%.sig}"; echo "exit $?"
      echo "--- verify $s, principal NOT in the grant (shutdown-host):"
      ssh-keygen -Y verify -f allowed -I shutdown-host -n hogtie-v1 -s "$s" <"${s%.sig}"; echo "exit $?"
      echo "--- find-principals for $s:"
      ssh-keygen -Y find-principals -f allowed -s "$s"; echo "exit $?"
    done
    echo "--- verify with the WRONG CA line:"
    ssh-keygen -q -t ecdsa -b 256 -N '' -f ca2 -C ca2
    printf '* cert-authority,namespaces="hogtie-v1" %s\n' "$(cut -d' ' -f1,2 ca2.pub)" >allowed2
    ssh-keygen -Y verify -f allowed2 -I deploy-site -n hogtie-v1 -s msg.sig <msg; echo "exit $?"

# Run the Go conformance binary against a freshly-started piggy agent and
# print per-test PASS/FAIL/SKIP lines. Useful for eyeballing which subtests
# pass without bats swallowing the output.
#
# run the Go conformance binary against a freshly-started piggy agent
[group('debug')]
debug-conformance-run: build-rust
    #!/usr/bin/env bash
    set -euo pipefail
    conformance=$(nix build .#piggy.tests.conformance --no-link --print-out-paths)/bin/piggy-agent-conformance
    tmpdir=$(mktemp -d /tmp/piggy-debug-conf.XXXXXX)
    sock="$tmpdir/agent.sock"
    trap 'kill "$agent_pid" 2>/dev/null || true; rm -rf "$tmpdir"' EXIT
    ./target/debug/piggy agent -A -D -a "$sock" &
    agent_pid=$!
    for _ in $(seq 1 20); do [[ -S $sock ]] && break; sleep 0.1; done
    [[ -S $sock ]] || { echo "agent socket never appeared"; exit 1; }
    "$conformance" "$sock" || true

# Inspect which libpcsclite.so.1 each PIV client resolves against.
# Used to diagnose "PCSC error: The Smart card resource manager has shut
# down" when piggy can't reach pcscd but pivy-tool can.
# Try piggy agent -i under PCSCLITE_CSOCK_NAME override to see if it's a
# socket-path disagreement between piggy's libpcsclite and the running daemon.
#
# run piggy agent -i against each candidate PCSCLITE_CSOCK_NAME socket
[group('debug')]
debug-pcsclite-csock-override: build-rust
    #!/usr/bin/env bash
    set -uo pipefail
    for sock in /run/pcscd/pcscd.comm /var/run/pcscd/pcscd.comm; do
      [[ -S $sock ]] || { echo "skip: $sock not a socket"; continue; }
      echo "=== PCSCLITE_CSOCK_NAME=$sock ==="
      PCSCLITE_CSOCK_NAME="$sock" ./target/debug/piggy agent -A -i 2>&1 | head -20
      echo
    done

# Trace openat() during piggy agent -i vs pivy-tool list — reveals which
# libpcsclite.so.1 is loaded and which pcscd socket is connected.
#
# trace openat() during piggy agent -i vs pivy-tool list
[group('debug')]
debug-pcsclite-opens: build-rust
    #!/usr/bin/env bash
    set -uo pipefail
    for cmd in "./target/debug/piggy agent -A -i" "pivy-tool list"; do
      echo "=== strace: $cmd ==="
      strace -f -e trace=openat,connect -o /tmp/pcsc-strace.$$ -- $cmd >/dev/null 2>&1 || true
      grep -E 'libpcsclite|pcscd\.comm|pcscd\.pid' /tmp/pcsc-strace.$$ | head -30
      rm -f /tmp/pcsc-strace.$$
      echo
    done

# Report which libpcsclite each PIV client (piggy/pivy-tool/pcscd) links and
# embeds — diagnoses "smart card resource manager has shut down" linkage skew.
#
# report which libpcsclite each PIV client links and embeds
[group('debug')]
debug-pcsclite-linkage:
    #!/usr/bin/env bash
    set -uo pipefail
    for bin in ./target/debug/piggy "$(command -v pivy-tool)" "$(command -v pcscd)"; do
      [[ -x $bin ]] || continue
      echo "=== $bin ==="
      echo "-- ldd pcsc deps --"
      ldd "$bin" 2>/dev/null | grep -i pcsc || echo "  (none direct)"
      echo "-- strings for pcscd socket path --"
      strings "$bin" 2>/dev/null | grep -E 'pcscd\.(comm|pid)|libpcsclite' | sort -u || true
      echo
    done

# Survey the wet-env PCSC state: pcscd process, system sockets, readers
# visible to libpcsclite (opensc-tool + pcsc_scan), ATR of any inserted
# card, and the USB device side via lsusb. Read-only — does not connect
# to the card or consume PIN retries. Serves the fibby hardware-proxy
# validation dev-loop (does the right card show up before we wire fibby
# to it?) and any other recipe that depends on a real card being present.
#
# survey the PCSC state: pcscd, sockets, readers, card ATR, and USB devices
[group('debug')]
debug-pcsc-env:
    #!/usr/bin/env bash
    set -uo pipefail
    echo "=== pcscd process ==="
    pgrep -a pcscd 2>/dev/null || echo "no pcscd process"
    echo
    echo "=== system sockets ==="
    for s in /run/pcscd/pcscd.comm /var/run/pcscd/pcscd.comm; do
      if [[ -S $s ]]; then ls -la "$s"; else echo "$s: not a socket"; fi
    done
    echo
    echo "=== PCSCLITE_CSOCK_NAME ==="
    echo "${PCSCLITE_CSOCK_NAME:-(unset)}"
    echo
    echo "=== opensc-tool readers ==="
    timeout 5 opensc-tool -l 2>&1
    echo
    echo "=== pcsc_scan one round ==="
    timeout 3 pcsc_scan -n 2>&1 | tail -8
    echo
    echo "=== lsusb (Yubico/CCID/smartcard) ==="
    lsusb 2>&1 | grep -iE 'yubico|yubikey|ccid|smart' || echo "no Yubico/CCID USB device"

# Survey pseudo-terminal (PTY) usage to diagnose "OSError: out of pty
# devices" / openpty() failures — notably the SSH_ASKPASS_REQUIRE tty
# tests in conformance/piggy_askpass.bats, which need a real PTY and
# hard-fail when the host pool is saturated. macOS uses a small fixed
# pool capped by kern.tty.ptmx_max (default 511), unlike Linux devpts'
# large dynamic limit, so saturation is a realistic transient here.
# Read-only: reports the cap, current allocation, and which processes
# hold ptys open (aggregated by command and by PID so a leaker shows as
# many identical rows). Serves the askpass conformance dev-loop.
#
# survey PTY usage and report which processes hold ptys open
[group('debug')]
debug-pty-holders:
    #!/usr/bin/env bash
    set -uo pipefail
    lsof="${LSOF:-/usr/sbin/lsof}"
    command -v "$lsof" >/dev/null 2>&1 || lsof="$(command -v lsof 2>/dev/null || echo lsof)"
    echo "=== pty cap (kern.tty.ptmx_max) vs current allocation ==="
    sysctl kern.tty.ptmx_max 2>/dev/null || echo "kern.tty.ptmx_max: (unavailable)"
    allocated=$(ls /dev/ttys* 2>/dev/null | wc -l | tr -d ' ')
    echo "allocated /dev/ttys* slaves: ${allocated:-0}"
    echo
    echo "=== holders by command (most ptys first) ==="
    # -w suppresses warnings; +c 0 keeps full command names so a leaker is
    # identifiable by name rather than truncated to 9 chars.
    "$lsof" -w +c 0 2>/dev/null | grep -E '/dev/ttys' \
      | awk '{print $1}' | sort | uniq -c | sort -rn || echo "(none)"
    echo
    echo "=== holders by (command, pid) — repeated identical rows = leak signature ==="
    "$lsof" -w +c 0 2>/dev/null | grep -E '/dev/ttys' \
      | awk '{print $1, $2}' | sort | uniq -c | sort -rn | head -50 || echo "(none)"

# Verify stats-me telemetry end-to-end (#141 + the piggy.pass/box/agent
# coverage expansion): report whether anything is collecting on the
# configured 127.0.0.1:8125, then prove piggy emits by running an
# instrumented `pass` command against a throwaway local UDP listener and
# printing the captured statsd datagram. No card needed. Serves the
# stats-me wiring dev-loop.
#
# verify stats-me telemetry by capturing piggy's statsd datagrams
[group('debug')]
debug-stats-me-roundtrip: build-rust
    #!/usr/bin/env bash
    set -uo pipefail
    echo "=== configured endpoint: ${STATSD_HOST:-(unset)}:${STATSD_PORT:-(unset)} ==="
    echo "=== UDP listeners on :8125 (the real stats-me daemon, if any) ==="
    ss -ulnp 2>/dev/null | grep 8125 || echo "(nothing listening on UDP 8125 — no stats-me daemon)"
    echo
    port=18125
    cap="$(mktemp)"
    # Capture datagrams on a throwaway port for ~3s, then exit.
    timeout 3 socat -u UDP-RECV:"$port" - >"$cap" 2>/dev/null &
    sock_pid=$!
    sleep 0.4
    store="$(mktemp -d)"
    echo "=== emit: piggy pass find (STATSD_PORT=$port) ==="
    STATSD_HOST=127.0.0.1 STATSD_PORT="$port" PIGGY_STORE_DIR="$store" \
      target/debug/piggy pass find nonexistent-term || true
    wait "$sock_pid" 2>/dev/null || true
    rm -rf "$store"
    echo
    echo "=== captured datagram(s) ==="
    if [[ -s "$cap" ]]; then cat "$cap"; echo; else echo "(none captured)"; fi
    rm -f "$cap"
    echo
    echo "=== stats-me collected piggy.* counters (statsd admin :8126) ==="
    if ss -tlnp 2>/dev/null | grep -q 8126; then
      # Emit one to the REAL endpoint, then query the live accumulators.
      STATSD_HOST=127.0.0.1 STATSD_PORT=8125 PIGGY_STORE_DIR="$(mktemp -d)" \
        target/debug/piggy pass find "roundtrip-marker-$$" >/dev/null 2>&1 || true
      sleep 0.3
      printf 'counters\nquit\n' | timeout 3 nc 127.0.0.1 8126 2>/dev/null \
        | tr ',' '\n' | grep -i piggy || echo "(no piggy.* counters returned)"
    else
      echo "(no statsd admin interface on :8126)"
    fi

# Bring fibby up with the hardware-proxy backend (proxying to the system
# pcscd/YubiKey), run an arbitrary client command pointed at fibby's
# socket via PCSCLITE_CSOCK_NAME, then tear fibby down and dump the
# FIBBY_LOG=wire trace. Single-shot, transactional — no leftover
# processes. Serves the fibby wet-env validation dev-loop: pivy-tool /
# piggy / opensc-tool exercises driven through fibby's protocol layer.
#
# Usage:
#   just debug-fibby-proxy pivy-tool list
#   just debug-fibby-proxy pivy-tool init
#   just debug-fibby-proxy pivy-tool -P 123456 generate 9e
#   just debug-fibby-proxy piggy pass show -v some/entry
#
# The recipe rebuilds with --features hardware-proxy on every call so
# you don't have to remember the feature flag.
#
# Env overrides (all optional):
#   FIBBY_BACKEND_PCSCD=<socket>  Tell fibby's HardwareProxy to talk to
#                                 a non-default pcscd (e.g. a private
#                                 pcscd started on its own socket).
#                                 Default: system pcscd at /run/pcscd/pcscd.comm.
#   FIBBY_READER=<substr>         Reader-name substring HardwareProxy
#                                 selects on. Default: "Yubico". Set it to
#                                 pick another reader when several are
#                                 attached.
#   FIBBY_KEEP_LOGS=<dir>         Copy the FIBBY_LOG=wire trace to this
#                                 directory before the cleanup trap erases
#                                 the tmp dir. Output file is named
#                                 wire-<UTC timestamp>-<pid>.log. Default:
#                                 unset (trace is ephemeral).
#
# run CLIENT_CMD against fibby in hardware-proxy mode and dump the wire trace
[group('debug')]
debug-fibby-proxy *CLIENT_CMD:
    #!/usr/bin/env bash
    set -uo pipefail
    if [[ -z "{{CLIENT_CMD}}" ]]; then
      echo "usage: just debug-fibby-proxy <client cmd...>" >&2
      exit 2
    fi
    cargo build -p fibby --features hardware-proxy >/dev/null 2>&1 || {
      echo "fibby --features hardware-proxy build failed; rerun to see why" >&2
      cargo build -p fibby --features hardware-proxy
      exit 1
    }
    sock_dir="${TMPDIR:-/tmp}/fibby-proxy.$$"
    mkdir -p "$sock_dir"
    sock="$sock_dir/pcscd.comm"
    log="$sock_dir/wire.log"
    reader="${FIBBY_READER:-Yubico}"
    # Last-resort cleanup: kill fibby + remove the tmp socket dir on any
    # exit path. Before the rm, copy the wire trace under
    # FIBBY_KEEP_LOGS if requested. Fibby itself rm -f's a stale socket
    # on startup, so a crashed previous run won't block restart. The
    # trailing `:` keeps cleanup's exit status from polluting the
    # script's final exit code — without it, `wait $fibby_pid`
    # propagates fibby's SIGTERM (143) and the recipe spuriously
    # reports failure.
    cleanup() {
      [[ -n "${fibby_pid:-}" ]] && kill "$fibby_pid" 2>/dev/null
      wait "${fibby_pid:-}" 2>/dev/null
      if [[ -n "${FIBBY_KEEP_LOGS:-}" && -f "$log" ]]; then
        mkdir -p "$FIBBY_KEEP_LOGS"
        stamp=$(date -u +%Y%m%dT%H%M%SZ)
        kept="$FIBBY_KEEP_LOGS/wire-$stamp-$$.log"
        cp "$log" "$kept" 2>/dev/null && \
          echo "  wire log kept: $kept" >&2
      fi
      rm -rf "$sock_dir"
      :
    }
    trap cleanup EXIT
    # FIBBY_BACKEND_PCSCD redirects fibby's *upstream* pcsc-lite client
    # (the one HardwareProxy uses internally). The CLIENT_CMD below uses
    # a fresh PCSCLITE_CSOCK_NAME=$sock that overrides this for the
    # client itself.
    if [[ -n "${FIBBY_BACKEND_PCSCD:-}" ]]; then
      echo "=== fibby backend pcscd → $FIBBY_BACKEND_PCSCD (reader=\"$reader\") ==="
      PCSCLITE_CSOCK_NAME="$FIBBY_BACKEND_PCSCD" \
        FIBBY_LOG=wire ./target/debug/fibby --backend hardware --reader "$reader" \
        --socket "$sock" >"$log" 2>&1 &
    else
      FIBBY_LOG=wire ./target/debug/fibby --backend hardware --reader "$reader" \
        --socket "$sock" >"$log" 2>&1 &
    fi
    fibby_pid=$!
    # Wait up to 5s for the socket to appear; if it doesn't, fibby crashed
    # at startup (usually pcsc init failure) — dump the log and bail.
    for _ in $(seq 1 50); do
      [[ -S "$sock" ]] && break
      sleep 0.1
    done
    if [[ ! -S "$sock" ]]; then
      echo "!!! fibby socket never appeared; log:" >&2
      cat "$log" >&2
      exit 1
    fi
    echo "=== fibby up on $sock (pid $fibby_pid); running client ==="
    PCSCLITE_CSOCK_NAME="$sock" {{CLIENT_CMD}}
    client_exit=$?
    echo
    echo "=== client exit: $client_exit ==="
    echo
    echo "=== fibby wire log ==="
    cat "$log"
    # Propagate the client's exit, not cleanup's. EXIT trap still runs
    # after this — but its exit status no longer overrides ours.
    exit "$client_exit"

# Tier-4 differential gate for fibby's hardware-proxy backend: run a
# real pivy-box stream encrypt + decrypt round-trip against the inserted
# PIV card, routed entirely through fibby's pcsc-lite protocol server.
# Calls debug-fibby-proxy with the in-repo helper script — the helper
# discovers the card GUID at runtime via `pivy-tool list`, so it works
# on any throwaway with slot 9D already initialized.
#
# Bootstrap a throwaway card before invoking this recipe:
#   just debug-fibby-proxy pivy-tool -K default init
#   just debug-fibby-proxy pivy-tool -P 123456 -K default -a eccp256 generate 9d
# Then:
#   just debug-fibby-roundtrip
# Expected tail of output: `=== ROUND-TRIP OK ===` and `client exit: 0`.
#
# run a pivy-box encrypt/decrypt round-trip against the inserted card via fibby
[group('debug')]
debug-fibby-roundtrip:
    just debug-fibby-proxy bash zz-tests_bats/helpers/fibby-roundtrip.sh

# Tier-4 differential gate at the **piggy** layer: pass init / insert /
# show round-trip against the inserted PIV card via fibby. Companion to
# debug-fibby-roundtrip (which exercises the same crypto at the
# pivy-box layer). Gitless store: piggy's find_inner_git_dir returns
# None and the post-write commit is silently skipped — proves the
# wet-env path without dragging in git config plumbing.
#
# Bootstrap as for debug-fibby-roundtrip. Build deps:
#   just build-rust   # debug piggy + piggy-ids on target/debug/
#
# run a piggy pass init/insert/show round-trip against the inserted card via fibby
[group('debug')]
debug-fibby-piggy-roundtrip: build-rust
    just debug-fibby-proxy bash zz-tests_bats/helpers/fibby-piggy-roundtrip.sh

# Tier-4 round-trip with persistent wire-log capture: same as
# debug-fibby-roundtrip but the FIBBY_LOG=wire trace is preserved
# under crates/fibby/tests/fixtures/captures/yubikey/wire-<timestamp>.log
# instead of being torn down with the recipe's tmp dir. Run this when
# a real YubiKey is inserted; the captured trace is the canonical
# input for the future per-APDU fixture set that VirtualCard's step-5
# tests will replay/diff against.
#
# run debug-fibby-roundtrip, keeping the wire log under the yubikey fixtures dir
[group('debug')]
debug-fibby-roundtrip-capture:
    FIBBY_KEEP_LOGS=crates/fibby/tests/fixtures/captures/yubikey \
      just debug-fibby-roundtrip

# Variant of debug-fibby-roundtrip-capture that routes the wire log into
# the `test-vector/` subdir, so captures against a throwaway YK with the
# RFC 6979 §A.2.5 scalar imported at slot 9D (see debug-yk-throwaway-
# import-rfc6979) stay segregated from the existing generated-key
# fixtures. Serves the fibby #134 byte-deterministic ECDH replay dev-loop.
#
# run debug-fibby-roundtrip, keeping the wire log under the test-vector fixtures dir
[group('debug')]
debug-fibby-roundtrip-capture-test-vector:
    FIBBY_KEEP_LOGS=crates/fibby/tests/fixtures/captures/yubikey/test-vector \
      just debug-fibby-roundtrip

# Reproduce the launchd environment that pivy-agent invokes piggy-askpass.sh
# under: no controlling TTY, no DISPLAY, scrubbed env. `setsid` detaches the
# controlling terminal so the script's `/dev/tty` open-test fails the same
# way it does under pivy-agent's fork+pipe. Exercises both call shapes
# pivy-agent uses (askpass at pivy-agent.c:841, plain-branch confirm at
# pivy-agent.c:1055).
#
# Expected pre-fix output: `exit=2`, stderr says "no render target
# available". That's what pivy-agent saw on Nov 14 2026 when home-manager
# pointed SSH_ASKPASS/SSH_CONFIRM at this script and signing failed with
# "agent refused operation".
#
# reproduce the launchd environment pivy-agent invokes piggy-askpass.sh under
[group('debug')]
debug-askpass-launchd-env: build-nix
    #!/usr/bin/env bash
    set -uo pipefail
    askpass=./result/libexec/piggy/piggy-askpass.sh
    [[ -x $askpass ]] || { echo "missing $askpass — run 'just build-nix' first" >&2; exit 1; }

    # Detach from the controlling TTY before exec. `setsid` is Linux-only
    # (not in BSD/Darwin coreutils), so we shell out to python3 — present
    # by default on both macOS and most Linux distros — to call os.setsid()
    # before execve. Same effect: child has no controlling terminal, so
    # opening /dev/tty fails, mirroring pivy-agent's fork+pipe context.
    detach_and_exec() {
      python3 -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' "$@"
    }

    run_case() {
      local label="$1" prompt="$2"
      local stderr_file
      stderr_file=$(mktemp -t piggy-askpass-stderr.XXXXXX)
      echo "=== $label ==="
      local stdout exit_code
      # `env -i` reproduces the scrubbed environment a launchd-spawned
      # process sees. `< /dev/null` closes stdin like pivy-agent's fork does.
      # Export the detach helper via a function-export so the env -i child
      # can still call it; simpler to inline the python invocation.
      stdout=$(env -i HOME="$HOME" PATH="/usr/bin:/bin" \
        python3 -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
        "$askpass" "$prompt" 2>"$stderr_file" < /dev/null)
      exit_code=$?
      echo "exit=$exit_code"
      echo "stdout=[$stdout]"
      echo "stderr=[$(cat "$stderr_file")]"
      rm -f "$stderr_file"
      echo
    }

    run_case "askpass-call (pivy-agent.c:841)" "Enter PIV PIN for token 12345"
    run_case "confirm-call (pivy-agent.c:1055)" "A new client is trying to use PIV token 12345"

# piggy#179: prove contrib/piggy-askpass.sh re-derives WAYLAND_DISPLAY from the
# live session when the frozen agent env lacks it. Hermetic and dependency-light
# (bash/python3/coreutils only — no bats, no rust build, no card, no display):
# stub zenity records the WAYLAND_DISPLAY it inherits, a python-made AF_UNIX
# socket feeds the glob source, and a stub systemctl feeds the import source.
# Mirrors the four `reattach_*` cases in conformance/piggy_askpass.bats for
# environments where bats isn't on PATH. See amarbel-llc/piggy#179.
#
# prove contrib/piggy-askpass.sh re-derives WAYLAND_DISPLAY from the live session
[group('debug')]
debug-askpass-reattach:
    #!/usr/bin/env bash
    set -uo pipefail
    askpass="$PWD/contrib/piggy-askpass.sh"
    py="$(command -v python3)"
    rc=0
    new_stub() {
      local d; d="$(mktemp -d)"
      local t
      for t in bash ps tr dirname mkdir date grep sed; do ln -sf "$(command -v "$t")" "$d/$t"; done
      {
        echo '#!/usr/bin/env bash'
        echo "printf '%s' \"\${WAYLAND_DISPLAY-}\" > \"$d/seen\""
        echo 'echo pin'
      } > "$d/zenity"
      chmod +x "$d/zenity"
      printf '%s' "$d"
    }
    check() {  # $1 label  $2 expected  $3 stub-dir
      local got; got="$(cat "$3/seen" 2>/dev/null || true)"
      if [[ "$got" == "$2" ]]; then echo "PASS  $1 (WAYLAND_DISPLAY=[$got])"
      else echo "FAIL  $1: expected [$2], saw [$got]"; rc=1; fi
    }

    # 1. glob: a Wayland socket discoverable under XDG_RUNTIME_DIR.
    d1="$(new_stub)"; rt1="$(mktemp -d)"
    "$py" -c 'import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$rt1/wayland-7"
    env -i HOME="$d1" PATH="$d1" XDG_RUNTIME_DIR="$rt1" \
      "$py" -c 'import os,sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
      "$askpass" "piggy-test: glob" </dev/null >/dev/null 2>&1 || true
    check "glob socket under XDG_RUNTIME_DIR" "wayland-7" "$d1"

    # 2. systemctl --user show-environment (authoritative import source).
    d2="$(new_stub)"
    {
      echo '#!/usr/bin/env bash'
      echo 'if [[ "${1:-}" == "--user" && "${2:-}" == "show-environment" ]]; then printf "WAYLAND_DISPLAY=wayland-3\nDISPLAY=:0\n"; fi'
    } > "$d2/systemctl"; chmod +x "$d2/systemctl"
    env -i HOME="$d2" PATH="$d2" \
      "$py" -c 'import os,sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
      "$askpass" "piggy-test: systemctl" </dev/null >/dev/null 2>&1 || true
    check "systemctl show-environment import" "wayland-3" "$d2"

    # 3. no source available → must NOT fabricate a display.
    d3="$(new_stub)"; rt3="$(mktemp -d)"
    env -i HOME="$d3" PATH="$d3" XDG_RUNTIME_DIR="$rt3" \
      "$py" -c 'import os,sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
      "$askpass" "piggy-test: none" </dev/null >/dev/null 2>&1 || true
    check "no source leaves display empty" "" "$d3"

    # 4. present display must not be clobbered.
    d4="$(new_stub)"; rt4="$(mktemp -d)"
    "$py" -c 'import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$rt4/wayland-7"
    env -i HOME="$d4" PATH="$d4" XDG_RUNTIME_DIR="$rt4" WAYLAND_DISPLAY=wayland-existing \
      "$py" -c 'import os,sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
      "$askpass" "piggy-test: present" </dev/null >/dev/null 2>&1 || true
    check "present display not clobbered" "wayland-existing" "$d4"

    echo
    [[ $rc -eq 0 ]] && echo "ALL PASS" || echo "FAILURES ABOVE"
    exit $rc

# Like debug-conformance-run, but with --hardware. Prompts for the card PIN
# via `ssh-add -X` so the sign test can actually execute against the card.
#
# run the Go conformance binary with --hardware against a real card
[group('debug')]
debug-conformance-run-hw: build-rust
    #!/usr/bin/env bash
    set -euo pipefail
    conformance=$(nix build .#piggy.tests.conformance --no-link --print-out-paths)/bin/piggy-agent-conformance
    tmpdir=$(mktemp -d /tmp/piggy-debug-conf.XXXXXX)
    sock="$tmpdir/agent.sock"
    trap 'kill "$agent_pid" 2>/dev/null || true; rm -rf "$tmpdir"' EXIT
    ./target/debug/piggy agent -A -D -a "$sock" &
    agent_pid=$!
    for _ in $(seq 1 20); do [[ -S $sock ]] && break; sleep 0.1; done
    [[ -S $sock ]] || { echo "agent socket never appeared"; exit 1; }
    echo "Unlocking agent via ssh-add -X (enter card PIN when prompted):"
    SSH_AUTH_SOCK="$sock" ssh-add -X
    "$conformance" --hardware "$sock" || true

# --- format / lint ---

[group('codemod')]
codemod: codemod-fmt codemod-fmt-go codemod-rfc0002-fixture codemod-pigpen-vectors codemod-facades codemod-diagrams

# Format the tree in place via `nix fmt`, which runs the conformist wrapper
# (formatter.${system}) — nixfmt + shfmt + rustfmt under one CLI. See
# conformist.nix for the program config. (Go is NOT covered here; use
# codemod-fmt-go for go/ hand-written sources.)
#
# format the tree in place via nix fmt
[group('codemod')]
codemod-fmt:
    nix fmt

# Clippy the workspace with warnings-as-errors; on Linux also clippy fibby
# with --features hardware-proxy so wet-env-path regressions fail the gate.
#
# clippy the workspace with warnings-as-errors
[group('pre-build')]
lint-rust:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo clippy --workspace --all-targets -- -D warnings
    # Linux-only second pass: clippy fibby with --features hardware-proxy
    # so wet-env-path regressions (status2 signature drift, protocol2
    # Option<T> mismatches, missing pcsc::Error variants) are caught at
    # the merge gate — the same lane the host-devshell-unblock fixes at
    # c0c59f0 + 653ca77 fell through silently before they were in CI.
    # Gated on Linux because flake.nix only adds pcsclite to
    # rustBuildInputs on isLinux (pcsclite is a Linux-only build input; the
    # hardware-proxy build needs libpcsclite-dev via pcsc-sys).
    if [ "$(uname -s)" = Linux ]; then
      cargo clippy -p fibby --all-targets --features hardware-proxy -- -D warnings
    fi
    # FDR 0006 (piggy#382): the fibby holder build, without the default
    # `test-double` feature, must stay clippy-clean too (dead code left
    # behind by a gate shows up only here).
    cargo clippy -p fibby --all-targets --no-default-features -- -D warnings

# FDR 0006 phase (c), piggy#382: the fibby holder build (`.#fibby-holder`)
# must carry none of the test double's conveniences. Builds the
# `checks.lint-fibby-holder` derivation, which greps the holder binary for
# every flag the test build lists (`fibby --test-flags`) and the fixed test
# certificates' subjects, runs the holder with each of those flags and with
# FIBBY_LOG=wire and wants exit 2, checks both builds' `--build-profile`, and
# checks the holder closure for pcsclite. Modelled on lint-closure-no-pivy.
#
# assert the fibby holder build carries no test flags, vectors or wire logging
[group('pre-build')]
lint-fibby-holder:
    #!/usr/bin/env bash
    set -euo pipefail
    system=$(nix eval --raw --impure --expr 'builtins.currentSystem')
    nix build ".#checks.${system}.lint-fibby-holder" --no-link --print-build-logs

# hogtie(8)'s shipped binary carries no test harness: HOGTIE_TEST_ROOT is not
# in it, and with that variable set it still insists on uid 0
# (checks.lint-hogtie).
#
# assert the shipped hogtie binary carries no test harness
[group('pre-build')]
lint-hogtie:
    #!/usr/bin/env bash
    set -euo pipefail
    system=$(nix eval --raw --impure --expr 'builtins.currentSystem')
    nix build ".#checks.${system}.lint-hogtie" --no-link --print-build-logs

# clippy hogtie with the test harness on, which the workspace pass leaves off
# (so its binary tests and the test kit are linted too)
[group('pre-build')]
lint-rust-hogtie:
    cargo clippy -p hogtie --all-targets --features test-harness -- -D warnings

# hogtie is Linux only (SO_PEERCRED, /proc, getrandom).
[linux]
_lint-hogtie-linux-only: lint-hogtie lint-rust-hogtie

[macos]
_lint-hogtie-linux-only:

# piggy#337: `piggy-piv --no-default-features` is the portable core pigsty
# links on Android and wasm. It must compile (clippy-clean), and its
# dependency tree must hold none of the native C crates below. Every
# piggy-side consumer keeps the default features, so nothing changes for
# them. The wasm32 `cargo check` the issue also wants needs a wasm-capable
# toolchain the devShell lacks; this tree check is the cheap stand-in.
#
# check piggy-piv builds with no default features and links no native C crate
[group('pre-build')]
lint-piggy-piv-portable:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo clippy -p piggy-piv --no-default-features --lib -- -D warnings
    tree=$(cargo tree -p piggy-piv --no-default-features -e normal --prefix none)
    bad=0
    for native in pcsc-sys openssl-sys; do
      if grep -q "^$native " <<<"$tree"; then
        echo "piggy-piv --no-default-features still depends on $native:" >&2
        cargo tree -p piggy-piv --no-default-features -e normal -i "$native" >&2
        bad=1
      fi
    done
    exit "$bad"

# Read-only formatting gate: builds the `checks.formatting`
# derivation, which runs the conformist formatters + the eng preset's
# file-based linters against a /nix/store snapshot of the source tree
# and fails if anything would change. Does NOT modify files in the
# worktree -- the modifying counterpart is `codemod-fmt`.
#
# check formatting via the sandboxed checks.formatting derivation
[group('pre-build')]
lint-fmt:
    #!/usr/bin/env bash
    set -euo pipefail
    system=$(nix eval --raw --impure --expr 'builtins.currentSystem')
    nix build ".#checks.${system}.formatting" --no-link --print-build-logs

# piggy#289 Phase 4: assert C pivy is NOT in the shipped `piggy` runtime
# closure. pivy is a test-only input now (`.#pivy`, the differential oracle),
# not a runtime dep; this builds the `checks.lint-closure-no-pivy` derivation,
# which greps the piggy closure's store-paths for the pivy store path and fails
# if a reference ever re-introduces it. The retirement's enforcement gate.
#
# assert C pivy is not in the shipped piggy runtime closure
[group('pre-build')]
lint-closure-no-pivy:
    #!/usr/bin/env bash
    set -euo pipefail
    system=$(nix eval --raw --impure --expr 'builtins.currentSystem')
    nix build ".#checks.${system}.lint-closure-no-pivy" --no-link --print-build-logs

# FDR 0009: pigtrough's HTTP/TLS stack (hyper, rustls with ring, tokio-rustls,
# webpki-roots) stays in pigtrough. Every other workspace member's normal and
# build dependency tree must be free of it, so `piggy`, the agent and fibby
# never link it. A dependency-tree check, not a store-closure one: Rust links
# statically, so the stack would leave no store path to find.
#
# assert no workspace crate but pigtrough pulls in the HTTP/TLS stack
[group('pre-build')]
lint-pigtrough-stack-isolated:
    #!/usr/bin/env bash
    set -euo pipefail
    found=$(cargo tree --locked --workspace --exclude pigtrough --edges normal,build \
      --prefix none --format '{p}' |
      grep -E '^(hyper|hyper-util|http-body-util|rustls|tokio-rustls|webpki-roots|ring) ' |
      sort -u || true)
    if [[ -n "$found" ]]; then
      echo "a workspace crate other than pigtrough pulls in its HTTP/TLS stack:" >&2
      echo "$found" >&2
      exit 1
    fi

# Impure lane: the eng-convention checks that need the live worktree (git
# remotes / default branch / sweatfile / agents-md) PLUS the go/ facade
# drift CHECK (conformist's dewey-facade-export). This is the merge-gate safety
# net for facade drift — it runs in the `lint` aggregate, so the pre-merge
# `just` hook fails on committed drift even if the `conformist-pre-commit`
# repair hook was bypassed. The pre-commit hook does the REPAIR; this does the
# CHECK (same dewey-facade-export module, two lanes — see flake.nix). Also
# fails when a copied conformance fixture differs from its source: the Go
# and Rust copies of the markl fixture (piggy#235; `just
# codemod-rfc0002-fixture` writes both), and the go/ testdata copies of the
# docs/rfcs vectors the Go tests read (piggy#189: go/ is its own nix source,
# so they cannot be symlinks).
#
# run the impure eng-convention checks plus the go/ facade drift CHECK
[group('pre-build')]
lint-worktree:
    #!/usr/bin/env bash
    set -euo pipefail
    cfg=$(nix build --no-link --print-out-paths '.#conformist-impure-config')
    conformist check --config-file "$cfg" --tree-root .
    markl=go/internal/charlie/markl_registrations/testdata
    drift=0
    while read -r copy source fix; do
      cmp -s "$copy" "$source" || {
        echo "$copy differs from $source; $fix" >&2
        drift=1
      }
    done <<EOF
    $markl/0002-markl-id-format-vectors.json crates/piggy-markl/testdata/0002-markl-id-format-vectors.json run: just codemod-rfc0002-fixture
    $markl/0011-identifier-vectors.txt docs/rfcs/0011-identifier-vectors.txt copy the docs/rfcs file over the copy
    $markl/0011-markl-id-format.md docs/rfcs/0011-markl-id-format.md copy the docs/rfcs file over the copy
    go/internal/delta/pigpen/testdata/0008-pigpen-vectors.txt docs/rfcs/0008-pigpen-vectors.txt run: just codemod-pigpen-vectors
    crates/piggy/testdata/0013-vectors.txt docs/rfcs/0013-vectors.txt copy the docs/rfcs file over the copy
    EOF
    exit "$drift"

# The justfile convention linters (recipe verbs, orphaned doc summaries)
# delivered as conformist's profile-pulled artifacts rather than a Nix
# module: `conformist.profile` at the repo root is conformist master's
# file copied verbatim (conformist RFC 0005, experimental), and the run
# pulls conformist itself from its forge so no devShell input changes.
# Linux only: the profile pins static `just` builds for x86_64/aarch64
# Linux and nothing for darwin. Not in the `lint` aggregate while the
# profile mechanism is experimental; run it by hand before touching
# recipe names or doc comments.
#
# run conformist's profile-delivered justfile linters over this justfile
[group('pre-build')]
[linux]
lint-justfile-profile:
    nix run --refresh 'git+https://code.linenisgreat.com/conformist.git' -- check --tree-root . --profile conformist.profile --profile-only

# Bring up the standalone `fibby` server in hardware-proxy mode, fronted
# by the system pcscd: short-circuits if already running, drops a PID
# file under .fibby/, and writes an env file (.fibby/env) consumers
# `eval` to set PCSCLITE_CSOCK_NAME.
#
# load-fibby assumes a real PC/SC reader + card are already plugged in
# and the system pcscd is up — its sole job is to translate pcsc-lite
# daemon-protocol traffic into PC/SC client traffic against the system
# pcscd. If no card is present, fibby's startup error surfaces via the
# log and the recipe bails with a clear hint.
#
# The fibby binary comes from `nix build .#fibby` (Linux-only at the
# moment because hardware-proxy needs libpcsclite — flake.nix gates it
# on isLinux). Use the dev-loop alternative `debug-fibby-proxy` if you
# need fast iteration off `./target/debug/fibby` instead.
#
# bring up the standalone fibby server in hardware-proxy mode
[group('operational')]
load-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p .fibby
    sock="/tmp/piggy-fibby-ipc/pcscd.comm"
    # Short-circuit if already running.
    if [[ -f .fibby/fibby.pid ]] && kill -0 "$(cat .fibby/fibby.pid)" 2>/dev/null; then
      echo "load-fibby: already running (pid $(cat .fibby/fibby.pid)). eval \$(cat .fibby/env)" >&2
      exit 0
    fi
    # System pcscd sanity check: HardwareProxy::new fails noisily if
    # neither standard socket is present; check first for a better
    # error than a stack trace.
    if [[ ! -S /run/pcscd/pcscd.comm && ! -S /var/run/pcscd/pcscd.comm ]]; then
      echo "load-fibby: no system pcscd socket — start pcscd first" >&2
      exit 1
    fi
    fibby_bin=$(nix build --no-link --print-out-paths .#fibby)/bin/fibby
    mkdir -p "$(dirname "$sock")"
    rm -f "$sock"
    FIBBY_LOG=info "$fibby_bin" \
      --backend hardware \
      --socket "$sock" \
      >.fibby/fibby.log 2>&1 &
    fibby_pid=$!
    echo "$fibby_pid" >.fibby/fibby.pid
    # Wait for the socket; if it doesn't appear, fibby crashed at
    # startup — most commonly "no reader matching Yubico" when the
    # card isn't plugged in.
    for _ in $(seq 1 50); do
      [[ -S "$sock" ]] && break
      sleep 0.1
    done
    if [[ ! -S "$sock" ]]; then
      echo "load-fibby: socket never appeared — see .fibby/fibby.log" >&2
      cat .fibby/fibby.log >&2
      kill "$fibby_pid" 2>/dev/null || true
      rm -f .fibby/fibby.pid
      exit 1
    fi
    cat >.fibby/env <<EOF
    export PCSCLITE_CSOCK_NAME="$sock"
    # fibby pid: $fibby_pid
    EOF
    echo "fibby: up — eval \$(cat .fibby/env) to connect"

# tear down the standalone fibby server brought up by `load-fibby`
[group('operational')]
clean-fibby:
    #!/usr/bin/env bash
    set -uo pipefail
    if [[ -f .fibby/fibby.pid ]]; then
      kill "$(cat .fibby/fibby.pid)" 2>/dev/null || true
    fi
    rm -rf .fibby
    rm -f /tmp/piggy-fibby-ipc/pcscd.comm
    rmdir /tmp/piggy-fibby-ipc 2>/dev/null || true
    echo "fibby: down"

# --- explore ---

# Run pivy-tool bats tests against the nix-built pivy (not the devshell's).
# Validates that changes to vendor/pivy/src/ are picked up by the actual
# build artifact. Used to verify #23 (-K default fix).
#
# run the pivy-tool bats tests against the nix-built pivy
[group('explore')]
explore-pivy-tool-bats: build-nix
    #!/usr/bin/env bash
    set -euo pipefail
    piggy_out=$(readlink -f ./result)
    # Extract the pivy store path from the piggy wrapper script.
    pivy_bin=$(grep -oP '/nix/store/[a-z0-9]+-pivy-[^/]+/bin' "$piggy_out/bin/piggy" | head -1)
    [[ -d "$pivy_bin" ]] || { echo "could not find pivy bin dir in piggy wrapper"; exit 1; }
    PATH="$pivy_bin:$PATH" \
      BATS_TEST_TIMEOUT=30 bats --no-sandbox --tap \
      zz-tests_bats/conformance/pivy_tool_admin_key.bats

# Send a pivy-shaped query extension request directly to $SSH_AUTH_SOCK
# (e.g. an ssh-agent-mux) and hex-dump the response. Hardware-free:
# query does not touch the card. Used to investigate piggy#119 where
# pivy's piv_box_open_agent() fails parsing the query response through
# ssh-agent-mux at vendor/pivy/src/piv.c:7014.
#
# send a pivy-shaped query extension request to an agent socket and dump the response
[group('explore')]
explore-trace-agent-query sock="":
    #!/usr/bin/env bash
    set -euo pipefail
    sock_arg="{{sock}}"
    export PIGGY_PROBE_SOCK="${sock_arg:-${SSH_AUTH_SOCK:?set SSH_AUTH_SOCK or pass a socket arg}}"
    python3 <<'PY'
    import os, socket, struct, sys
    sock_path = os.environ['PIGGY_PROBE_SOCK']
    print(f"probing socket = {sock_path}")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    SSH_AGENTC_EXTENSION = 27
    name = b"query"
    payload = bytes([SSH_AGENTC_EXTENSION]) \
        + struct.pack(">I", len(name)) + name \
        + struct.pack(">I", 0)
    framed = struct.pack(">I", len(payload)) + payload
    print(f"--- request ({len(framed)} bytes) ---")
    print(framed.hex(' '))
    s.sendall(framed)
    raw = b''
    while len(raw) < 4:
        chunk = s.recv(4 - len(raw))
        if not chunk: break
        raw += chunk
    length = struct.unpack(">I", raw)[0]
    print(f"--- response (length={length}) ---")
    body = b''
    while len(body) < length:
        chunk = s.recv(length - len(body))
        if not chunk: break
        body += chunk
    print(body.hex(' '))
    print()
    if len(body) < 1:
        print("response too short"); sys.exit(0)
    code = body[0]
    code_name = 'SSH2_AGENT_EXT_RESPONSE' if code==29 else 'SSH_AGENT_SUCCESS' if code==6 else '???'
    print(f"code byte = {code} ({code_name})")
    i = 1
    idx = 0
    while i + 4 <= len(body):
        slen = struct.unpack(">I", body[i:i+4])[0]
        i += 4
        if i + slen > len(body):
            print(f"  string[{idx}] OVERRUN: claimed_len={slen}, remaining={len(body)-i}")
            print(f"  from-len4 hex: {body[i-4:].hex(' ')}")
            break
        s_bytes = body[i:i+slen]
        i += slen
        try:
            s_str = s_bytes.decode('utf-8')
        except UnicodeDecodeError:
            s_str = f"<non-utf8: {s_bytes.hex(' ')}>"
        nul_at = s_bytes.find(b'\x00')
        nul_note = ""
        if nul_at != -1:
            if nul_at == len(s_bytes) - 1:
                nul_note = "  [trailing NUL]"
            else:
                nul_note = f"  [!! embedded NUL at byte {nul_at} — pivy sshbuf_get_cstring -4 !!]"
        print(f"  string[{idx}] len={slen} {s_str!r}{nul_note}")
        idx += 1
    if i < len(body):
        print(f"trailing bytes ({len(body)-i}): {body[i:].hex(' ')}")
    s.close()
    PY

# Verify the #119/#123 ssh-agent-mux ecdh decrypt fix end-to-end against the
# real card, using a piggy built from THIS worktree. The worktree binary
# bundles the patched vendored pivy-box on its PATH (flake.nix runtimeDeps),
# so its `pass show` exercises the #119 query-response parse fix; its dispatch
# honors PIGGY_AUTH_SOCK (#123). The installed nix-profile piggy predates the
# fix, so this recipe deliberately builds + runs the worktree binary instead.
#
# Pins the mux scenario the issues describe: route piggy's own decrypts at
# piggy-agent (PIGGY_AUTH_SOCK — advertises ecdh@joyent.com) while the ambient
# SSH_AUTH_SOCK is ssh-agent-mux (drops ecdh, see ssh-agent-mux#10). Mirrors
# eng/zz-pocs/piggy_pass_rcm_hook but against the freshly-built binary.
#
# INTERACTIVE + HARDWARE: piggy-agent prompts for your PIV PIN on the cold
# show. SIDE EFFECTS: inserts then removes two throwaway entries in your real
# piggy store (sign-commits if piggy.signcommits=true) and restarts your
# piggy-agent to start from a cold PIN cache. Linux-only.
#
# NOT part of `just` / the pre-merge CI lane, and must never be: it needs
# interactive PIN entry, so it stays an out-of-band manual verification
# (explore group only, run by hand when you want to re-confirm the live path).
#
# Primary signal: `pass show` through the mux env succeeds with no
# sshbuf_get_cstring / "failed to unlock ebox with agent" line. The client-side
# askpass count is supplementary (a nonzero count means pivy-box fell back to a
# direct-card unlock because the agent ecdh path failed; the agent's own PIN
# prompt is rendered by piggy-agent and is NOT counted here).
#
# verify the ssh-agent-mux ecdh decrypt fix end-to-end against the real card
[group('explore')]
[linux]
explore-verify-auth-sock-cache piggy_auth_sock=env_var_or_default("PIGGY_AUTH_SOCK", "") ssh_auth_sock=env_var_or_default("SSH_AUTH_SOCK", ""):
    #!/usr/bin/env bash
    set -euo pipefail

    piggy_sock="{{piggy_auth_sock}}"
    mux_sock="{{ssh_auth_sock}}"
    : "${piggy_sock:?set PIGGY_AUTH_SOCK (piggy-agent socket) or pass piggy_auth_sock=...}"
    : "${mux_sock:?set SSH_AUTH_SOCK (mux socket) or pass ssh_auth_sock=...}"

    echo "=== building worktree piggy (nix build .#piggy) ==="
    out=$(nix build .#piggy --no-link --print-out-paths)
    PIGGY="$out/bin/piggy"
    echo "piggy        = $PIGGY ($("$PIGGY" version 2>/dev/null || echo '?'))"
    echo "PIGGY_AUTH_SOCK (piggy-agent) = $piggy_sock"
    echo "SSH_AUTH_SOCK   (mux)         = $mux_sock"

    probe_dir="$HOME/.tmp/piggy-auth-sock-probe"
    shim="$probe_dir/askpass-shim.sh"
    counter="$probe_dir/askpass-count"
    p1=piggy-authsock-probe-1
    p2=piggy-authsock-probe-2
    mkdir -p "$probe_dir"

    # Every piggy call runs with the mux as the ambient SSH_AUTH_SOCK; the #123
    # routing should redirect the decrypt at PIGGY_AUTH_SOCK.
    export SSH_AUTH_SOCK="$mux_sock"
    export PIGGY_AUTH_SOCK="$piggy_sock"

    cleanup() {
      "$PIGGY" pass rm -f "$p1" >/dev/null 2>&1 || true
      "$PIGGY" pass rm -f "$p2" >/dev/null 2>&1 || true
      rm -rf "$probe_dir"
    }
    trap cleanup EXIT

    echo
    echo "=== inserting throwaway probes into the real store ==="
    printf 'authsock-probe-1\n' | "$PIGGY" pass insert -e -f "$p1"
    printf 'authsock-probe-2\n' | "$PIGGY" pass insert -e -f "$p2"

    # Counting shim: one line per invocation, then exec the real askpass.
    # Catches CLIENT-side prompts (pivy-box falling back to a direct PCSC card
    # unlock because the agent ecdh path failed). PIN prompts the agent renders
    # itself are NOT counted here.
    cat >"$shim" <<'SHIM'
    #!/usr/bin/env bash
    printf 'askpass invoked at %s\n' "$(date +%s.%N)" >>"$COUNTER"
    exec "$REAL_SSH_ASKPASS" "$@"
    SHIM
    chmod +x "$shim"
    : >"$counter"

    echo
    echo "=== restarting piggy-agent (cold PIN cache) ==="
    systemctl --user restart piggy-agent || echo "WARN: could not restart piggy-agent (continuing)"
    for _ in 1 2 3 4 5; do [[ -S "$piggy_sock" ]] && break; sleep 1; done
    [[ -S "$piggy_sock" ]] || echo "WARN: $piggy_sock is not a live socket — is piggy-agent running?"

    run_show() {
      local name="$1" errf rc
      errf="$probe_dir/$name.err"
      echo
      echo "=== piggy pass show $name (through mux env) ==="
      set +e
      env REAL_SSH_ASKPASS="${SSH_ASKPASS:-}" COUNTER="$counter" SSH_ASKPASS="$shim" \
        "$PIGGY" pass show "$name" >/dev/null 2>"$errf"
      rc=$?
      set -e
      echo "exit=$rc"
      [[ -s "$errf" ]] && { echo "--- stderr ---"; cat "$errf"; }
      if grep -qiE 'sshbuf_get_cstring|invalid format|failed to unlock ebox with agent' "$errf"; then
        echo ">> agent-unlock error present (the #119/#123 symptom)"
        return 1
      fi
      return "$rc"
    }

    show1_ok=0; show2_ok=0
    run_show "$p1" && show1_ok=1 || true
    run_show "$p2" && show2_ok=1 || true

    count=$(wc -l <"$counter"); count="${count// /}"
    echo
    echo "=== summary ==="
    echo "show1 clean: $([[ $show1_ok == 1 ]] && echo yes || echo NO)"
    echo "show2 clean: $([[ $show2_ok == 1 ]] && echo yes || echo NO)"
    echo "client-side askpass (direct-card fallback) invocations: $count"
    if [[ $show1_ok == 1 && $show2_ok == 1 ]]; then
      echo "RESULT: PASS — pass-show decrypts through the mux env with no agent-unlock error. #119/#123 verified end-to-end."
    else
      echo "RESULT: FAIL — at least one show hit the agent-unlock error path. See stderr above."
    fi

# HARDWARE + out-of-band — piggy#56: exercise the REAL Rust PinSession on a
# real card. Unlike a `piggy agent` invocation (a separate agent process in
# front of the card), this runs the in-process `unlock_ebox_card_integration`
# test, which drives piggy's Rust `CardEcdhOracle` → `begin_pin_session` →
# `PinSession::{verify_pin,ecdh_derive}` DIRECTLY against the card. First time
# the Rust #56 PinSession code runs on real hardware (the lanes only ever ran
# it against virtual cards).
# Pins to the throwaway via PIGGY_TEST_CARD_GUID so a co-resident prod card is
# never selected; one fail-fast PIN check first. NEVER pass your prod PIN.
#
# run the Rust card-unlock integration test against a real throwaway card
[group('explore')]
[linux]
explore-rust-card-unlock-hw guid="5DA19C98257243EFCD29BE3AE91EA7F8" pin="123456": build-rust
    #!/usr/bin/env bash
    set -euo pipefail
    guid="{{guid}}"; pin="{{pin}}"
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    pivy_tool="$pivy_out/bin/pivy-tool"
    tmpdir=$(mktemp -d /tmp/piggy-rust-card-hw.XXXXXX); trap 'rm -rf "$tmpdir"' EXIT
    pub="$tmpdir/9d.pub"

    echo "=== pre-flight: throwaway $guid present + single PIN check ==="
    # piggy#286: verifies the PIN on the card (consumes a retry on a wrong
    # PIN), so the card must be an allowlisted throwaway.
    serial="$("$pivy_tool" -g "$guid" list 2>/dev/null | awk '/serial:/ {print $2; exit}')"
    bash zz-tests_bats/helpers/piggy-throwaway-guard.sh --guid "$guid" ${serial:+--serial "$serial"} || exit 1
    "$pivy_tool" -g "$guid" pubkey 9d >"$pub" 2>/dev/null || { echo "no 9d key on $guid"; exit 1; }
    if ! "$pivy_tool" -g "$guid" -P "$pin" ecdh 9d <"$pub" >/dev/null 2>&1; then
      echo "REFUSING: PIN/ECDH check failed on $guid slot 9d. NOT running."; exit 1
    fi
    echo "PIN OK."

    echo "=== unlock_ebox_card_integration vs the real throwaway (Rust PinSession) ==="
    askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
    PIGGY_TEST_CARD_GUID="$guid" \
      PIGGY_TEST_FIB_PIN="$pin" \
      SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force DISPLAY="" \
      cargo test --test unlock_ebox_card_integration -- --nocapture

# HARDWARE, read-only — enumerate every PIV card currently visible to
# pcscd. Prints each card's reader, GUID, CHUID, and slots via
# `pivy-tool list`, then a YubiKey factory serial per card via the
# 0xF8 vendor INS. No PIN, no sign, no retry consumption. Use this to
# confirm which physical card is the throwaway vs prod (by GUID/serial)
# before running hardware recipes like explore-rust-card-unlock-hw.
#
# enumerate every PIV card visible to pcscd with its GUID, slots, and serial
[group('debug')]
[linux]
debug-list-piv-cards:
    #!/usr/bin/env bash
    set -euo pipefail
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    pivy_tool="$pivy_out/bin/pivy-tool"
    echo "=== pivy-tool list (all visible PIV cards) ==="
    "$pivy_tool" list
    echo
    echo "=== per-card YubiKey serial (0xF8), keyed by GUID ==="
    # Pull each GUID from the list output and query its serial individually.
    "$pivy_tool" list 2>/dev/null | awk '/guid:/ {print $2}' | while read -r g; do
      serial="$("$pivy_tool" -g "$g" list 2>/dev/null | awk '/serial:/ {print $2; exit}')"
      printf '  guid %s  serial %s\n' "$g" "${serial:-<not reported by the PIV applet>}"
    done
    # Older YubiKey 4 firmware never answers the 0xF8 probe; ykman reads the
    # serial over the management interface instead (piggy#286).
    if command -v ykman >/dev/null 2>&1; then
      echo
      echo "=== ykman list --serials (management interface; the fallback for a serial-less YK4) ==="
      ykman list --serials 2>/dev/null || echo "  (ykman saw no device)"
    else
      echo
      echo "  ykman not on PATH; for a YK4 that reports no serial above, run: nix run nixpkgs#yubikey-manager -- list --serials"
    fi

# DIAGNOSTIC (piggy#56) — hold an SCardBeginTransaction lock on the card at
# <guid> for <secs>s via the piggy-piv hold_lock example, so a co-resident
# client must block on the lock. Read-only (no PIN). Kill/Ctrl-C to release.
#
# hold an SCardBeginTransaction lock on the card at guid for secs seconds
[group('debug')]
[linux]
debug-hold-card-lock guid="5DA19C98257243EFCD29BE3AE91EA7F8" secs="3600":
    cargo run -q -p piggy-piv --example hold_lock -- "{{guid}}" "{{secs}}"

# DIAGNOSTIC (piggy#56) — run the faithful reset-loop contender standalone
# for <secs>s and report how many begin+verify+end(ResetCard) cycles it
# completes. Confirms the contender actually exercises the card (a low/zero
# count would mean the "race" tests had no real reset contention). HARDWARE;
# verifies the PIN repeatedly (correct PIN does not decrement the counter).
#
# run the piggy-piv reset-loop example for secs seconds and count the cycles
[group('debug')]
[linux]
debug-reset-loop guid="5DA19C98257243EFCD29BE3AE91EA7F8" pin="123456" secs="5":
    cargo run -q -p piggy-piv --example reset_loop -- "{{guid}}" "{{pin}}" "{{secs}}"

# DIAGNOSTIC (piggy#56) — is a second client's card lock actually visible to
# other clients on the throwaway, or do they run in isolation? Holds an
# SCardBeginTransaction (the hold_lock example) on <guid>, then checks
# whether `pivy-tool ecdh 9d` BLOCKS on that lock (times out) and runs once
# the holder is killed. A clean block→unblock proves lock-level contention
# is REAL on this card (=> a non-reproducing reset race is a reset-semantics
# issue, e.g. deferred disconnect-reset — switch the contender to a real
# pivy-agent). Instant success despite the held lock means the clients are
# NOT sharing the card (deeper isolation; the race test was hollow).
# HARDWARE; the lock-hold is read-only, the ecdh probe verifies the PIN once.
#
# probe whether a held card lock blocks a co-resident pivy-tool ecdh
[group('debug')]
[linux]
debug-lock-contention-probe guid="5DA19C98257243EFCD29BE3AE91EA7F8" pin="123456": build-rust
    #!/usr/bin/env bash
    set -uo pipefail
    guid="{{guid}}"; pin="{{pin}}"
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    pivy_tool="$pivy_out/bin/pivy-tool"

    tmpdir=$(mktemp -d /tmp/piggy-lockprobe.XXXXXX)
    pub="$tmpdir/9d.pub"; hold_log="$tmpdir/hold.log"; hold_pid=""
    cleanup() { [[ -n "$hold_pid" ]] && kill "$hold_pid" 2>/dev/null || true; rm -rf "$tmpdir"; }
    trap cleanup EXIT

    "$pivy_tool" -g "$guid" pubkey 9d >"$pub" 2>/dev/null || { echo "no 9d key on $guid"; exit 1; }

    echo "=== starting lock holder (SCardBeginTransaction, never releases) ==="
    cargo run -q -p piggy-piv --example hold_lock -- "$guid" 120 >"$hold_log" 2>&1 &
    hold_pid=$!
    for _ in $(seq 1 120); do grep -q HOLDING "$hold_log" 2>/dev/null && break; sleep 0.5; done
    if ! grep -q HOLDING "$hold_log" 2>/dev/null; then
      echo "holder never acquired the lock:"; cat "$hold_log"; exit 1
    fi
    echo "  holder holds the lock (pid $hold_pid)"

    echo "=== Test 1: pivy-tool ecdh WHILE lock held (expect BLOCK -> timeout) ==="
    if timeout 8 "$pivy_tool" -g "$guid" -P "$pin" ecdh 9d <"$pub" >/dev/null 2>&1; then
      echo "  pivy-tool ecdh SUCCEEDED despite the held lock"; locked_blocks=no
    else
      echo "  pivy-tool ecdh did NOT complete (rc=$?; 124=timeout) while the lock was held"; locked_blocks=yes
    fi

    echo "=== releasing the lock (kill holder) ==="
    kill "$hold_pid" 2>/dev/null || true; wait "$hold_pid" 2>/dev/null || true; hold_pid=""
    sleep 1

    echo "=== Test 2: pivy-tool ecdh with lock RELEASED (expect SUCCESS) ==="
    if timeout 8 "$pivy_tool" -g "$guid" -P "$pin" ecdh 9d <"$pub" >/dev/null 2>&1; then
      echo "  pivy-tool ecdh SUCCEEDED after release"; freed_ok=yes
    else
      echo "  pivy-tool ecdh still failing after release (rc=$?) — unexpected"; freed_ok=no
    fi

    echo
    echo "=== conclusion ==="
    if [[ "${locked_blocks:-}" == yes && "${freed_ok:-}" == yes ]]; then
      echo "Lock-level contention is REAL (blocked while held, ran when freed)."
      echo "=> the race not reproducing is a RESET-semantics issue; switch the"
      echo "   contender to a real pivy-agent (persistent conn + end-txn reset)."
    elif [[ "${locked_blocks:-}" == no ]]; then
      echo "Clients are NOT sharing the card lock — deeper isolation; the race test was hollow."
    else
      echo "Inconclusive — see output above."
    fi

# --- update / clean ---

[group('maintenance')]
update: update-nix

# update flake.lock to the latest inputs (nix flake update)
[group('maintenance')]
update-nix:
    nix flake update

[group('maintenance')]
clean: clean-build clean-rust

# remove the nix build result symlink (rm -rf result)
[group('maintenance')]
clean-build:
    rm -rf result

# remove the cargo build artifacts (cargo clean)
[group('maintenance')]
clean-rust:
    cargo clean

# --- maintenance: version bump + tag + release ---
#
# Three recipes per eng-versioning(7). `version.env` is the single
# source of truth, mirrored into crates/piggy/Cargo.toml and Cargo.lock
# (piggy#171): `bump-version` is a pure mutation, `tag` reads the
# current value and pushes the signed tag SET, `release` orchestrates
# the whole flow (changelog → bump → commit → tag set → fj release).
# `version.env` is also read by `flake.nix` at eval time and by
# `crates/piggy/build.rs` at compile time, which fails the build when
# Cargo.toml's version disagrees with it.
#
# MULTI-ARTIFACT RELEASE (mirrors purse-first; eng-versioning(7)): one
# PIGGY_VERSION covers every artifact in this repo, so piggy and the
# go/ Go module always release in lockstep at the same version.
# `tag` materializes the whole tag set from that single version (see
# release_tag_prefixes below).
#
# Grouped under the canonical `maintenance` lifecycle group of
# eng-design_patterns-justfile(7) (alongside update-*/clean-*);
# eng-versioning(7) still says "maint" — reconciling that wording
# onto `maintenance` is tracked at amarbel-llc/eng#122.

# The release tag prefixes, in order. The bare "v" tag is primary
# (piggy's repo-root Rust/C package + the Forgejo release); the
# path-prefixed entries are the sub-directory Go modules the Go module
# proxy needs to resolve a versioned `go get` (so `go/v<sem>`
# resolves `code.linenisgreat.com/piggy/go@v<sem>`, which madder
# pins). The `conformance/` module is intentionally absent: it's a
# vendored test binary nobody `go get`s by version. Add a prefix here
# when a new sub-directory module must be independently consumable.
release_tag_prefixes := "v go/v"

# Rewrite the version everywhere it lives: version.env's PIGGY_VERSION, and
# the package.version of crates/piggy and crates/age-plugin-piggy with their
# Cargo.lock entries. Each crate's build.rs fails the build if its version
# disagrees with version.env (piggy#171). Committing is `release`'s job.
# Usage: just bump-version 0.1.1
#
# rewrite the PIGGY_VERSION line in version.env
[group('maintenance')]
bump-version new_version:
    sed -E -i "s/^(export PIGGY_VERSION)=.*/\1={{new_version}}/" version.env
    for crate in piggy age-plugin-piggy; do \
      sed -E -i '0,/^version = ".*"$/s//version = "{{new_version}}"/' "crates/$crate/Cargo.toml"; \
      sed -E -i "/^name = \"$crate\"\$/{n;s/^version = \".*\"\$/version = \"{{new_version}}\"/}" Cargo.lock; \
    done

# Sign + push the full release tag set named after the current
# version.env: the bare v<sem> plus each release_tag_prefixes entry
# (v<sem>, go/v<sem>), all at the single PIGGY_VERSION so piggy and
# the go/ module tag in lockstep. The whole set is created locally
# first, then pushed — a mid-set failure (signing, a pre-existing tag)
# leaves only local tags to delete, with nothing pushed to roll back.
# Usage: just tag "release v0.1.1"
#
# sign and push the full release tag set for the current version.env
[group('maintenance')]
[positional-arguments]
tag message="":
    #!/usr/bin/env bash
    set -euo pipefail
    . version.env
    version="${PIGGY_VERSION:?missing PIGGY_VERSION in version.env}"
    # Read the message from the positional $1, NOT from a just interpolation of
    # the message parameter. positional-arguments passes it as a real shell
    # parameter so bash never re-parses it. A just interpolation of the message
    # would text-substitute the multi-line changelog into the recipe body, where
    # parens and backticks in commit subjects (feat(x): ..., signatures[],
    # `card init`) would run as command substitution and break the script. This
    # comment must itself avoid the literal two-brace interpolation token, since
    # just expands those even inside comments — that bug broke the v0.1.16 cut.
    msg="${1:-release v$version}"
    tags=()
    for prefix in {{release_tag_prefixes}}; do
        tag="${prefix}${version}"
        git tag -s -m "$msg" "$tag"
        gum log --level info "Created tag: $tag"
        tags+=("$tag")
    done
    for tag in "${tags[@]}"; do
        git push origin "$tag"
        gum log --level info "Pushed $tag"
        git tag -v "$tag"
    done

# Cut a release: must be run on master. Versions every artifact together
# at one PIGGY_VERSION. Generates a repo-wide auto-changelog (commits
# since the previous primary v* tag) BEFORE bumping so the bump commit
# doesn't appear in its own changelog, then bumps version.env, commits,
# signs+pushes the v<sem> + go/v<sem> tag set, and creates a Forgejo
# release (pointed at the primary v<sem>) whose notes are the changelog
# plus the sibling sub-module tags. Usage: just release 0.1.1
#
# cut a release: changelog, version bump, commit, tag set, and Forgejo release
[group('maintenance')]
release new_version:
    #!/usr/bin/env bash
    set -euo pipefail

    branch=$(git rev-parse --abbrev-ref HEAD)
    if [[ "$branch" != "master" ]]; then
        gum log --level error "release only allowed from master (on '$branch')"
        exit 1
    fi

    # Match only the PRIMARY version tags (v<digit>…); the path-prefixed
    # sub-module tags (go/v…) sort separately and must not bound the
    # changelog range.
    prev=$(git tag --sort=-v:refname -l "v*" | grep -E '^v[0-9]' | head -1 || true)
    header="release v{{new_version}}"
    # Enumerated in the tag annotation + Forgejo release notes; `tag` creates
    # these from release_tag_prefixes, the release points at the primary.
    siblings=$'\n\nTags: go/v{{new_version}}'
    if [[ -n "$prev" ]]; then
        summary=$(git log --format='- %s' "$prev"..HEAD)
        if [[ -n "$summary" ]]; then
            msg="$header"$'\n\n'"$summary""$siblings"
        else
            msg="$header""$siblings"
        fi
    else
        msg="$header""$siblings"
    fi

    just bump-version "{{new_version}}"
    git add version.env crates/piggy/Cargo.toml crates/age-plugin-piggy/Cargo.toml Cargo.lock
    git commit -m "$header"

    just tag "$msg"

    fj release create "$header" --tag "v{{new_version}}" --body "$msg"

# Factory-reset a YubiKey 4 throwaway so its PIV applet is wiped and the
# CHUID GUID rolls. DESTRUCTIVE — the recipe refuses to run unless the
# inserted card reports firmware 4.x (so an accidentally-inserted YK5
# primary is not blocked/reset). Sequence: 3 wrong PIN attempts to block
# PIN → 3 wrong PUK attempts to block PUK → --action=reset → re-probe
# status. Serves the fibby #134 test-vector capture dev-loop.
#
# factory-reset a throwaway YubiKey 4's PIV applet
[group('debug')]
debug-yk-throwaway-reset:
    #!/usr/bin/env bash
    set -uo pipefail
    unset PCSCLITE_CSOCK_NAME  # talk to system pcscd, not fibby
    status=$(yubico-piv-tool --action=status 2>&1) || {
      echo "ERROR: yubico-piv-tool --action=status failed:" >&2
      echo "$status" >&2
      exit 1
    }
    version=$(echo "$status" | awk '/^Version:/ {print $2}')
    serial=$(echo "$status" | awk '/^Serial Number:/ {print $3}')
    if [[ "$version" != 4.* ]]; then
      echo "ERROR: refusing to reset — firmware '$version' is not 4.x" >&2
      echo "this recipe is hard-coded for the throwaway YK4; primary YK5 must be swapped out" >&2
      exit 1
    fi
    # piggy#286: the inserted card must be on the operator's throwaway
    # allowlist (environment), identified by pivy-tool; the firmware check
    # above is only a coarse second line.
    PIVY_TOOL="$(nix build .#pivy --no-link --print-out-paths)/bin/pivy-tool" \
      bash zz-tests_bats/helpers/piggy-throwaway-guard.sh --probe || exit 1
    echo "Pre-reset: firmware=$version serial=$serial"
    echo
    echo "=== Blocking PIN with 3 wrong attempts ==="
    for _ in 1 2 3; do
      yubico-piv-tool --action=verify-pin --pin=000000 2>&1 || true
    done
    echo
    echo "=== Blocking PUK with 3 wrong attempts ==="
    for _ in 1 2 3; do
      yubico-piv-tool --action=change-puk -P 00000000 -N 11111111 2>&1 || true
    done
    echo
    echo "=== Running reset ==="
    yubico-piv-tool --action=reset
    echo
    echo "=== Post-reset status ==="
    yubico-piv-tool --action=status

# Import the RFC 6979 §A.2.5 P-256 test-vector key into slot 9D of a
# freshly-reset throwaway YK4, so subsequent GA ECDH wire captures are
# byte-deterministic against any VirtualCard implementation that uses
# the same scalar. DESTRUCTIVE — overwrites slot 9D. Requires the card
# to be at factory mgmt-key (auto on freshly-reset card). Same 4.x
# firmware safety as debug-yk-throwaway-reset. Serves the fibby #134
# test-vector capture dev-loop.
#
# import the RFC 6979 test-vector key into slot 9D of a throwaway YubiKey 4
[group('debug')]
debug-yk-throwaway-import-rfc6979:
    #!/usr/bin/env bash
    set -uo pipefail
    unset PCSCLITE_CSOCK_NAME
    status=$(yubico-piv-tool --action=status 2>&1) || {
      echo "ERROR: yubico-piv-tool --action=status failed:" >&2
      echo "$status" >&2
      exit 1
    }
    version=$(echo "$status" | awk '/^Version:/ {print $2}')
    if [[ "$version" != 4.* ]]; then
      echo "ERROR: refusing to import — firmware '$version' is not 4.x" >&2
      exit 1
    fi
    # piggy#286: destructive (overwrites 9D) — allowlisted throwaway only.
    PIVY_TOOL="$(nix build .#pivy --no-link --print-out-paths)/bin/pivy-tool" \
      bash zz-tests_bats/helpers/piggy-throwaway-guard.sh --probe || exit 1
    pem="crates/fibby/tests/fixtures/test-vectors/rfc6979-a-2-5-priv.pem"
    if [[ ! -f "$pem" ]]; then
      echo "ERROR: test-vector PEM not found: $pem" >&2
      exit 1
    fi
    echo "Importing $pem to slot 9d (algorithm ECCP256)..."
    yubico-piv-tool \
      --action=import-key \
      --slot=9d \
      --algorithm=ECCP256 \
      --key-format=PEM \
      --input="$pem"
    echo
    echo "=== Post-import status ==="
    yubico-piv-tool --action=status

# Phase 0 smoke probe for piggy#135: stand up fibby with the virtual
# backend, point pivy-agent at it via PCSCLITE_CSOCK_NAME, and run
# `ssh-add -L` against the agent. Dumps the wire trace + agent stderr
# inline so the dev-loop sees what pivy-agent expects from a PIV card
# that VirtualCard doesn't yet provide (slot cert objects, mgmt-key
# validation, etc.). Read-only on the host; no hardware involved.
# Hard-kills both children on exit; safe to re-run repeatedly.
#
# Both binaries come from nix derivations (.#pivy + .#fibby); matches
# the production wire surface and avoids stale target/debug artifacts.
# The CI gate for this same probe lives at
# `test-bats-conformance-fibby-pivy-agent-smoke`.
#
# smoke-probe pivy-agent against a virtual fibby with ssh-add -L
[group('debug')]
debug-fibby-pivy-agent-smoke:
    #!/usr/bin/env bash
    set -uo pipefail
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    pivy_agent="$pivy_out/bin/pivy-agent"
    fibby_bin="$fibby_out/bin/fibby"
    [[ -x $fibby_bin ]] || { echo "missing $fibby_bin"; exit 1; }
    [[ -x $pivy_agent ]] || { echo "missing $pivy_agent"; exit 1; }

    # Short-path workdir under /tmp so AF_UNIX sun_path doesn't overflow
    # (108 bytes Linux / 104 darwin). $BATS_TEST_TMPDIR-style nesting
    # would overflow against $TMPDIR inside the spinclass worktree.
    workdir=$(mktemp -d /tmp/p0-XXXXXX)
    fibby_sock="$workdir/pcscd.comm"
    agent_sock="$workdir/a.sock"
    fibby_log="$workdir/fibby.log"
    agent_log="$workdir/agent.log"

    fibby_pid=""
    agent_pid=""
    cleanup() {
      [[ -n $fibby_pid ]] && kill "$fibby_pid" 2>/dev/null || true
      [[ -n $agent_pid ]] && kill "$agent_pid" 2>/dev/null || true
      rm -rf "$workdir"
    }
    trap cleanup EXIT

    echo "=== Starting fibby (virtual backend, Yk4 model, empty slots) ==="
    FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
      >"$fibby_log" 2>&1 &
    fibby_pid=$!
    for _ in $(seq 1 50); do
      [[ -S $fibby_sock ]] && break
      sleep 0.1
    done
    if [[ ! -S $fibby_sock ]]; then
      echo "fibby socket never appeared:" >&2
      cat "$fibby_log" >&2 || true
      exit 1
    fi
    echo "fibby up (pid=$fibby_pid, socket=$fibby_sock)"
    echo

    # Refusal askpass: any PIN prompt should be visible as a banner in
    # stderr, never a GUI dialog. We don't supply PIGGY_TEST_FIB_PIN
    # because the smoke shouldn't reach a PIN-gated path.
    askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"

    echo "=== Starting pivy-agent (PCSCLITE_CSOCK_NAME=fibby) ==="
    PCSCLITE_CSOCK_NAME="$fibby_sock" \
      SSH_ASKPASS="$askpass" \
      SSH_ASKPASS_REQUIRE=force \
      DISPLAY="" \
      "$pivy_agent" -A -D -a "$agent_sock" >"$agent_log" 2>&1 &
    agent_pid=$!
    for _ in $(seq 1 50); do
      [[ -S $agent_sock ]] && break
      sleep 0.1
    done
    if [[ ! -S $agent_sock ]]; then
      echo "agent socket never appeared:" >&2
      echo "--- agent log ---" >&2
      cat "$agent_log" >&2 || true
      echo "--- fibby log ---" >&2
      cat "$fibby_log" >&2 || true
      exit 1
    fi
    echo "pivy-agent up (pid=$agent_pid, socket=$agent_sock)"
    echo

    echo "=== Probe: ssh-add -L ==="
    SSH_AUTH_SOCK="$agent_sock" ssh-add -L
    add_status=$?
    echo "(exit=$add_status)"
    echo

    echo "=== pivy-agent stderr ==="
    cat "$agent_log"
    echo

    echo "=== fibby wire trace (last 80 lines) ==="
    tail -80 "$fibby_log"

# piggy#135 slot-9A sign dev-loop: a non-batman mirror of the
# `pivy_agent_signs_and_verifies_via_seeded_fibby_slot_9a` bats test. Seeds
# fibby's slot 9A (cert + RFC 6979 §A.2.5 key), points pivy-agent at it,
# and drives a real `ssh-keygen -Y sign -U` (agent-sign) + verify
# round-trip — proving the slot-9A ECDSA sign path works end-to-end through
# pivy-agent. Runs OUTSIDE batman so it works in dev containers where the
# batman/sandcastle wrapper can't create namespaces (piggy#136 /
# amarbel-llc/bats#31). Supplies the VirtualCard default PIN
# non-interactively. Exits non-zero on any failure. No hardware.
#
# drive a slot-9A agent-sign and verify round-trip against fibby
[group('debug')]
debug-fibby-slot-9a-sign:
    #!/usr/bin/env bash
    set -uo pipefail
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    pivy_agent="$pivy_out/bin/pivy-agent"
    fibby_bin="$fibby_out/bin/fibby"
    [[ -x $fibby_bin ]] || { echo "missing $fibby_bin"; exit 1; }
    [[ -x $pivy_agent ]] || { echo "missing $pivy_agent"; exit 1; }

    workdir=$(mktemp -d /tmp/p0sign-XXXXXX)
    fibby_sock="$workdir/pcscd.comm"
    agent_sock="$workdir/a.sock"
    fibby_log="$workdir/fibby.log"
    agent_log="$workdir/agent.log"
    fibby_pid=""
    agent_pid=""
    cleanup() {
      [[ -n $fibby_pid ]] && kill "$fibby_pid" 2>/dev/null || true
      [[ -n $agent_pid ]] && kill "$agent_pid" 2>/dev/null || true
      rm -rf "$workdir"
    }
    trap cleanup EXIT

    echo "=== Starting fibby (virtual, --seed-rfc6979-slot-9a-cert) ==="
    FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
      --seed-rfc6979-slot-9a-cert >"$fibby_log" 2>&1 &
    fibby_pid=$!
    for _ in $(seq 1 50); do [[ -S $fibby_sock ]] && break; sleep 0.1; done
    [[ -S $fibby_sock ]] || { echo "fibby socket never appeared:"; cat "$fibby_log"; exit 1; }

    # Supply the VirtualCard default PIN non-interactively so pivy-agent
    # can unlock the slot-9A sign (PIN policy "once").
    askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
    echo "=== Starting pivy-agent (PCSCLITE_CSOCK_NAME=fibby) ==="
    PCSCLITE_CSOCK_NAME="$fibby_sock" \
      SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force DISPLAY="" \
      PIGGY_TEST_FIB_PIN=123456 \
      "$pivy_agent" -A -D -a "$agent_sock" >"$agent_log" 2>&1 &
    agent_pid=$!
    for _ in $(seq 1 50); do [[ -S $agent_sock ]] && break; sleep 0.1; done
    [[ -S $agent_sock ]] || { echo "agent socket never appeared:"; cat "$agent_log"; cat "$fibby_log"; exit 1; }

    export SSH_AUTH_SOCK="$agent_sock"
    echo "=== ssh-add -L ==="
    ssh-add -L | tee "$workdir/all.pub"
    grep '^ecdsa-sha2-nistp256 ' "$workdir/all.pub" >"$workdir/id.pub" || {
      echo "no ecdsa-sha2-nistp256 identity"; cat "$agent_log"; exit 1; }

    echo "phase0-fibby-slot-9a-sign-smoke" >"$workdir/data"
    read -r ktype kdata _ <"$workdir/id.pub"
    printf 'smoke@fibby %s %s\n' "$ktype" "$kdata" >"$workdir/allowed_signers"

    echo "=== ssh-keygen -Y sign (agent-sign via slot 9A) ==="
    if ! ssh-keygen -Y sign -f "$workdir/id.pub" -U -n file "$workdir/data"; then
      echo "!!! SIGN FAILED"; echo "--- agent log ---"; cat "$agent_log"
      echo "--- fibby trace tail ---"; tail -80 "$fibby_log"; exit 1
    fi

    echo "=== ssh-keygen -Y verify ==="
    if ! ssh-keygen -Y verify -f "$workdir/allowed_signers" -I smoke@fibby \
        -n file -s "$workdir/data.sig" <"$workdir/data"; then
      echo "!!! VERIFY FAILED"; echo "--- agent log ---"; cat "$agent_log"
      echo "--- fibby trace tail ---"; tail -80 "$fibby_log"; exit 1
    fi

    grep -q "GA ECDSA 9A -> 9000" "$fibby_log" || {
      echo "!!! no successful slot-9A GA ECDSA sign in fibby trace"
      tail -80 "$fibby_log"; exit 1; }
    echo
    echo "=== SLOT-9A SIGN ROUND-TRIP OK ==="

# piggy#135 Phase A+B smoke: build piggy-test-sshd, start it (RFC-0001
# handshake over stdout, shutdown on stdin EOF), then (A) connect with an
# ephemeral key and assert a remote `exec`'s stdout + exit-status
# propagate, and (B) connect with agent forwarding (`ssh -A`) and assert
# the remote side sees the forwarded key via `ssh-add -l`. No fibby yet —
# that's Phase D. Exits non-zero on any failure. No hardware.
#
# smoke-test piggy-test-sshd's remote exec and agent-forwarding paths
[group('debug')]
debug-piggy-test-sshd:
    #!/usr/bin/env bash
    set -uo pipefail
    sshd_out=$(nix build .#piggy-test-sshd --no-link --print-out-paths)
    sshd_bin="$sshd_out/bin/piggy-test-sshd"
    [[ -x $sshd_bin ]] || { echo "missing $sshd_bin"; exit 1; }

    workdir=$(mktemp -d /tmp/p135a-XXXXXX)
    hs="$workdir/handshake"
    err="$workdir/stderr"
    fifo="$workdir/stdin.fifo"
    mkfifo "$fifo"
    cookie=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')

    sshd_pid=""
    agent_pid=""
    cleanup() {
      [[ -n $sshd_pid ]] && kill "$sshd_pid" 2>/dev/null || true
      [[ -n $agent_pid ]] && kill "$agent_pid" 2>/dev/null || true
      exec 9>&- 2>/dev/null || true
      rm -rf "$workdir"
    }
    trap cleanup EXIT

    # Start the server with stdin from a fifo so we control EOF (= the
    # RFC-0001 shutdown signal). The child blocks opening the fifo for
    # read until we open it for write on fd 9.
    PIGGY_PLUGIN_COOKIE="$cookie" "$sshd_bin" <"$fifo" >"$hs" 2>"$err" &
    sshd_pid=$!
    exec 9>"$fifo"

    for _ in $(seq 1 50); do [[ -s $hs ]] && break; sleep 0.1; done
    [[ -s $hs ]] || { echo "no handshake line; stderr:"; cat "$err"; exit 1; }
    line=$(head -1 "$hs")
    echo "handshake: $line"

    IFS='|' read -r got_cookie version _transport addr kh_field subproto <<<"$line"
    [[ $got_cookie == "$cookie" ]] || { echo "cookie mismatch"; exit 1; }
    [[ $version == 1 ]] || { echo "version: $version"; exit 1; }
    [[ $subproto == ssh ]] || { echo "subproto: $subproto"; exit 1; }
    port="${addr##*:}"
    kh="${kh_field#known_hosts=}"
    [[ -s $kh ]] || { echo "known_hosts missing: $kh"; exit 1; }

    key="$workdir/id"
    ssh-keygen -t ed25519 -N '' -f "$key" -q

    # Env isolation: run the ssh client with a pristine HOME under
    # `env -i` so the test neither inherits nor fights the operator's ssh
    # config or the home-manager ssh wrapper (which injects
    # `-o UserKnownHostsFile=$SSH_HOME/known_hosts -F $SSH_HOME/config`,
    # winning over our flags via ssh's first-wins -o rule). Both stock
    # ssh ($HOME/.ssh/known_hosts) and the wrapper ($SSH_HOME) then read
    # our ephemeral known_hosts. PATH is preserved so `ssh` resolves.
    client_home="$workdir/clienthome"
    mkdir -p "$client_home/.ssh"
    chmod 700 "$client_home/.ssh"
    cp "$kh" "$client_home/.ssh/known_hosts"
    : >"$client_home/.ssh/config"

    echo "=== remote exec (echo + exit 7) ==="
    out=$(env -i \
      HOME="$client_home" \
      SSH_HOME="$client_home/.ssh" \
      PATH="$PATH" \
      ssh -F "$client_home/.ssh/config" -i "$key" \
        -o IdentitiesOnly=yes \
        -o UserKnownHostsFile="$client_home/.ssh/known_hosts" \
        -o GlobalKnownHostsFile=/dev/null \
        -o StrictHostKeyChecking=yes \
        -o BatchMode=yes \
        -p "$port" testuser@127.0.0.1 \
        'echo hello-from-piggy-sshd; exit 7')
    rc=$?
    echo "stdout: $out"
    echo "exit:   $rc"
    [[ $out == hello-from-piggy-sshd ]] || { echo "!!! unexpected stdout"; cat "$err"; exit 1; }
    [[ $rc -eq 7 ]] || { echo "!!! exit-status not propagated (want 7, got $rc)"; cat "$err"; exit 1; }
    echo "=== PHASE A (exec) OK ==="
    echo

    # --- Phase B: agent forwarding ---
    # Stand up a throwaway local ssh-agent holding the same ephemeral key,
    # connect with `ssh -A`, and confirm the remote `ssh-add -l` (talking
    # to the SSH_AUTH_SOCK piggy-test-sshd injected) sees the key — i.e.
    # the agent channel is forwarded all the way back to our agent.
    agentsock="$workdir/agent.sock"
    eval "$(ssh-agent -a "$agentsock")" >/dev/null
    agent_pid="${SSH_AGENT_PID:-}"
    SSH_AUTH_SOCK="$agentsock" ssh-add "$key" 2>/dev/null
    fp=$(ssh-keygen -lf "$key.pub" | awk '{print $2}')
    echo "local key fingerprint: $fp"

    echo "=== remote ssh-add -l over forwarded agent ==="
    remote_keys=$(env -i \
      HOME="$client_home" \
      SSH_HOME="$client_home/.ssh" \
      SSH_AUTH_SOCK="$agentsock" \
      PATH="$PATH" \
      ssh -A -F "$client_home/.ssh/config" -i "$key" \
        -o IdentitiesOnly=yes \
        -o UserKnownHostsFile="$client_home/.ssh/known_hosts" \
        -o GlobalKnownHostsFile=/dev/null \
        -o StrictHostKeyChecking=yes \
        -o BatchMode=yes \
        -p "$port" testuser@127.0.0.1 \
        'ssh-add -l')
    echo "remote: $remote_keys"
    grep -qF "$fp" <<<"$remote_keys" || {
      echo "!!! forwarded agent did not expose the key"; cat "$err"; exit 1; }
    echo "=== PHASE B (agent forwarding) OK ==="
    echo
    echo "=== PHASE A+B SMOKE OK ==="

# piggy#138 repro: the SSH-forwarded-style agent decrypt against fibby's
# virtual slot-9D. Stands up fibby (virtual, --seed-rfc5903-slot-9d-cert
# + CHUID), points pivy-agent at it (PCSCLITE_CSOCK_NAME), builds a piggy
# store (init + insert — both client-side / direct to fibby), then runs
# `piggy pass show` with PIGGY_AUTH_SOCK=<agent> so the decrypt routes
# through the C `pivy-box stream decrypt` → `piv_box_open_agent`
# ecdh-rebox path (NOT the direct-PCSC path). Dumps the TRACE-level agent
# log + fibby wire trace. No hardware, no SSH transport — this is the
# minimal (transport-free) reproduction of the failing combination from
# #138's 3-axis bisection: C rebox client + on-demand agent unlock +
# fibby. Exits 0 if the decrypt round-trips, non-zero (reproducing #138)
# otherwise.
#
# reproduce the agent rebox decrypt against fibby's virtual slot 9D
[group('debug')]
debug-ssh-via-fibby GDB="":
    #!/usr/bin/env bash
    set -uo pipefail
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    pivy_agent="$pivy_out/bin/pivy-agent"
    pivy_tool="$pivy_out/bin/pivy-tool"
    fibby_bin="$fibby_out/bin/fibby"
    piggy_bin="$piggy_out/bin/piggy"
    for b in "$pivy_agent" "$pivy_tool" "$fibby_bin" "$piggy_bin"; do
      [[ -x $b ]] || { echo "missing $b"; exit 1; }
    done

    workdir=$(mktemp -d /tmp/p138-XXXXXX)
    keepdir=/tmp/p138-last
    rm -rf "$keepdir"; mkdir -p "$keepdir"
    fibby_sock="$workdir/pcscd.comm"
    agent_sock="$workdir/a.sock"
    fibby_log="$workdir/fibby.log"
    agent_log="$workdir/agent.log"
    export PIGGY_STORE_DIR="$workdir/store"
    fibby_pid=""
    agent_pid=""
    cleanup() {
      [[ -n $fibby_pid ]] && kill "$fibby_pid" 2>/dev/null || true
      [[ -n $agent_pid ]] && kill "$agent_pid" 2>/dev/null || true
      # Preserve logs under a stable path for post-mortem (the agent
      # SIGABRTs on the #138 bug; its stderr holds the fatal line).
      cp "$agent_log" "$fibby_log" "$workdir/show.err" "$keepdir/" 2>/dev/null || true
      rm -rf "$workdir"
    }
    trap cleanup EXIT

    echo "=== Starting fibby (virtual, --seed-rfc5903-slot-9d-cert) ==="
    FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
      --seed-rfc5903-slot-9d-cert >"$fibby_log" 2>&1 &
    fibby_pid=$!
    for _ in $(seq 1 50); do [[ -S $fibby_sock ]] && break; sleep 0.1; done
    [[ -S $fibby_sock ]] || { echo "fibby socket never appeared:"; cat "$fibby_log"; exit 1; }

    # Test askpass: hands the agent the VirtualCard default PIN (123456)
    # non-interactively so slot 9D can unlock on-demand during the rebox.
    askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"

    echo "=== Starting pivy-agent (-A -d TRACE, PCSCLITE_CSOCK_NAME=fibby) ==="
    # Passing GDB=1 (`just debug-ssh-via-fibby 1`) wraps the agent in
    # gdb --batch so the SIGABRT (the #138 bug) is caught and a backtrace
    # lands in the agent log. Requires gdb on PATH; symbols depend on the
    # pivy build (see nix/pivy.nix).
    agent_argv=("$pivy_agent" -A -d -a "$agent_sock")
    if [[ -n "{{ GDB }}" ]]; then
      # gdb can't exec pivy's makeWrapper shell shim — target the real
      # ELF (.pivy-agent-unwrapped, not stripped) and replicate the
      # wrapper's libpcsclite LD_PRELOAD ourselves.
      agent_unwrapped="${pivy_agent%/pivy-agent}/.pivy-agent-unwrapped"
      [[ -x $agent_unwrapped ]] || { echo "missing $agent_unwrapped"; exit 1; }
      for lib in /usr/lib/x86_64-linux-gnu/libpcsclite.so.1 \
                 /usr/lib/libpcsclite.so.1 /lib/x86_64-linux-gnu/libpcsclite.so.1; do
        [[ -e $lib ]] && { export LD_PRELOAD="$lib${LD_PRELOAD:+:$LD_PRELOAD}"; break; }
      done
      agent_argv=(gdb -q -batch \
        -ex 'set pagination off' \
        -ex 'set print frame-arguments all' \
        -ex run \
        -ex 'printf "\n=== BACKTRACE ===\n"' \
        -ex 'bt' \
        -ex 'printf "\n=== BACKTRACE FULL ===\n"' \
        -ex 'bt full' \
        --args "$agent_unwrapped" -A -d -a "$agent_sock")
    fi
    PCSCLITE_CSOCK_NAME="$fibby_sock" \
      SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force DISPLAY="" \
      PIGGY_TEST_FIB_PIN=123456 \
      "${agent_argv[@]}" >"$agent_log" 2>&1 &
    agent_pid=$!
    for _ in $(seq 1 50); do [[ -S $agent_sock ]] && break; sleep 0.1; done
    [[ -S $agent_sock ]] || { echo "agent socket never appeared:"; cat "$agent_log"; cat "$fibby_log"; exit 1; }

    echo "=== discover GUID via pivy-tool list (through fibby) ==="
    guid=$(PCSCLITE_CSOCK_NAME="$fibby_sock" "$pivy_tool" list 2>&1 | grep -oiE '[0-9a-f]{32}' | head -1)
    [[ -n $guid ]] || { echo "no GUID found"; cat "$fibby_log"; exit 1; }
    echo "  guid: $guid"

    echo "=== piggy pass init -g $guid (direct to fibby) ==="
    PCSCLITE_CSOCK_NAME="$fibby_sock" "$piggy_bin" pass init -g "$guid" \
      || { echo "init failed"; tail -40 "$fibby_log"; exit 1; }

    plaintext="secret-via-fibby-138"
    echo "=== piggy pass insert -e foo/bar (direct to fibby) ==="
    printf '%s\n' "$plaintext" | PCSCLITE_CSOCK_NAME="$fibby_sock" \
      "$piggy_bin" pass insert -e foo/bar \
      || { echo "insert failed"; tail -40 "$fibby_log"; exit 1; }

    # Decrypt via the agent. PIGGY_AUTH_SOCK overrides SSH_AUTH_SOCK for
    # piggy's own pivy-box child only, so the decrypt hits piv_box_open_agent
    # (rebox) against the agent, NOT fibby's direct-PCSC path. PCSCLITE_CSOCK_NAME
    # is intentionally NOT set here, mirroring the SSH-remote side that has
    # no fibby socket of its own.
    echo "=== piggy pass show foo/bar (PIGGY_AUTH_SOCK=agent → rebox path) ==="
    got=$(PIGGY_AUTH_SOCK="$agent_sock" "$piggy_bin" pass show foo/bar 2>"$workdir/show.err")
    show_rc=$?
    echo "  show exit: $show_rc"
    echo "  show stderr:"; sed 's/^/    /' "$workdir/show.err"
    echo "  got: '$got'"
    echo
    if grep -q '=== BACKTRACE ===' "$agent_log"; then
      echo "=== pivy-agent gdb backtrace ==="
      sed -n '/=== BACKTRACE ===/,$p' "$agent_log"
      echo
    fi
    echo "=== agent crash / extension lines (grep) ==="
    grep -nE 'FATAL|fatal|assert|VERIFY|abort|panic|rebox|ecdh|EXTENSION|extension|failed to process' "$agent_log" || true
    echo
    echo "=== pivy-agent log (last 30 lines) ==="
    tail -30 "$agent_log"
    echo
    echo "=== logs preserved under $keepdir ==="

    if [[ $show_rc -eq 0 && $got == "$plaintext" ]]; then
      echo "=== DECRYPT OK (rebox path works) ==="
      exit 0
    else
      echo "=== DECRYPT FAILED — reproduces #138 ==="
      exit 1
    fi

# piggy#135 Phase D: end-to-end SSH-forwarded decrypt — the realistic
# deployment shape this whole arc is about. Stands up the full stack:
# fibby (virtual, seeded slot-9D ECDH cert) + pivy-agent over fibby + a
# piggy store (init + insert, direct to fibby) + the piggy-test-sshd
# fixture server. Then runs a *remote* `piggy pass show` over `ssh -A`,
# so the decrypt routes through the FORWARDED agent socket back to
# pivy-agent ↔ fibby (not a direct path). No hardware. Exits 0 iff the
# remote decrypt round-trips. This is the debug-recipe scaffold for the
# Phase D bats lane (conformance/piggy_ssh_via_fibby.bats).
#
# run an end-to-end SSH-forwarded piggy pass show decrypt over fibby
[group('debug')]
debug-ssh-decrypt-via-fibby:
    #!/usr/bin/env bash
    set -uo pipefail
    unset PIGGY_AUTH_SOCK  # the remote must use the FORWARDED SSH_AUTH_SOCK
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    sshd_out=$(nix build .#piggy-test-sshd --no-link --print-out-paths)
    pivy_agent="$pivy_out/bin/pivy-agent"
    fibby_bin="$fibby_out/bin/fibby"
    piggy_bin="$piggy_out/bin/piggy"
    sshd_bin="$sshd_out/bin/piggy-test-sshd"
    for b in "$pivy_agent" "$fibby_bin" "$piggy_bin" "$sshd_bin"; do
      [[ -x $b ]] || { echo "missing $b"; exit 1; }
    done

    workdir=$(mktemp -d /tmp/p135d-XXXXXX)
    fibby_sock="$workdir/pcscd.comm"
    agent_sock="$workdir/a.sock"
    fibby_log="$workdir/fibby.log"
    agent_log="$workdir/agent.log"
    sshd_hs="$workdir/handshake"
    sshd_err="$workdir/sshd.err"
    sshd_fifo="$workdir/sshd.fifo"
    store="$workdir/store"
    fibby_pid=""; agent_pid=""; sshd_pid=""
    cleanup() {
      [[ -n $sshd_pid ]] && kill "$sshd_pid" 2>/dev/null || true
      [[ -n $agent_pid ]] && kill "$agent_pid" 2>/dev/null || true
      [[ -n $fibby_pid ]] && kill "$fibby_pid" 2>/dev/null || true
      exec 9>&- 2>/dev/null || true
      rm -rf "$workdir"
    }
    trap cleanup EXIT

    echo "=== Starting fibby (virtual, --seed-rfc5903-slot-9d-cert) ==="
    FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
      --seed-rfc5903-slot-9d-cert >"$fibby_log" 2>&1 &
    fibby_pid=$!
    for _ in $(seq 1 50); do [[ -S $fibby_sock ]] && break; sleep 0.1; done
    [[ -S $fibby_sock ]] || { echo "fibby socket never appeared:"; cat "$fibby_log"; exit 1; }

    # pivy-agent unlocks slot 9D on-demand during the (forwarded) rebox via
    # the test askpass; the unlock happens at this local agent process, the
    # SSH channel only proxies the agent protocol.
    askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
    echo "=== Starting pivy-agent (PCSCLITE_CSOCK_NAME=fibby) ==="
    PCSCLITE_CSOCK_NAME="$fibby_sock" \
      SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force DISPLAY="" \
      PIGGY_TEST_FIB_PIN=123456 \
      "$pivy_agent" -A -D -a "$agent_sock" >"$agent_log" 2>&1 &
    agent_pid=$!
    for _ in $(seq 1 50); do [[ -S $agent_sock ]] && break; sleep 0.1; done
    [[ -S $agent_sock ]] || { echo "agent socket never appeared:"; cat "$agent_log"; cat "$fibby_log"; exit 1; }

    echo "=== piggy pass init + insert (direct to fibby) ==="
    PCSCLITE_CSOCK_NAME="$fibby_sock" PIGGY_STORE_DIR="$store" \
      "$piggy_bin" pass init || { echo "init failed"; tail -40 "$fibby_log"; exit 1; }
    plaintext="ssh-forwarded-decrypt-135d"
    printf '%s\n' "$plaintext" | PCSCLITE_CSOCK_NAME="$fibby_sock" \
      PIGGY_STORE_DIR="$store" "$piggy_bin" pass insert -e foo/bar \
      || { echo "insert failed"; tail -40 "$fibby_log"; exit 1; }

    # piggy-test-sshd: RFC-0001 handshake on stdout, shutdown on stdin EOF.
    mkfifo "$sshd_fifo"
    cookie=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
    echo "=== Starting piggy-test-sshd ==="
    PIGGY_PLUGIN_COOKIE="$cookie" "$sshd_bin" <"$sshd_fifo" >"$sshd_hs" 2>"$sshd_err" &
    sshd_pid=$!
    exec 9>"$sshd_fifo"
    for _ in $(seq 1 50); do [[ -s $sshd_hs ]] && break; sleep 0.1; done
    [[ -s $sshd_hs ]] || { echo "no sshd handshake; stderr:"; cat "$sshd_err"; exit 1; }
    line=$(head -1 "$sshd_hs")
    IFS='|' read -r got_cookie _version _transport addr kh_field _subproto <<<"$line"
    [[ $got_cookie == "$cookie" ]] || { echo "cookie mismatch"; exit 1; }
    port="${addr##*:}"
    kh="${kh_field#known_hosts=}"
    [[ -s $kh ]] || { echo "known_hosts missing: $kh"; exit 1; }

    key="$workdir/id"
    ssh-keygen -t ed25519 -N '' -f "$key" -q
    client_home="$workdir/clienthome"
    mkdir -p "$client_home/.ssh"; chmod 700 "$client_home/.ssh"
    cp "$kh" "$client_home/.ssh/known_hosts"
    : >"$client_home/.ssh/config"

    # `ssh -A` forwards THIS shell's SSH_AUTH_SOCK (= pivy-agent). The
    # server injects a forwarded SSH_AUTH_SOCK into the remote command's
    # env; PIGGY_AUTH_SOCK is unset, so the remote piggy decrypts through
    # the forwarded socket → SSH channel → pivy-agent ↔ fibby.
    echo "=== ssh -A remote 'piggy pass show foo/bar' (forwarded decrypt) ==="
    remote_out=$(env -i \
      HOME="$client_home" \
      SSH_HOME="$client_home/.ssh" \
      SSH_AUTH_SOCK="$agent_sock" \
      PATH="$PATH" \
      ssh -A -F "$client_home/.ssh/config" -i "$key" \
        -o IdentitiesOnly=yes \
        -o UserKnownHostsFile="$client_home/.ssh/known_hosts" \
        -o GlobalKnownHostsFile=/dev/null \
        -o StrictHostKeyChecking=yes \
        -o BatchMode=yes \
        -p "$port" testuser@127.0.0.1 \
        "PIGGY_STORE_DIR=$store $piggy_bin pass show foo/bar")
    rc=$?
    echo "  ssh exit: $rc"
    echo "  remote stdout: $remote_out"
    echo

    if [[ $rc -eq 0 ]] && printf '%s\n' "$remote_out" | grep -Fxq "$plaintext"; then
      echo "=== PHASE D SSH-FORWARDED DECRYPT OK ==="
      exit 0
    else
      echo "=== PHASE D FAILED ==="
      echo "--- agent log tail ---"; tail -60 "$agent_log"
      echo "--- fibby log tail ---"; tail -60 "$fibby_log"
      echo "--- sshd stderr ---"; cat "$sshd_err"
      exit 1
    fi

# piggy#135: regenerate fibby's slot-9C (Digital Signature) test cert. One-shot
# generator — produces a FRESH P-256 key each run. The slot-9C SIGN path uses
# RFC 6979 deterministic ECDSA, so (unlike 9D's ECDH, piggy#134) there is no
# captured wire to byte-replay against: a published vector isn't required, only
# a key distinct from 9A (§A.2.5) and 9D (§8.1). Saves the key PEM under
# tests/fixtures/test-vectors/ as the reproducibility anchor and prints Rust
# byte arrays (scalar + PIV cert-object) to paste into virtual_card.rs as
# FIBBY_SLOT_9C_TEST_PRIV / FIBBY_SLOT_9C_CERT_OBJECT. The cert's ECDSA sig
# uses a random k, so re-running re-pins the const — only do so deliberately.
# Cross-check the printed pubkey is distinct from the 9A/9D points.
#
# regenerate fibby's slot-9C test key and cert
[group('debug')]
debug-fibby-gen-slot-9c-cert:
    #!/usr/bin/env bash
    set -euo pipefail
    dir="crates/fibby/tests/fixtures/test-vectors"
    pem="$dir/fibby-slot-9c-test-priv.pem"
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT

    # Generate until the raw scalar is exactly 32 bytes (64 hex) so the text
    # extraction below is unambiguous (no leading-zero short form).
    scalar=""
    for _ in $(seq 1 16); do
      openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/key.pem"
      scalar=$(openssl pkey -in "$tmp/key.pem" -text -noout 2>/dev/null \
        | sed -n '/priv:/,/pub:/{/priv:/d;/pub:/d;p}' | tr -dc '0-9a-f')
      [[ ${#scalar} -eq 64 ]] && break
      scalar=""
    done
    [[ ${#scalar} -eq 64 ]] || { echo "could not extract a 32-byte scalar" >&2; exit 1; }

    # Self-sign the cert (fixed subject + serial; 100-year validity).
    openssl req -x509 -key "$tmp/key.pem" -subj "/CN=fibby-test-slot-9c" \
      -set_serial 1 -days 36500 -sha256 -outform DER -out "$tmp/cert.der"
    der=$(od -An -tx1 "$tmp/cert.der" | tr -dc '0-9a-f')
    der_len=$(( ${#der} / 2 ))

    ber_len() { # echo BER length bytes (hex) for $1
      local n=$1
      if [[ $n -lt 128 ]]; then printf '%02x' "$n"
      elif [[ $n -lt 256 ]]; then printf '81%02x' "$n"
      else printf '82%02x%02x' $(( (n >> 8) & 255 )) $(( n & 255 )); fi
    }

    # PIV cert object TLV: 53 L1 [ 70 L2 <DER> 71 01 00  FE 00 ]
    inner="70$(ber_len "$der_len")${der}710100fe00"
    inner_len=$(( ${#inner} / 2 ))
    obj="53$(ber_len "$inner_len")${inner}"

    rust_array() { fold -w2 | awk 'BEGIN{ORS=""}{printf "0x%s, ", toupper($0)}'; echo; }

    cp "$tmp/key.pem" "$pem"
    echo "=== wrote $pem ==="
    echo
    echo "=== pubkey (verify DISTINCT from 9A 60FED4BA… / 9D DAD0B653…) ==="
    openssl pkey -in "$pem" -text -noout 2>/dev/null | sed -n '/pub:/,/ASN1 OID/p'
    echo
    echo "=== FIBBY_SLOT_9C_TEST_PRIV (32 bytes) ==="
    printf '%s' "$scalar" | rust_array
    echo
    echo "=== FIBBY_SLOT_9C_CERT_OBJECT ($(( ${#obj} / 2 )) bytes) ==="
    printf '%s' "$obj" | rust_array

# piggy#135 slot-9C sign dev-loop: a non-batman mirror of the
# `pivy_agent_signs_and_verifies_via_seeded_fibby_slot_9c` bats test. Seeds
# fibby's slot 9C (cert + key), points pivy-agent at it, and drives a real
# `ssh-keygen -Y sign -U` + verify round-trip — proving the slot-9C ECDSA sign
# path works end-to-end through pivy-agent. Supplies the VirtualCard PIN
# non-interactively. Exits non-zero on any failure. No hardware.
#
# drive a slot-9C agent-sign and verify round-trip against fibby
[group('debug')]
debug-fibby-slot-9c-sign:
    #!/usr/bin/env bash
    set -uo pipefail
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    pivy_agent="$pivy_out/bin/pivy-agent"
    fibby_bin="$fibby_out/bin/fibby"
    [[ -x $fibby_bin ]] || { echo "missing $fibby_bin"; exit 1; }
    [[ -x $pivy_agent ]] || { echo "missing $pivy_agent"; exit 1; }

    workdir=$(mktemp -d /tmp/p9csign-XXXXXX)
    fibby_sock="$workdir/pcscd.comm"
    agent_sock="$workdir/a.sock"
    fibby_log="$workdir/fibby.log"
    agent_log="$workdir/agent.log"
    fibby_pid=""
    agent_pid=""
    cleanup() {
      [[ -n $fibby_pid ]] && kill "$fibby_pid" 2>/dev/null || true
      [[ -n $agent_pid ]] && kill "$agent_pid" 2>/dev/null || true
      rm -rf "$workdir"
    }
    trap cleanup EXIT

    echo "=== Starting fibby (virtual, --seed-slot-9c-cert) ==="
    FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
      --seed-slot-9c-cert >"$fibby_log" 2>&1 &
    fibby_pid=$!
    for _ in $(seq 1 50); do [[ -S $fibby_sock ]] && break; sleep 0.1; done
    [[ -S $fibby_sock ]] || { echo "fibby socket never appeared:"; cat "$fibby_log"; exit 1; }

    askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
    echo "=== Starting pivy-agent (PCSCLITE_CSOCK_NAME=fibby) ==="
    PCSCLITE_CSOCK_NAME="$fibby_sock" \
      SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force DISPLAY="" \
      PIGGY_TEST_FIB_PIN=123456 \
      "$pivy_agent" -A -D -a "$agent_sock" >"$agent_log" 2>&1 &
    agent_pid=$!
    for _ in $(seq 1 50); do [[ -S $agent_sock ]] && break; sleep 0.1; done
    [[ -S $agent_sock ]] || { echo "agent socket never appeared:"; cat "$agent_log"; cat "$fibby_log"; exit 1; }

    export SSH_AUTH_SOCK="$agent_sock"
    ssh-add -L >"$workdir/id.pub" 2>/dev/null
    grep -q '^ecdsa-sha2-nistp256 ' "$workdir/id.pub" || {
      echo "no ecdsa-sha2-nistp256 identity"; cat "$agent_log"; exit 1; }

    echo "phase-fibby-slot-9c-sign-smoke" >"$workdir/data"
    read -r ktype kdata _ <"$workdir/id.pub"
    printf 'smoke@fibby %s %s\n' "$ktype" "$kdata" >"$workdir/allowed_signers"

    echo "=== ssh-keygen -Y sign (agent-sign via slot 9C) ==="
    if ! ssh-keygen -Y sign -f "$workdir/id.pub" -U -n file "$workdir/data"; then
      echo "!!! SIGN FAILED"; echo "--- agent log ---"; cat "$agent_log"
      echo "--- fibby trace tail ---"; tail -80 "$fibby_log"; exit 1
    fi

    echo "=== ssh-keygen -Y verify ==="
    if ! ssh-keygen -Y verify -f "$workdir/allowed_signers" -I smoke@fibby \
        -n file -s "$workdir/data.sig" <"$workdir/data"; then
      echo "!!! VERIFY FAILED"; echo "--- agent log ---"; cat "$agent_log"
      echo "--- fibby trace tail ---"; tail -80 "$fibby_log"; exit 1
    fi

    grep -q "GA ECDSA 9C -> 9000" "$fibby_log" || {
      echo "!!! no successful slot-9C GA ECDSA sign in fibby trace"
      tail -80 "$fibby_log"; exit 1; }
    echo
    echo "=== SLOT-9C SIGN ROUND-TRIP OK ==="

# piggy#135 GENERATE ASYMMETRIC dev-loop: drive the real `pivy-tool generate`
# client against fibby's virtual card to validate the INS 0x47 request/response
# wire format (no captured fixture exists, so the real client accepting fibby's
# 7F49/86 response is the authoritative format check). Stands up fibby virtual
# with just a CHUID (initialized, empty slots), then runs `pivy-tool -K default
# -a eccp256 generate 9a` (SELECT + mgmt-key auth + GENERATE) and asserts it
# prints a public key. Exits non-zero on failure. No hardware.
#
# piggy#320: run `piggy card init` against a fresh fibby with a slow askpass
# (each secret answered after DELAY seconds, as a human would), first alone,
# then beside a `piggy list` loop, then beside a running `piggy agent -A`.
# Tests whether another client's probe during init's prompts is what makes
# step 7 (management-key rotation) answer 0x6982. No hardware, no tty.
#
# reproduce card init's step-7 0x6982 with and without a concurrent PC/SC client
[group('debug')]
[linux]
debug-card-init-interleave DELAY="3": build-rust
    #!/usr/bin/env bash
    set -uo pipefail
    piggy="$PWD/target/debug/piggy"
    fibby="$PWD/target/debug/fibby"
    test_askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
    workdir=$(mktemp -d /tmp/pg320-XXXXXX)
    trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$workdir"' EXIT
    printf '#!/usr/bin/env bash\nsleep %s\nexec %q "$@"\n' "{{ DELAY }}" "$test_askpass" >"$workdir/slow-askpass"
    chmod +x "$workdir/slow-askpass"
    run_case() {
      local name="$1" interloper="$2" sock="$workdir/$1.comm"
      FIBBY_LOG=debug "$fibby" --socket "$sock" --backend virtual --model yk5 --auto-touch \
        >"$workdir/$name.fibby.log" 2>&1 &
      local fpid=$!
      for _ in $(seq 1 50); do [[ -S $sock ]] && break; sleep 0.1; done
      local ipid=""
      if [[ $interloper == list ]]; then
        ( while :; do PCSCLITE_CSOCK_NAME="$sock" "$piggy" list --format=ndjson >/dev/null 2>&1; sleep 0.5; done ) &
        ipid=$!
      elif [[ $interloper == agent ]]; then
        # The setup the failing runs had: a card agent beside the card.
        PCSCLITE_CSOCK_NAME="$sock" SSH_ASKPASS=/bin/false SSH_ASKPASS_REQUIRE=force DISPLAY= \
          "$piggy" agent -A -a "$workdir/$name.agent.sock" >"$workdir/$name.agent.log" 2>&1 &
        ipid=$!
        sleep 1
      fi
      local rc=0 started=$SECONDS
      PCSCLITE_CSOCK_NAME="$sock" PIGGY_TEST_FIB_PIN=654321 \
        SSH_ASKPASS="$workdir/slow-askpass" SSH_ASKPASS_REQUIRE=force DISPLAY= \
        setsid -w "$piggy" card init --no-seal-management-key <<<"y" \
        >"$workdir/$name.out" 2>"$workdir/$name.err" || rc=$?
      [[ -n $ipid ]] && kill "$ipid" 2>/dev/null
      kill "$fpid" 2>/dev/null
      echo "=== $name (interloper=$interloper): card init exit $rc after $((SECONDS - started)) s"
      echo "fibby: $(grep -c 'DISCONNECT' "$workdir/$name.fibby.log") disconnects, $(grep -c 'END TRANSACTION with reset' "$workdir/$name.fibby.log") reset dispositions, $(grep -c 'VERIFY -> 9000' "$workdir/$name.fibby.log") good VERIFYs"
      grep -E '\[[0-9]/7\]|failed|error' "$workdir/$name.err" | tail -4
    }
    run_case alone none
    run_case beside-list list
    run_case beside-agent agent

# drive pivy-tool generate against fibby to check the GENERATE ASYMMETRIC wire format
[group('debug')]
debug-fibby-generate:
    #!/usr/bin/env bash
    set -uo pipefail
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    pivy_tool="$pivy_out/bin/pivy-tool"
    fibby_bin="$fibby_out/bin/fibby"
    [[ -x $fibby_bin ]] || { echo "missing $fibby_bin"; exit 1; }
    [[ -x $pivy_tool ]] || { echo "missing $pivy_tool"; exit 1; }

    workdir=$(mktemp -d /tmp/pgen-XXXXXX)
    fibby_sock="$workdir/pcscd.comm"
    fibby_log="$workdir/fibby.log"
    fibby_pid=""
    cleanup() {
      [[ -n $fibby_pid ]] && kill "$fibby_pid" 2>/dev/null || true
      rm -rf "$workdir"
    }
    trap cleanup EXIT

    echo "=== Starting fibby (virtual, --seed-chuid: initialized, empty slots) ==="
    FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
      --seed-chuid >"$fibby_log" 2>&1 &
    fibby_pid=$!
    for _ in $(seq 1 50); do [[ -S $fibby_sock ]] && break; sleep 0.1; done
    [[ -S $fibby_sock ]] || { echo "fibby socket never appeared:"; cat "$fibby_log"; exit 1; }

    echo "=== pivy-tool -P 123456 -K default -a eccp256 generate 9a (mgmt-auth + GENERATE) ==="
    # -P supplies the PIN non-interactively; stdin from /dev/null + a timeout
    # so any unexpected interactive prompt fails fast instead of hanging.
    out=$(PCSCLITE_CSOCK_NAME="$fibby_sock" timeout 30 "$pivy_tool" \
      -P 123456 -K default -a eccp256 generate 9a </dev/null 2>&1)
    rc=$?
    echo "$out"
    echo "  pivy-tool exit: $rc"
    echo
    echo "=== fibby wire trace (tail 40) ==="
    tail -40 "$fibby_log"
    echo

    # pivy-tool prints the generated public key as an `ecdsa-sha2-nistp256 ...`
    # SSH line on success.
    if [[ $rc -eq 0 ]] && printf '%s\n' "$out" | grep -q 'ecdsa-sha2-nistp256 ' \
        && grep -q "GENERATE slot=0x9a ECCP256 -> 9000" "$fibby_log"; then
      echo "=== GENERATE OK (pivy-tool generated a key on fibby slot 9A) ==="
      exit 0
    else
      echo "=== GENERATE FAILED ==="
      exit 1
    fi

# piggy#289 list-port inspection recipe: dump C `pivy-tool -j list`, C's human
# `list`, and `piggy tool -j list` side by side against the SAME fibby the
# tool-fibby differential lane uses, for eyeballing the JSON when iterating on
# the list port. The byte-exact regression check is the `list_json_matches_c`
# bats test; this is the manual-inspection companion. No hardware.
# NOTE: run this in-session via `!` (it backgrounds a fibby daemon, which wedges
# just-us / subagent tool-runners on the inherited stdout fd; an interactive `!`
# shell returns in seconds). See the fibby-debug-recipes memory.
#
# capture C pivy-tool -j list JSON against fibby (list-port inspection)
[group('debug')]
debug-tool-list-capture:
    #!/usr/bin/env bash
    set -uo pipefail
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    pivy_tool="$pivy_out/bin/pivy-tool"
    fibby_bin="$PWD/target/debug/fibby"
    piggy_bin="$PWD/target/debug/piggy"
    [[ -x $fibby_bin ]] || { echo "missing $fibby_bin (just build-rust)"; exit 1; }
    [[ -x $pivy_tool ]] || { echo "missing $pivy_tool (nix build .#pivy)"; exit 1; }

    workdir=$(mktemp -d /tmp/tool-list-XXXXXX)
    fibby_sock="$workdir/pcscd.comm"
    fibby_log="$workdir/fibby.log"
    fibby_pid=""
    cleanup() {
      [[ -n $fibby_pid ]] && kill "$fibby_pid" 2>/dev/null || true
      rm -rf "$workdir"
    }
    trap cleanup EXIT

    echo "=== Starting fibby (virtual, slots 9A + 9D + PINFO seeded, tool-fibby lane) ==="
    FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
      --seed-rfc6979-slot-9a-cert --seed-rfc5903-slot-9d-cert --seed-pinfo >"$fibby_log" 2>&1 &
    fibby_pid=$!
    for _ in $(seq 1 50); do [[ -S $fibby_sock ]] && break; sleep 0.1; done
    [[ -S $fibby_sock ]] || { echo "fibby socket never appeared:"; cat "$fibby_log"; exit 1; }

    echo "=== C: pivy-tool -j list (THE SPEC) ==="
    PCSCLITE_CSOCK_NAME="$fibby_sock" timeout 30 "$pivy_tool" -j list </dev/null
    echo
    echo "=== C: pivy-tool list (human, for reference) ==="
    PCSCLITE_CSOCK_NAME="$fibby_sock" timeout 30 "$pivy_tool" list </dev/null
    echo
    echo "=== C: pivy-tool -p list (parseable, piggy#345) ==="
    PCSCLITE_CSOCK_NAME="$fibby_sock" timeout 30 "$pivy_tool" -p list </dev/null
    echo
    for args in "-j list" "list" "-p list"; do
      echo "=== piggy: piggy tool $args ==="
      # shellcheck disable=SC2086 # $args is the deliberately split option list
      PCSCLITE_CSOCK_NAME="$fibby_sock" timeout 30 "$piggy_bin" tool $args </dev/null || true
      echo
    done

# piggy#248 event-driven wake dev-loop: prove fibby's new WAIT_READER_STATE_CHANGE
# (register + reader-state array + async 8-byte notify on `fibby ctl`) actually
# unblocks a REAL SCardGetStatusChange client. fibby-wait-ready is the oracle (a
# get_status_change loop): start fibby with a card + control socket, remove the
# card so fibby-wait-ready blocks waiting for PRESENT, then `fibby ctl insert` and
# confirm fibby-wait-ready returns within its timeout. Exits 0 iff the wake works.
# This is the authoritative empirical check on the old-mode (proto<=4005) wire
# assumption before the agent event source (piggy#248) is built on top. Uses
# cargo debug binaries for fast iteration. No hardware.
#
# validate fibby's event-driven wake against a real SCardGetStatusChange client
[group('debug')]
debug-fibby-get-status-change:
    #!/usr/bin/env bash
    set -uo pipefail
    cargo build -p fibby -p fibby-wait-ready >/dev/null 2>&1 || {
      echo "build failed; rerun to see why:"; cargo build -p fibby -p fibby-wait-ready; exit 1; }
    fibby_bin="$PWD/target/debug/fibby"
    wait_bin="$PWD/target/debug/fibby-wait-ready"
    [[ -x $fibby_bin && -x $wait_bin ]] || { echo "missing debug binaries"; exit 1; }

    workdir=$(mktemp -d /tmp/pgsc-XXXXXX)
    sock="$workdir/pcscd.comm"
    ctl="$workdir/ctl.sock"
    log="$workdir/fibby.log"
    reader="Virtual PCD piggy fibby 00 00"
    fibby_pid=""
    cleanup() { [[ -n $fibby_pid ]] && kill "$fibby_pid" 2>/dev/null || true; rm -rf "$workdir"; }
    trap cleanup EXIT

    echo "=== Starting fibby (virtual, --seed-chuid, --control-socket) ==="
    FIBBY_LOG=wire "$fibby_bin" --socket "$sock" --control-socket "$ctl" \
      --backend virtual --seed-chuid >"$log" 2>&1 &
    fibby_pid=$!
    for _ in $(seq 1 50); do [[ -S $sock && -S $ctl ]] && break; sleep 0.1; done
    [[ -S $sock && -S $ctl ]] || { echo "sockets never appeared:"; cat "$log"; exit 1; }

    echo "=== remove the card so fibby-wait-ready blocks on PRESENT ==="
    "$fibby_bin" ctl --socket "$ctl" remove "$reader"

    echo "=== launch fibby-wait-ready (blocks in SCardGetStatusChange, 8s timeout) ==="
    PCSCLITE_CSOCK_NAME="$sock" timeout 12 "$wait_bin" --reader "$reader" --timeout 8 &
    wait_pid=$!
    sleep 1.5

    echo "=== insert the card -> should wake fibby-wait-ready promptly ==="
    "$fibby_bin" ctl --socket "$ctl" insert "$reader"

    wait "$wait_pid"; rc=$?
    echo "=== fibby-wait-ready exit code: $rc (0 = woke on insert) ==="
    echo "=== fibby wire trace (tail 80) ==="
    tail -80 "$log"
    if [[ $rc -eq 0 ]]; then echo "=== WAKE OK (piggy#248 wire confirmed) ==="; else echo "=== WAKE FAILED ==="; fi
    exit $rc

# Dump the real launchd state of the piggy-agent agent so the `piggy
# health` macOS service probe (point 1) can be grounded in actual
# `launchctl print` output rather than guessed. Read-only: print +
# list only, no load/unload. Serves the piggy-health darwin-service
# design loop.
#
# dump the launchd state of the piggy-agent service
[macos]
[group('explore')]
explore-launchd-piggy-agent label="piggy-agent":
    #!/usr/bin/env bash
    set -uo pipefail
    uid=$(id -u)
    echo "=== launchctl print gui/$uid/{{label}} ==="
    launchctl print "gui/$uid/{{label}}" 2>&1 || echo "  (exit $?)"
    echo
    echo "=== launchctl list {{label}} (legacy) ==="
    launchctl list "{{label}}" 2>&1 || echo "  (exit $?)"
    echo
    echo "=== launchctl print gui/$uid | grep piggy-agent ==="
    launchctl print "gui/$uid" 2>&1 | grep -i piggy-agent || echo "  (no match)"

# Run the dev `piggy health -v` against the live local agent/cards so the
# macOS launchd service probe (point 1) can be eyeballed end-to-end.
# `-v` forces diags onto passing points; `--format tap` keeps output
# deterministic regardless of tty. Serves the piggy-health verify loop.
#
# run piggy health -v --format tap against the live local agent and cards
[group('explore')]
explore-piggy-health *ARGS:
    cargo run -q -p piggy -- health -v --format tap {{ARGS}}

# Print this host's piggy agent unit log for a window (read only): the front's
# lines for a refused sign ("sign request timed out" names the upstream).
# SINCE and UNTIL are journalctl times, e.g. "2026-11-23 12:55".
#
# print the user unit's journal for a time window
[group('explore')]
[linux]
explore-agent-log SINCE UNTIL UNIT="piggy-agent.service":
    journalctl --user -u {{ UNIT }} --since "{{ SINCE }}" --until "{{ UNTIL }}" --no-pager

# Run the pigtrough pilot pass (docs/plans/2026-11-16-pigtrough-pilot-runbook.md)
# start to finish with no terminal, in a throwaway runtime dir: start
# `serve`, print each check's command and result, stop `serve`, remove the
# dir. BIN is a built pigtrough (the `nix build .#pigtrough` output); the
# recipe builds nothing.
#   PHASE=pre-load touches no secret and no network: the fail-closed 503 and
#     the fixed 403 refusals.
#   PHASE=loaded also loads github/forgejo-mirror from the operator's own
#     store (PIGGY_STORE_DIR unset; a card decrypt) and makes three read-only
#     GETs to api.github.com: the direct unauthenticated baseline, the
#     proxied call, and the proxied call with a bogus client Authorization.
#     The token goes from `piggy pass show` straight into `pigtrough load`;
#     only status lines and x-ratelimit-limit are printed.
#   PHASE=proc loads the same secret (read once into the check's memory),
#     makes no GitHub call, and runs runbook step 6 on the loaded serve:
#     cmdline, environ, open fds, the serve log, the dumpable state and
#     ptrace access; each artifact is searched for the exact token and for
#     the ghp_/github_pat_ prefixes, printing only counts and PASS/FAIL.
#   PHASE=proc-fake is PHASE=proc with a fixed fake token and no card: it
#     checks the step-6 plumbing itself. The fake token has the ghp_ prefix
#     on purpose, so a leak of it would show in both counts.
#
# run the pigtrough pilot pass against a throwaway runtime dir (PHASE=pre-load, loaded or proc)
[group('explore')]
[linux]
explore-pigtrough-pilot-pass BIN PHASE="pre-load":
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{ PHASE }}" in
      pre-load | loaded | proc | proc-fake) ;;
      *)
        echo "PHASE is pre-load, loaded, proc or proc-fake" >&2
        exit 2
        ;;
    esac
    bin="{{ BIN }}"
    [[ -x $bin ]] || {
      echo "not executable: $bin" >&2
      exit 2
    }
    # Not $TMPDIR: a worktree's .tmp is too deep for a unix socket path.
    base=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/pigtrough-pilot.XXXXXX")
    run=$base/run
    log=$base/serve.log
    serve_pid=""
    cleanup() {
      if [[ -n $serve_pid ]]; then
        # TERM, not INT: bash starts background jobs with SIGINT ignored.
        kill -TERM "$serve_pid" 2>/dev/null || true
        wait "$serve_pid" 2>/dev/null || true
        if pgrep -f "serve --dir $run" >/dev/null; then
          echo "--- serve STILL RUNNING after TERM"
        else
          echo "--- no serve process left"
        fi
      fi
      echo
      echo "--- serve output"
      cat "$log" 2>/dev/null || true
      rm -rf "$base"
      if [[ -e $base ]]; then echo "--- $base NOT removed"; else echo "--- removed $base"; fi
    }
    trap cleanup EXIT
    "$bin" serve --dir "$run" >"$log" 2>&1 &
    serve_pid=$!
    for _ in $(seq 50); do
      [[ -S $run/proxy.sock && -S $run/control.sock ]] && break
      sleep 0.1
    done
    [[ -S $run/proxy.sock ]] || {
      echo "serve did not come up" >&2
      exit 1
    }
    echo "--- runtime dir and sockets (uid $(id -u))"
    stat -c '%a %u %F %n' "$run" "$run/proxy.sock" "$run/control.sock"
    sock=$run/proxy.sock
    api=http://pigtrough/github-api
    repo=repos/amarbel-llc/piggy
    full() {
      echo
      echo "\$ curl -i --unix-socket proxy.sock $*"
      curl -sS -i --max-time 10 --path-as-is --unix-socket "$sock" "$@"
      echo
    }
    short() {
      echo
      echo "\$ curl -i --unix-socket proxy.sock $* | grep status, x-ratelimit-limit"
      curl -sS -i --max-time 30 --unix-socket "$sock" "$@" |
        grep -i -e '^HTTP/' -e '^x-ratelimit-limit' || true
    }
    # Runbook step 6. The token is read once, kept in this shell's memory
    # only (never exported, never an argument: printf is a builtin and grep
    # reads it as a pattern file through a pipe), and never printed, nor its
    # length or a hash. Each artifact is searched for the exact token and
    # for GitHub's token prefixes; only counts and PASS/FAIL are printed.
    run_step_6() {
      local token pid=$serve_pid fails=0 artifact
      if [[ "{{ PHASE }}" == proc-fake ]]; then
        echo "\$ (a fixed fake token, no card)   (into this check's memory, then into pigtrough load)"
        token=ghp_pigtroughPilotFakeTokenNotASecret0000
      else
        echo "\$ piggy pass show github/forgejo-mirror   (into this check's memory, then into pigtrough load)"
        token=$(
          unset PIGGY_STORE_DIR
          piggy pass show github/forgejo-mirror
        )
      fi
      [[ -n $token ]] || {
        echo "FAIL: empty secret"
        return 1
      }
      printf '%s\n' "$token" | "$bin" load github-api --dir "$run"
      mkdir "$base/step6"
      tr '\0' '\n' <"/proc/$pid/cmdline" >"$base/step6/cmdline"
      cp "$log" "$base/step6/serve.log"
      if cat "/proc/$pid/environ" >"$base/step6/environ" 2>/dev/null; then
        echo "environ: READABLE"
      else
        echo "environ: not readable ($(cat "/proc/$pid/environ" 2>&1 >/dev/null | sed 's/.*: //'))"
        rm -f "$base/step6/environ"
      fi
      if ls -l "/proc/$pid/fd" >"$base/step6/fds" 2>/dev/null; then
        echo "open fds: listed, $(($(wc -l <"$base/step6/fds") - 1)) entries:"
        sed 's/.* \([0-9]* -> .*\)/  \1/' "$base/step6/fds" | tail -n +2 | sed "s|$run|run|"
      else
        echo "open fds: not listable ($(ls "/proc/$pid/fd" 2>&1 >/dev/null | sed 's/.*: //'))"
        rm -f "$base/step6/fds"
      fi
      echo "cmdline: $(tr '\n' ' ' <"$base/step6/cmdline" | sed "s|$run|run|")"
      echo "dumpable: $(grep -i '^dumpable' "/proc/$pid/status" || echo "no Dumpable field in /proc/<pid>/status on this kernel")"
      stat -c 'owner of /proc/<pid>/environ: uid %u' "/proc/$pid/environ"
      stat -c 'owner of /proc/<pid>/fd: uid %u (serve runs as uid '"$(id -u)"')' "/proc/$pid/fd"
      if (exec 3<"/proc/$pid/mem") 2>/dev/null; then
        echo "ptrace access (open /proc/<pid>/mem): ALLOWED"
      else
        echo "ptrace access (open /proc/<pid>/mem): refused"
      fi
      # Positive control, through a pipe (the token is never written to a
      # file): the same searches must find it, else a 0 below proves nothing.
      local control_exact control_prefix
      control_exact=$(printf '%s\n' "$token" | grep -c -F -f <(printf '%s\n' "$token") || true)
      control_prefix=$(printf '%s\n' "$token" | grep -c -E 'ghp_|github_pat_' || true)
      echo "control (the token itself, via a pipe): token matches $control_exact (must be 1), ghp_/github_pat_ matches $control_prefix (1 if the token has one of these prefixes)"
      [[ $control_exact == 1 ]] || {
        echo "FAIL: the search cannot find the token; step 6 is void"
        unset token
        return 1
      }
      for artifact in "$base"/step6/*; do
        local exact prefix
        exact=$(grep -a -c -F -f <(printf '%s\n' "$token") "$artifact" || true)
        prefix=$(grep -a -c -E 'ghp_|github_pat_' "$artifact" || true)
        if [[ $exact == 0 && $prefix == 0 ]]; then
          echo "PASS ${artifact##*/}: token matches 0, ghp_/github_pat_ matches 0"
        else
          echo "FAIL ${artifact##*/}: token matches $exact, ghp_/github_pat_ matches $prefix"
          fails=$((fails + 1))
        fi
      done
      unset token
      echo "step 6: $fails artifact(s) failed"
      [[ $fails == 0 ]]
    }
    full "$api/$repo"
    if [[ "{{ PHASE }}" == pre-load ]]; then
      full -H 'Authorization: Bearer not-a-token' "$api/$repo"
      full "$api/user"
      full "$api/repos/someone-else/repo"
      full -X DELETE "$api/$repo"
      full "http://pigtrough/elsewhere/x"
      full "$api/repos/amarbel-llc/%2e%2e"
      exit 0
    fi
    echo
    if [[ "{{ PHASE }}" == loaded ]]; then
      echo "\$ piggy pass show github/forgejo-mirror | pigtrough load github-api --dir run"
      (
        unset PIGGY_STORE_DIR
        piggy pass show github/forgejo-mirror
      ) | "$bin" load github-api --dir "$run"
    else
      run_step_6
      exit 0
    fi
    echo
    echo "\$ curl -i https://api.github.com/$repo | grep status, x-ratelimit-limit   (direct, no token)"
    curl -sS -i --max-time 30 "https://api.github.com/$repo" |
      grep -i -e '^HTTP/' -e '^x-ratelimit-limit' || true
    short "$api/$repo"
    short -H 'Authorization: Bearer not-a-token' "$api/$repo"

# Stop any `pigtrough serve` a killed explore-pigtrough-pilot-pass left
# running, and remove its throwaway runtime dirs.
#
# clean up after an interrupted explore-pigtrough-pilot-pass
[group('explore')]
[linux]
explore-pigtrough-pilot-pass-clean:
    #!/usr/bin/env bash
    set -uo pipefail
    pattern="pigtrough serve --dir ${XDG_RUNTIME_DIR:-/tmp}/pigtrough-pilot\."
    pgrep -af "$pattern" || echo "no leftover serve"
    pkill -TERM -f "$pattern" && sleep 1
    pgrep -af "$pattern" && echo "still running" || echo "no serve running"
    for d in "${XDG_RUNTIME_DIR:-/tmp}"/pigtrough-pilot.*; do
      [[ -e $d ]] || continue
      rm -rf "$d" && echo "removed $d"
    done

# Slice 4 of the pigtrough loopback listener (docs/plans/2026-11-17-
# pigtrough-listener-options.md): how reliably /proc/net/tcp attributes the
# owner of a loopback client. Runs the ignored tests of
# crates/pigtrough/tests/admission_probe.rs: 800 concurrent same-user
# connections, 300 clients gone before the lookup, ::1 refused, and the
# other-uid and network-namespace cases, which print NOT TESTED with the
# reason where they cannot run here. No credential, loopback only, no
# pigtrough binary; prints only the COUNTS lines. One cargo run.
#
# count the loopback peer-uid attribution cases (pigtrough listener, slice 4)
[group('explore')]
[linux]
explore-pigtrough-admission:
    #!/usr/bin/env bash
    set -uo pipefail
    cargo test -p pigtrough --test admission_probe -- --ignored --test-threads=1 --nocapture 2>&1 \
      | grep -E 'COUNTS |^test result|panicked|error(\[|:)' || true

# Stage the hand pass that closes piggy#303 (FDR 0006 phase (a), "Phase
# acceptance"): open a shell with everything the operator needs to read the
# prompts, drive the new verbs and misuse them, and print the checklist.
#
# CARD=virtual (the default) touches no real card: a private fibby card, a
# private piggy agent on it with a stock ssh-agent as its software upstream,
# and PCSCLITE_CSOCK_NAME / SSH_AUTH_SOCK / PIGGY_AUTH_SOCK pointed at them,
# with PIGGY_STORE_DIR an empty private store.
# The card wants a real touch decision: `fdr-touch &` grants the next one.
#   PROMPTS=test (the default) answers every PIN prompt with the virtual
#     card's PIN through the test askpass and prints what the prompt carried:
#     nothing can reach a real dialog (piggy-testing(7) PIN PROMPT SAFETY NET).
#   PROMPTS=real runs contrib/piggy-askpass.sh, so the operator SEES the real
#     dialogs, against the virtual card only (its PIN is 123456). Start each
#     text with `piggy-test:` and the dialog carries a [TEST] banner.
#   PROMPTS=gtk is PROMPTS=real with PIGGY_ASKPASS_GTK=1 in the agent's
#     environment, so the operator sees the GTK 4 helper's dialogs.
# CARD=real is the explicit flag for the real-card half of the pass. It
# starts nothing and redirects nothing: the shell talks to the host's pcscd
# and the operator's own agent, and every prompt is a real one.
# RUN, when given, is run with `bash -c` in that environment instead of the
# shell (how the recipe itself is checked without a terminal).
#
# stage the piggy#303 hand pass: a shell on a virtual card (or, CARD=real, the real one) plus the checklist
[group('explore')]
[linux]
explore-fdr0006-a CARD="virtual" PROMPTS="test" RUN="":
    #!/usr/bin/env bash
    set -euo pipefail
    card="{{ CARD }}"
    prompts="{{ PROMPTS }}"
    run={{ quote(RUN) }}
    case "$card" in virtual | real) ;; *) echo "CARD must be virtual or real, not '$card'" >&2; exit 2 ;; esac
    case "$prompts" in test | real | gtk) ;; *) echo "PROMPTS must be test, real or gtk, not '$prompts'" >&2; exit 2 ;; esac

    piggy_out=$(nix build .#default --no-link --print-out-paths)
    dir="$(mktemp -d -t fdr6a.XXXXXX)"
    mkdir "$dir/bin"
    ln -s "$piggy_out/bin/piggy" "$dir/bin/piggy"
    export PATH="$dir/bin:$PATH"
    export FDR0006_DIR="$dir"

    cat >"$dir/CHECKLIST" <<'CHECKLIST_EOF'
    piggy#303 hand pass (FDR 0006 phase (a)). `cat $FDR0006_DIR/CHECKLIST` shows this again.
    Work in $FDR0006_DIR (cd there); comment on piggy#303 with what you ran,
    on which host and card, and what you sent back. The operator closes #303.

    1. UX REVIEW: read, do not run
       piggy operator-sign --help          piggy card init --help
       piggy card add-key --help           piggy card export-attestation --help
       man piggy-agent   (OPERATOR ACTS, SCOPES, ENVIRONMENT)     man piggy   (operator-sign)

    2. PROVISION (virtual card, or a THROWAWAY YubiKey; never a card you rely on)
       piggy card init                     # new defaults: 9A once/cached, 9C always/always
       piggy health --format tap           # per-slot policy points; "can sign operator acts"
       piggy list --format=ndjson          # pin_policy / touch_policy per slot
       piggy card export-attestation > 9c.attestation ; cat 9c.attestation
       piggy card init                     # again, on the provisioned card: must refuse
       piggy card add-key 9c               # occupied: must refuse without --replace
       (the agent picks the new keys up on its next card check: ssh-add -L shows PIV_slot_9C)
       virtual card: signing waits for a touch. `fdr-touch &` BEFORE the command
       grants the next one asked for; card init asks for two (`fdr-touch 2 &`).
       PROMPTS=test: keep the card's PIN 123456, the test askpass answers with it.

    3. OPERATOR ACT: read the prompt before you type
       printf 'piggy-test: grant merge to master\n' > grant.txt
       piggy operator-sign --namespace piggy-escalation-v1 < grant.txt > grant.sig ; echo "exit $?"
       ssh-add -L | awk '/PIV_slot_9C/ {print "operator", $1, $2}' > allowed_signers
       ssh-keygen -Y verify -f allowed_signers -I operator -n piggy-escalation-v1 -s grant.sig < grant.txt
       Repeat with --namespace piggy-certificate-v1 and piggy-quote-v1: is each prompt
       visibly its own, and the escalation the strongest?
       Try a 4096-byte text: does the dialog show ALL of it (it must, or fail)?
       Try text with <b>markup</b> & an under_score and a back\slash: shown literally?

    4. MISUSE: each must refuse, with an exit code you could script against
       piggy operator-sign --namespace piggy-escalation-v1 --slot 9a < grant.txt   # 1 refused-policy
       piggy operator-sign --namespace git < grant.txt                              # 1 not a namespace
       piggy operator-sign --namespace piggy-escalation-v1 < /dev/null              # 1 no text
       PIGGY_AUTH_SOCK=/nonexistent piggy operator-sign --namespace piggy-escalation-v1 < grant.txt   # 3
       ssh-add -L | grep PIV_slot_9C > 9c.pub
       ssh-keygen -Y sign -f 9c.pub -U -n piggy-escalation-v1 grant.txt             # must be refused
       ssh-keygen -Y sign -f 9c.pub -U -n file grant.txt                            # ordinary: allowed

    5. QA: break it on purpose (each is exit 4 unless noted)
       cancel the PIN prompt                       -> cancelled
       enter the PIN, then do not touch            -> cancelled after the card's timeout
       enter the PIN, pull the card before touching
       pull the card, then ask                     -> card-absent (or exit 1 no key, once the agent drops it)
       Was there a visible notice when the card started waiting for the touch?

    6. TIER 1: software keys through the piggy socket
       ssh-keygen -t ed25519 -N '' -f soft -C piggy-test-soft ; ssh-add soft ; ssh-add -L
       ssh-keygen -Y sign -f soft.pub -U -n file grant.txt   (then verify as in 3, with -n file)
       stop the software upstream (virtual: fdr-stop-software); ssh-add -L must still list the card's keys
       On your own host this is services.piggy-agent.softwareKeys.enable = true.

    NOT COVERED BY THE AUTOMATED LANES: yours to judge on a real card and display
       - what the three operator-act dialogs (piggy-askpass-gtk) look like, and whether a long text shows whole
       - whether the touch notice reaches you where you are looking
       - the attestation chain to a Yubico root, and the real F9 certificate
         (openssl verify -partial_chain -CAfile f9.pem attestation.pem)
    CHECKLIST_EOF

    cleanup() {
      local pid
      for pid in "${agent_pid:-}" "${soft_pid:-}" "${fibby_pid:-}"; do
        [[ -n $pid ]] && kill "$pid" 2>/dev/null || true
      done
      rm -rf "$dir"
    }
    trap cleanup EXIT

    if [[ $card == real ]]; then
      echo "CARD=real: nothing is redirected. Prompts, PINs and touches below are REAL."
      echo "pcscd: the host's.  agent: ${PIGGY_AUTH_SOCK:-${SSH_AUTH_SOCK:-<no agent socket set>}}"
      echo "Use a THROWAWAY card for step 2. Steps marked 'virtual' do not apply."
    else
      fibby_out=$(nix build .#fibby --no-link --print-out-paths)
      reader="Virtual PCD piggy fibby 00 00"
      export PCSCLITE_CSOCK_NAME="$dir/pcscd.comm"
      # A private, empty store: card init must not offer to seal a virtual
      # card's management key into the operator's own.
      export PIGGY_STORE_DIR="$dir/store"
      FIBBY_LOG=info "$fibby_out/bin/fibby" --socket "$PCSCLITE_CSOCK_NAME" --backend virtual \
        --control-socket "$dir/control.sock" --model yk5 --serial 12345678 >"$dir/fibby.log" 2>&1 &
      fibby_pid=$!

      # fdr-remove / fdr-insert: pull and replace the card.
      # fdr-touch [N]: grant the next N (default 1) touches the card asks
      # for, waiting up to two minutes (`fdr-touch &` before the command
      # that will ask); `fdr-touch now` grants one that is already pending.
      for verb in touch remove insert; do
        printf '#!/usr/bin/env bash\nexec %q ctl --socket %q %s %q\n' \
          "$fibby_out/bin/fibby" "$dir/control.sock" "$verb" "$reader" >"$dir/bin/fdr-$verb"
        chmod +x "$dir/bin/fdr-$verb"
      done
      mv "$dir/bin/fdr-touch" "$dir/bin/fdr-touch-now"
      cat >"$dir/bin/fdr-touch" <<'TOUCH_EOF'
    #!/usr/bin/env bash
    [[ ${1:-} == now ]] && exec fdr-touch-now
    want=${1:-1}
    asked() { grep -c 'TOUCH needed' "$FDR0006_DIR/fibby.log" 2>/dev/null || true; }
    before=$(asked)
    granted=0
    for _ in $(seq 1 1200); do
      if (($(asked) > before + granted)); then
        fdr-touch-now >/dev/null
        granted=$((granted + 1))
        ((granted == want)) && exit 0
      fi
      sleep 0.1
    done
    echo "fdr-touch: the card asked for $granted of $want touches in two minutes" >&2
    exit 1
    TOUCH_EOF
      chmod +x "$dir/bin/fdr-touch"

      if [[ $prompts == test ]]; then
        export SSH_ASKPASS="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
        export SSH_ASKPASS_REQUIRE=force
        export DISPLAY=""
        export PIGGY_TEST_FIB_PIN=123456
        export PIGGY_TEST_FIB_MGMT_KEY=default
        # The touch notice lands in $FDR0006_DIR/notices, not on a desktop.
        printf '#!/usr/bin/env bash\nprintf "%%s | %%s\\n" "$1" "$2" >>"$FDR0006_DIR/notices"\n' >"$dir/bin/fdr-notifier"
        chmod +x "$dir/bin/fdr-notifier"
        export PIGGY_ASKPASS_NOTIFIER="$dir/bin/fdr-notifier"
        echo "PROMPTS=test: PIN prompts are answered for you; what each carried is in $dir/agent.log"
        echo "Touch notices are recorded in $dir/notices"
      else
        export SSH_ASKPASS="$PWD/contrib/piggy-askpass.sh"
        # Without force the agent would read the PIN from this terminal
        # and the dialogs under review would never appear.
        export SSH_ASKPASS_REQUIRE=force
        # The dialogs are opened by the AGENT, so the opt-in must be in the
        # environment it is started with, not just in the RUN shell.
        # contrib/piggy-askpass.sh is run directly here, not through the nix
        # wrapper that puts the helper on PATH, so put it there ourselves.
        if [[ $prompts == gtk ]]; then
          gtk_out=$(nix build .#piggy-askpass-gtk --no-link --print-out-paths)
          export PATH="$gtk_out/bin:$PATH" PIGGY_ASKPASS_GTK=1
        fi
        echo "PROMPTS=$prompts: you will see real dialogs, for the VIRTUAL card. Its PIN is 123456."
        echo "Begin each text with 'piggy-test:' so the dialog carries a [TEST] banner."
      fi

      ssh-agent -D -a "$dir/soft.sock" >/dev/null 2>&1 &
      soft_pid=$!
      "$dir/bin/piggy" agent -A -a "$dir/agent.sock" \
        --upstream "software=$dir/soft.sock" --add-new-keys-to software >"$dir/agent.log" 2>&1 &
      agent_pid=$!
      for _ in $(seq 1 50); do [[ -S $dir/agent.sock ]] && break; sleep 0.1; done
      [[ -S $dir/agent.sock ]] || { echo "the agent did not come up:" >&2; cat "$dir/agent.log" >&2; exit 1; }
      export SSH_AUTH_SOCK="$dir/agent.sock" PIGGY_AUTH_SOCK="$dir/agent.sock"
      printf '#!/usr/bin/env bash\nkill %s\n' "$soft_pid" >"$dir/bin/fdr-stop-software"
      chmod +x "$dir/bin/fdr-stop-software"
      echo "CARD=virtual: a blank virtual card (PIN 123456, default management key)."
      echo "Helpers: fdr-touch [N|now]  fdr-remove  fdr-insert  fdr-stop-software"
      echo "Logs: $dir/agent.log  $dir/fibby.log"
    fi

    cd "$dir"
    if [[ -n $run ]]; then
      bash -c "$run"
      exit
    fi
    echo
    cat "$dir/CHECKLIST"
    PS1="(fdr0006-a:$card) ${PS1:-\\$ }" "${SHELL:-bash}" || true

# The piggy#303 operator-act prompt checks on a host with no GUI: drive
# contrib/piggy-askpass.sh's /dev/tty render target with expect(1) end to
# end (piggy agent on a private fibby card, then `piggy operator-sign`).
# expect gives the agent a PRIVATE pty as its controlling terminal, so the
# askpass renders there; the whole run is under `setsid -w`, so nothing can
# reach the operator's own tty. This is the terminal rendering only: what
# zenity draws is piggy#315 (recorded argv) and piggy#316 (Xvfb screenshots).
#
# drive the operator-act askpass tty prompt with expect against a virtual card (piggy#303)
[group('explore')]
[linux]
explore-fdr0006-a-askpass-tty:
    #!/usr/bin/env bash
    set -euo pipefail
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    expect_out=$(nix build --inputs-from . nixpkgs-master#expect --no-link --print-out-paths)
    cargo build -p card-frontend-server --quiet
    dir="$(mktemp -d -t fdr6a-tty.XXXXXX)"
    export DIR="$dir" PIGGY="$piggy_out/bin/piggy" ASKPASS="$PWD/contrib/piggy-askpass.sh"
    export PCSCLITE_CSOCK_NAME="$dir/pcscd.comm" PIGGY_STORE_DIR="$dir/store"
    export PIGGY_AUTH_SOCK="$dir/agent.sock" SSH_AUTH_SOCK="$dir/agent.sock"
    # No askpass may fall through to a GUI or the operator's terminal.
    unset DISPLAY WAYLAND_DISPLAY SSH_ASKPASS SSH_ASKPASS_REQUIRE
    pids=()
    cleanup() { kill "${pids[@]}" 2>/dev/null || true; rm -rf "$dir"; }
    trap cleanup EXIT

    "$fibby_out/bin/fibby" --socket "$PCSCLITE_CSOCK_NAME" --backend virtual \
      --model yk5 --auto-touch >"$dir/fibby.log" 2>&1 &
    pids+=($!)
    "$PWD/target/debug/card-frontend-server" --socket "$dir/frontend.sock" \
      --pin 123456 --puk 12345678 --mgmt-source random >"$dir/frontend.log" 2>&1 &
    pids+=($!)
    for _ in $(seq 1 50); do [[ -S $dir/frontend.sock ]] && break; sleep 0.1; done
    "$PIGGY" card init --frontend jsonrpc --socket "$dir/frontend.sock" </dev/null >/dev/null

    printf 'piggy-test: T1 grant merge to master\n' >"$dir/t1.txt"
    printf 'piggy-test: T2 certify key ssh-ed25519 AAAA-test\n' >"$dir/t2.txt"
    printf 'piggy-test: T3 quote this line\n' >"$dir/t3.txt"
    { printf 'piggy-test: T4 long text\n'
      for i in $(seq 1 60); do printf 'line %02d %s\n' "$i" "$(printf 'x%.0s' $(seq 1 52))"; done
      printf 'LAST LINE of the long text\n'; } >"$dir/t4.txt"
    printf 'piggy-test: T5 <b>markup</b> & an under_score and a back\\slash\n' >"$dir/t5.txt"

    cat >"$dir/acts.exp" <<'EXPECT_EOF'
    set timeout 60
    set dir $env(DIR)
    # The agent's controlling terminal is this private pty; the askpass it
    # spawns opens /dev/tty and renders there.
    spawn -noecho env SSH_ASKPASS=$env(ASKPASS) $env(PIGGY) agent -A -a $dir/agent.sock
    for {set i 0} {$i < 100 && ![file exists $dir/agent.sock]} {incr i} { after 100 }
    # Wait for the agent to have the card's 9C key before the first act.
    for {set i 0} {$i < 100} {incr i} {
      if {![catch {exec ssh-add -L} keys] && [string match *PIV_slot_9C* $keys]} break
      after 200
    }
    set fh [open $dir/allowed_signers w]
    foreach line [split $keys "\n"] {
      if {[string match *PIV_slot_9C* $line]} { puts $fh "operator [lrange $line 0 1]" }
    }
    close $fh
    # One act: start operator-sign in the background, capture everything the
    # askpass drew up to its PIN line into NAME.screen, then answer with PIN
    # (or ^D to cancel) and, for an escalation, WORD.
    proc act {name ns file pin word} {
      global dir spawn_id
      exec sh -c "\"\$PIGGY\" operator-sign --namespace $ns <$dir/$file >$dir/$name.sig 2>$dir/$name.err; echo \$? >$dir/$name.rc" &
      expect {
        -re {PIN for card [0-9A-F]+ to sign this operator act\r?\n} {
          set fh [open $dir/$name.screen w]; puts -nonewline $fh $expect_out(buffer); close $fh
        }
        timeout { set fh [open $dir/$name.screen w]; puts $fh "TIMEOUT waiting for the PIN line"; close $fh; return }
      }
      if {$pin eq "^D"} { send "\x04" } else { send "$pin\r" }
      if {$word ne ""} {
        expect {
          -exact "Type ESCALATE to grant this escalation: " { send "$word\r" }
          timeout {}
        }
      }
      for {set i 0} {$i < 300 && ![file exists $dir/$name.rc]} {incr i} {
        expect -timeout 0 -re {.+} {}
        after 100
      }
    }
    act esc   piggy-escalation-v1  t1.txt 123456 ESCALATE
    act cert  piggy-certificate-v1 t2.txt 123456 ""
    act quote piggy-quote-v1       t3.txt 123456 ""
    act long  piggy-escalation-v1  t4.txt 123456 ESCALATE
    act markup piggy-escalation-v1 t5.txt 123456 ESCALATE
    act cancel piggy-escalation-v1 t1.txt ^D ""
    act wrongword piggy-escalation-v1 t1.txt 123456 nope
    EXPECT_EOF
    setsid -w "$expect_out/bin/expect" "$dir/acts.exp" </dev/null >"$dir/expect.log" 2>&1 || true
    for f in "$dir"/*.screen; do
      printf '\n# ----- %s\n' "$(basename "$f")"
      sed 's/^/# /' "$f"
    done
    printf '\n# ----- operator-sign stderr\n'
    for f in "$dir"/*.err; do printf '# %s: %s\n' "$(basename "$f" .err)" "$(tr '\n' ' ' <"$f")"; done

    # acts.exp wrote the 9C key while its agent was alive.
    touch "$dir/allowed_signers"
    n=0 fails=0
    check() { # check DESCRIPTION COMMAND...
      n=$((n + 1))
      if "${@:2}" >/dev/null 2>&1; then echo "ok $n - $1"; else echo "not ok $n - $1"; fails=$((fails + 1)); fi
    }
    rc_is() { [[ $(cat "$dir/$1.rc" 2>/dev/null) == "$2" ]]; }
    shows() { grep -qF -- "$2" "$dir/$1.screen"; }
    verifies() { ssh-keygen -Y verify -f "$dir/allowed_signers" -I operator -n "$2" -s "$dir/$1.sig" <"$dir/$3"; }
    echo "TAP version 14"
    check "escalation: banner"                 shows esc '!!! OPERATOR ACT: ESCALATION'
    check "escalation: [TEST] tag"             shows esc '[TEST]'
    check "escalation: the operator's text"    shows esc 'piggy-test: T1 grant merge to master'
    check "escalation: signed (exit 0)"        rc_is esc 0
    check "escalation: sshsig verifies"        verifies esc piggy-escalation-v1 t1.txt
    check "certificate: banner"                shows cert '=== OPERATOR ACT: CERTIFICATE'
    check "certificate: the operator's text"   shows cert 'piggy-test: T2 certify key'
    check "certificate: signed, verifies"      verifies cert piggy-certificate-v1 t2.txt
    check "quote: banner"                      shows quote '=== OPERATOR ACT: QUOTE'
    check "quote: signed, verifies"            verifies quote piggy-quote-v1 t3.txt
    check "long text: first line shown"        shows long 'line 01 '
    check "long text: last line shown"         shows long 'LAST LINE of the long text'
    check "long text: signed, verifies"        verifies long piggy-escalation-v1 t4.txt
    check "markup: shown literally"            shows markup 'T5 <b>markup</b> & an under_score and a back\slash'
    check "markup: signed, verifies"           verifies markup piggy-escalation-v1 t5.txt
    check "cancel at the PIN: exit 4"          rc_is cancel 4
    check "cancel at the PIN: says cancelled"  grep -q cancelled "$dir/cancel.err"
    check "wrong escalation word: exit 4"      rc_is wrongword 4
    echo "1..$n"
    ((fails == 0))

# The piggy#378 hand pass, staged (FDR 0006 phase (b)): a piggy agent on a
# private blank fibby card, a PIN put in its cache with `ssh-add -X` (the
# test askpass answers, piggy-testing(7) PIN PROMPT SAFETY NET; no card
# VERIFY happens), then what the operator checks: VmLck grew by a page per
# cached PIN, /proc/<pid>'s files belong to root (the agent is non-dumpable), the
# agent's core limit is 0 although it was started with a raised one, and a
# SIGABRT leaves no core file. core_pattern, suid_dumpable and what
# coredumpctl recorded are printed for the reader, not judged. VmRSS is the
# figure behind the mlockall ruling (FDR 0006, Tuning Levers). BIN_DIR, when given, is a
# directory holding the piggy and fibby to run (e.g. target/debug) in
# place of the nix-built ones.
#
# stage the piggy#378 hand pass: guarded PIN cache, non-dumpable agent, no core dump
[group('explore')]
[linux]
explore-fdr0006-b BIN_DIR="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -n "{{ BIN_DIR }}" ]]; then
      bin="$(realpath "{{ BIN_DIR }}")"
      piggy="$bin/piggy" fibby="$bin/fibby"
    else
      piggy="$(nix build .#default --no-link --print-out-paths)/bin/piggy"
      fibby="$(nix build .#fibby --no-link --print-out-paths)/bin/fibby"
    fi
    dir="$(mktemp -d -t fdr6b.XXXXXX)"
    export PCSCLITE_CSOCK_NAME="$dir/pcscd.comm" PIGGY_STORE_DIR="$dir/store"
    export SSH_AUTH_SOCK="$dir/agent.sock" PIGGY_AUTH_SOCK="$dir/agent.sock"
    export SSH_ASKPASS="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
    export SSH_ASKPASS_REQUIRE=force DISPLAY="" PIGGY_TEST_FIB_PIN=123456
    unset WAYLAND_DISPLAY
    pids=()
    cleanup() { kill "${pids[@]}" 2>/dev/null || true; rm -rf "$dir"; }
    trap cleanup EXIT

    "$fibby" --socket "$PCSCLITE_CSOCK_NAME" --backend virtual --model yk5 >"$dir/fibby.log" 2>&1 &
    pids+=($!)
    for _ in $(seq 1 50); do [[ -S $PCSCLITE_CSOCK_NAME ]] && break; sleep 0.1; done
    # Raised, so a zero limit in the agent is the agent's own doing.
    ulimit -c "$(ulimit -H -c)"
    (cd "$dir" && exec "$piggy" agent -d -a "$dir/agent.sock") >"$dir/agent.log" 2>&1 &
    agent=$!
    pids+=($agent)
    for _ in $(seq 1 50); do [[ -S $dir/agent.sock ]] && break; sleep 0.1; done
    [[ -S $dir/agent.sock ]] || { echo "the agent did not come up:" >&2; cat "$dir/agent.log" >&2; exit 1; }

    status_kib() { awk -v f="$1:" '$1 == f {print $2}' "/proc/$agent/status"; }
    page_kib=$(($(getconf PAGESIZE) / 1024))
    lck_before=$(status_kib VmLck)
    unlock_rc=0
    setsid -w ssh-add -X </dev/null >"$dir/ssh-add.log" 2>&1 || unlock_rc=$?
    lck_after=$(status_kib VmLck)
    rss=$(status_kib VmRSS)
    # proc(5): a non-dumpable process's /proc/<pid> FILES belong to root.
    owner=$(stat -c %U "/proc/$agent/environ")
    core_limit=$(awk '/^Max core file size/ {print $5}' "/proc/$agent/limits")
    started=$(date +%s)
    # SIGABRT, not SIGSEGV: Rust's std handles SIGSEGV (stack-overflow
    # detection) and a kill(2)-sent one does not end the process. Both
    # are core-dumping signals.
    kill -ABRT "$agent"
    for _ in $(seq 1 100); do kill -0 "$agent" 2>/dev/null || break; sleep 0.1; done
    alive=0
    kill -0 "$agent" 2>/dev/null && alive=1
    sleep 1
    cores=$(find "$dir" -maxdepth 1 -name 'core*' | wc -l)

    echo "# agent pid $agent: VmLck $lck_before kB -> $lck_after kB after ssh-add -X (page $page_kib kB); VmRSS $rss kB"
    echo "# /proc/$agent/environ owner: $owner; agent core limit: $core_limit; shell core limit: $(ulimit -c)"
    echo "# core_pattern: $(cat /proc/sys/kernel/core_pattern); suid_dumpable: $(cat /proc/sys/fs/suid_dumpable)"
    echo "# uid_map: $(tr -s ' ' <"/proc/$$/uid_map")"
    if command -v coredumpctl >/dev/null; then
      echo "# coredumpctl since the SIGABRT:"
      coredumpctl list --no-pager --since "@$started" 2>&1 | sed 's/^/#   /' || true
    fi
    echo "# agent log:"
    sed 's/^/#   /' "$dir/agent.log"

    n=0 fails=0
    check() { # check DESCRIPTION COMMAND...
      n=$((n + 1))
      if "${@:2}" >/dev/null 2>&1; then echo "ok $n - $1"; else echo "not ok $n - $1"; fails=$((fails + 1)); fi
    }
    echo "TAP version 14"
    check "ssh-add -X was accepted"                 test "$unlock_rc" = 0
    check "VmLck grew by at least a page"           test "$lck_after" -ge "$((lck_before + page_kib))"
    sed 's/\x1b\[[0-9;]*m//g' "$dir/agent.log" >"$dir/agent.plain.log"
    check "the agent reads itself non-dumpable"     grep -q 'process hardening.*dumpable=Some(false)' "$dir/agent.plain.log"
    check "/proc/<agent>/environ belongs to root"   test "$owner" = root
    check "the agent's core limit is 0"             test "$core_limit" = 0
    check "SIGABRT ended the agent"                 test "$alive" = 0
    check "no core file in the agent's directory"   test "$cores" = 0
    echo "1..$n"
    ((fails == 0))

# The piggy#382 hand pass, staged (FDR 0006 phase (c), the fibby holder
# build): builds `.#fibby-holder` and `.#fibby`, checks that each reports
# its build profile, that the holder refuses every test flag the test build
# lists and FIBBY_LOG=wire while the test build accepts them, then starts a
# holder on a private socket with a control socket, checks it is
# non-dumpable with a zero core limit, creates an Ed25519 card at runtime,
# reads its attestation with `piggy card export-attestation`, destroys it,
# and leaves a shell there (`exit` tears it down) so the operator can read
# `fibby --help` for both builds and drive `fibby ctl` by hand; NO_SHELL=1 in
# the environment skips the shell, tears down at once and exits 0 only when
# every check is ok (for an unattended run). Virtual
# cards only: no real card, no PIN prompt (the askpass safety net is set
# anyway, piggy-testing(7)). BIN_DIR, when given, holds a holder build named
# fibby-holder, a test-double build named fibby and a piggy to run instead.
#
# stage the piggy#383 hand pass: a holder agent over the fibby holder build, a bound and a sibling systemd scope
[group('explore')]
[linux]
explore-fdr0006-d BIN_DIR="" NO_SHELL="":
    #!/usr/bin/env bash
    set -euo pipefail
    # NO_SHELL=1 as a parameter or in the environment runs unattended.
    NO_SHELL="${NO_SHELL:-{{ NO_SHELL }}}"
    if [[ -n "{{ BIN_DIR }}" ]]; then
      bin="$(realpath "{{ BIN_DIR }}")"
      holder="$bin/fibby-holder" piggy="$bin/piggy"
    else
      holder="$(nix build .#fibby-holder --no-link --print-out-paths)/bin/fibby"
      piggy="$(nix build .#default --no-link --print-out-paths)/bin/piggy"
    fi
    command -v systemd-run >/dev/null || { echo "explore-fdr0006-d: systemd-run is needed (a systemd user session makes the scopes)" >&2; exit 1; }
    dir="$(mktemp -d -t fdr6d.XXXXXX)"
    # The safety net with NO PIN: a prompt makes the helper refuse (piggy#35),
    # and a minted key must never need one.
    export SSH_ASKPASS="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
    export SSH_ASKPASS_REQUIRE=force DISPLAY=""
    unset WAYLAND_DISPLAY PIGGY_TEST_FIB_PIN SSH_AUTH_SOCK PIGGY_AUTH_SOCK
    pids=()
    tag="fdr6d-$$"
    cleanup() {
      systemctl --user stop "$tag-bound.scope" "$tag-sibling.scope" 2>/dev/null || true
      kill "${pids[@]}" 2>/dev/null || true
      rm -rf "$dir"
    }
    trap cleanup EXIT
    trap 'exit 130' INT TERM HUP

    n=0 fails=0
    check() { # check DESCRIPTION COMMAND...; a failing check's output is printed as diagnostics
      n=$((n + 1))
      if "${@:2}" >"$dir/check.out" 2>&1; then
        echo "ok $n - $1"
      else
        echo "not ok $n - $1"
        sed 's/^/#   /' "$dir/check.out"
        fails=$((fails + 1))
      fi
    }
    # in_scope UNIT CMD...: run CMD inside a fresh transient user scope UNIT.
    in_scope() { systemd-run --user --scope --quiet --unit "$1" "${@:2}"; }

    ctl="$dir/ctl.sock" agent="$dir/agent.sock"
    export PCSCLITE_CSOCK_NAME="$dir/pcscd.comm"
    "$holder" --socket "$PCSCLITE_CSOCK_NAME" --control-socket "$ctl" --model yk5.7 >"$dir/holder.log" 2>&1 &
    pids+=($!)
    for _ in $(seq 1 50); do [[ -S $ctl ]] && break; sleep 0.1; done
    # The implicit blank card takes a reader slot the holder could use.
    "$holder" ctl --socket "$ctl" destroy "Virtual PCD piggy fibby 00 00" >/dev/null 2>&1 || true
    "$piggy" agent --holder --holder-fibby-ctl "$ctl" --scope piggy-mint-v1=caller \
      --scope-poll-interval 1 -a "$agent" >"$dir/agent.log" 2>&1 &
    pids+=($!)
    for _ in $(seq 1 50); do [[ -S $agent ]] && break; sleep 0.1; done
    export SSH_AUTH_SOCK="$agent"
    echo "# holder fibby: $holder"
    echo "# piggy:        $piggy"
    echo "TAP version 14"
    check "holder fibby reports profile holder"      test "$("$holder" ctl --socket "$ctl" profile)" = "ok holder"
    check "a mint naming no scope is refused scope-unbound" bash -c "\"$piggy\" holder mint 2>&1 | grep -q scope-unbound"
    check "a mint naming an undefined scope is refused unknown-scope" bash -c "\"$piggy\" holder mint --scope piggy-mint-v9 2>&1 | grep -q unknown-scope"

    # The bound scope: mint two keys, sign with the first, then wait for
    # the go-file so the scope stays alive while the sibling is tried.
    cat >"$dir/bound.sh" <<EOF
    set -euo pipefail
    cd "$dir"
    "$piggy" holder mint --scope piggy-mint-v1 > a.pub
    "$piggy" holder mint --scope piggy-mint-v1 > b.pub
    read -r t k _ < a.pub; printf 'fdr6d %s %s\n' "\$t" "\$k" > signers
    echo "piggy-test: signed from the bound scope" > data
    ssh-keygen -Y sign -f a.pub -U -n file data
    ssh-keygen -Y verify -f signers -I fdr6d -n file -s data.sig < data
    "$piggy" holder retire a.pub
    touch bound.ok
    while [[ ! -e go ]]; do sleep 0.2; done
    EOF
    in_scope "$tag-bound" bash "$dir/bound.sh" >"$dir/bound.log" 2>&1 &
    pids+=($!)
    for _ in $(seq 1 300); do [[ -e $dir/bound.ok ]] && break; sleep 0.1; done
    check "bound scope: minted two keys, signed and verified with one, retired it" test -e "$dir/bound.ok"
    check "bound scope: the retired card is gone, the other stays" bash -c "\"$holder\" ctl --socket \"$ctl\" list | grep -qF 'piggy-holder 2' && ! \"$holder\" ctl --socket \"$ctl\" list | grep -qF 'piggy-holder 1'"
    # The sibling scope: the same socket, a different cgroup.
    echo "piggy-test: from the sibling" >"$dir/sdata"
    sibling_sign_refused() {
      local out rc=0
      out="$(in_scope "$tag-sibling-sign" ssh-keygen -Y sign -f "$dir/b.pub" -U -n file "$dir/sdata" 2>&1)" || rc=$?
      printf '%s\n(exit %s)\n' "$out" "$rc"
      [[ $rc -ne 0 ]]
    }
    sibling_retire_refused() {
      local out rc=0
      out="$(in_scope "$tag-sibling" "$piggy" holder retire "$dir/b.pub" 2>&1)" || rc=$?
      printf '%s\n(exit %s)\n' "$out" "$rc"
      [[ $out == *not-bound-scope* ]]
    }
    check "sibling scope: a sign with the bound key is refused" sibling_sign_refused
    check "sibling scope: the refusal names not-bound-scope in the agent log" grep -q not-bound-scope "$dir/agent.log"
    check "sibling scope: a retire of the bound key is refused not-bound-scope" sibling_retire_refused
    # The bound scope exits: its card goes by itself.
    touch "$dir/go"
    gone=0
    for _ in $(seq 1 100); do
      if ! "$holder" ctl --socket "$ctl" list | grep -qF "piggy-holder 2"; then gone=1; break; fi
      sleep 0.1
    done
    check "scope exit: the remaining card was destroyed by the holder" test "$gone" = 1
    check "scope exit: the agent log says the scope exited" grep -q "its scope exited" "$dir/agent.log"
    check "scope exit: the key is no longer listed" bash -c "! ssh-add -L 2>/dev/null | grep -qF holder:"
    echo "1..$n"
    echo "# Read the unit logs: cat $dir/agent.log $dir/holder.log $dir/bound.log"
    if [[ "${NO_SHELL:-}" == 1 ]]; then
      echo "# NO_SHELL=1: no shell; $fails of $n checks failed."
      ((fails == 0))
      exit
    fi
    echo "# A holder agent is serving $agent over the holder fibby ($ctl)."
    echo "# Try: systemd-run --user --scope \"\$PIGGY\" holder mint --scope piggy-mint-v1"
    echo "#      \"\$FIBBY\" ctl --socket \"\$FIBBY_CTL\" list; ssh-add -L; exit the shell to stop everything."
    FIBBY="$holder" FIBBY_CTL="$ctl" PIGGY="$piggy" "${SHELL:-bash}" -i || true
    ((fails == 0))

# Can a process of the SAME uid leave its cgroup and join another? Holder
# keys and the front's per-caller limit (piggy#407) identify a caller by the
# cgroup path read from /proc/<pid>/cgroup, so a process that can move itself
# into a victim's cgroup poses as the victim. From inside a fresh user scope
# it tries to write its own pid into (1) a sibling user scope, (2) the cgroup
# this recipe itself runs in (the stand-in for the operator's login-shell
# scope), (3) a cgroup of the root-owned system slice, and prints what the
# kernel said. Each line is TAP: ok = the move was REFUSED (the boundary
# holds), not ok = the process moved (the boundary is open). No card, no
# piggy binary, no PIN prompt; it only needs a systemd user session and
# cgroup v2. A moved probe process exits at once and takes nothing with it.
#
# probe whether a same-uid process can move itself into another cgroup (lane 3, piggy#407)
[group('explore')]
[linux]
explore-cgroup-self-move:
    #!/usr/bin/env bash
    set -euo pipefail
    command -v systemd-run >/dev/null || { echo "explore-cgroup-self-move: systemd-run is needed (a systemd user session makes the scopes)" >&2; exit 1; }
    root=/sys/fs/cgroup
    [[ -e $root/cgroup.controllers ]] || { echo "explore-cgroup-self-move: $root is not a cgroup v2 mount" >&2; exit 1; }
    tag="cgmove-$$"
    dir="$(mktemp -d -t cgmove.XXXXXX)"
    cleanup() {
      systemctl --user stop "$tag-target.scope" "$tag-probe.scope" 2>/dev/null || true
      kill "${pids[@]}" 2>/dev/null || true
      rm -rf "$dir"
    }
    pids=()
    trap cleanup EXIT
    trap 'exit 130' INT TERM HUP
    cg_of() { sed -n 's/^0:://p' "/proc/$1/cgroup"; }
    own_cg="$(cg_of $$)"
    echo "# uid $(id -u); this recipe runs in cgroup $own_cg"
    # The sibling target: a scope holding one sleeping process.
    systemd-run --user --scope --quiet --unit "$tag-target" sleep 300 >"$dir/target.log" 2>&1 &
    pids+=($!)
    target_pid=""
    # The target scope's own process, found through the scope's cgroup (the
    # unit name is unique to this run), never by matching a command line that
    # another session's `sleep` could also carry.
    for _ in $(seq 1 50); do
      target_cg_dir="$(systemctl --user show "$tag-target.scope" -p ControlGroup --value 2>/dev/null || true)"
      if [[ -n $target_cg_dir ]]; then
        # (a kernel file reports size 0, so read it rather than test -s)
        target_pid="$(head -n1 "$root$target_cg_dir/cgroup.procs" 2>/dev/null || true)"
        [[ -n $target_pid ]] && break
      fi
      sleep 0.1
    done
    if [[ -z $target_pid ]]; then
      echo "explore-cgroup-self-move: the sibling target scope did not come up; systemd-run said:" >&2
      sed 's/^/#   /' "$dir/target.log" >&2
      echo "#   the unit: $(systemctl --user show "$tag-target.scope" -p ControlGroup -p ActiveState 2>&1 | tr '\n' ' ')" >&2
      echo "#   its cgroup.procs: $(cat "$root${target_cg_dir:-/none}/cgroup.procs" 2>&1 | tr '\n' ' ')" >&2
      exit 1
    fi
    target_cg="$(cg_of "$target_pid")"
    echo "# sibling target scope: $target_cg"
    # Who owns what: the answer to a move is the kernel's, these are its inputs.
    for cg in "$target_cg" "$own_cg" /system.slice; do
      printf '# %s: owner %s, cgroup.procs mode %s, delegated subtree files %s\n' \
        "$cg" "$(stat -c %U "$root$cg")" "$(stat -c %a "$root$cg/cgroup.procs")" \
        "$([[ -w $root$cg/cgroup.procs ]] && echo writable-by-me || echo not-writable-by-me)"
    done
    # The probe: runs in its own fresh scope and tries each move, reporting
    # where it ended up. It prints "moved <cgroup>" or "refused <error>".
    cat >"$dir/probe.sh" <<'EOF'
    # The write is made by this shell itself (no subshell), of its own pid.
    exec 3>&2 2>"$TMPDIR_PROBE.err"
    me="$BASHPID"
    if { printf '%s\n' "$me" >"$root$1/cgroup.procs"; } 2>>"$TMPDIR_PROBE.err"; then
      exec 2>&3
      echo "moved $(sed -n 's/^0:://p' "/proc/$me/cgroup")"
    else
      exec 2>&3
      echo "refused (wrote pid '$me' to $1) $(cat "$TMPDIR_PROBE.err")"
    fi
    EOF
    probe() { # probe CGROUP: run the move attempt from a fresh scope, print its one line
      systemd-run --user --scope --quiet --unit "$tag-probe" \
        env root="$root" TMPDIR_PROBE="$dir/probe" bash -c "$(cat "$dir/probe.sh")" probe "$1" 2>&1
      systemctl --user stop "$tag-probe.scope" 2>/dev/null || true
    }
    n=0 moved=0 inconclusive=0
    # A move the kernel refuses for permission (EACCES/EPERM) is a boundary
    # that holds; a refusal for any other reason (EINVAL, EBUSY, ...) says
    # nothing about permission and is counted as inconclusive, never as a move
    # and never as ok. judge DESCRIPTION OUTPUT prints one TAP line.
    judge() {
      local what="$1" out="$2"
      n=$((n + 1))
      if [[ $out == moved* ]]; then
        echo "not ok $n - $what was NOT refused: the process moved ($out)"
        moved=$((moved + 1))
      elif [[ $out == *"Permission denied"* || $out == *"Operation not permitted"* ]]; then
        echo "ok $n - $what is refused for permission ($out)"
      else
        echo "not ok $n - $what was refused, but NOT for permission: INCONCLUSIVE ($out)"
        inconclusive=$((inconclusive + 1))
      fi
    }
    verdict() { judge "$1" "$(probe "$2")"; } # verdict DESCRIPTION CGROUP
    control() { # control DESCRIPTION CGROUP: the probe's own cgroup, a move that must succeed
      local out
      out="$(probe "$2")"
      n=$((n + 1))
      if [[ $out == moved* ]]; then
        echo "ok $n - control: $1 works ($out)"
      else
        echo "not ok $n - control: $1 failed, so the write method itself is suspect ($out)"
        inconclusive=$((inconclusive + 1))
      fi
    }
    # The probe's scope is a sibling of the target, so its path is known up front.
    probe_cg="${target_cg%/*}/$tag-probe.scope"
    echo "# probe scope (the control's target): $probe_cg"
    for f in cgroup.type cgroup.controllers cgroup.subtree_control; do
      printf '# target %s: %s\n' "$f" "$(tr '\n' ' ' <"$root$target_cg/$f")"
    done
    echo "TAP version 14"
    control "a process writing its own pid into the cgroup it is already in" "$probe_cg"
    verdict "a same-uid process moving into a sibling user scope"        "$target_cg"
    verdict "a same-uid process moving into the recipe's own cgroup"     "$own_cg"
    verdict "a same-uid process moving into the root-owned system slice" /system.slice
    # A process that starts where a login shell's children start (not under the
    # user manager): the recipe's own cgroup, so no systemd-run in between.
    from_login() { # from_login DESCRIPTION CGROUP
      judge "$1" "$(env root="$root" TMPDIR_PROBE="$dir/login" bash -c "$(cat "$dir/probe.sh")" probe "$2" 2>&1)"
    }
    echo "# from a process that starts in $own_cg (the login session scope):"
    from_login "a login-session process moving into a user-manager scope" "$target_cg"
    echo "1..$n"
    echo "# $moved moves succeeded; $inconclusive attempts were inconclusive (not a permission refusal, not a move); $n attempts in all."
    ((moved == 0 && inconclusive == 0))

# What a holder pair costs in memory: for each count in COUNTS it starts that
# many pairs of (the fibby HOLDER build + `piggy agent --holder`) as throwaway
# processes with scratch state, each pair minting one key, and reads the RSS
# split (anonymous, file, shmem), peak, data, locked pages and thread count
# from /proc/PID/status at idle (after the mint) and again after one sign each,
# with the host's MemAvailable drop per pair. (PSS is not readable: both
# processes are non-dumpable on purpose, so a same-uid reader is denied
# smaps_rollup.) Virtual cards only: no real card and no PIN prompt (the askpass safety
# net is set anyway, piggy-testing(7)). BIN_DIR, when given, holds a holder
# build named fibby-holder and a piggy to measure instead.
#
# measure the memory of N fibby + holder-agent pairs (no card, FDR 0006 shape A sizing)
[group('explore')]
[linux]
explore-holder-memory COUNTS="1 4 8 16" BIN_DIR="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -n "{{ BIN_DIR }}" ]]; then
      bin="$(realpath "{{ BIN_DIR }}")"
      holder="$bin/fibby-holder" piggy="$bin/piggy"
    else
      holder="$(nix build .#fibby-holder --no-link --print-out-paths)/bin/fibby"
      piggy="$(nix build .#default --no-link --print-out-paths)/bin/piggy"
    fi
    dir="$(mktemp -d -t holdermem.XXXXXX)"
    export SSH_ASKPASS="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
    export SSH_ASKPASS_REQUIRE=force DISPLAY=""
    unset WAYLAND_DISPLAY PIGGY_TEST_FIB_PIN SSH_AUTH_SOCK PIGGY_AUTH_SOCK
    pids=()
    cleanup() {
      kill "${pids[@]}" 2>/dev/null || true
      wait 2>/dev/null || true
      rm -rf "$dir"
    }
    trap cleanup EXIT
    trap 'exit 130' INT TERM HUP
    # field FILE NAME: the number after "NAME:" in a /proc status-like file.
    field() { awk -v k="$2:" '$1 == k {print $2; exit}' "$1"; }
    start_pair() { # start_pair INDEX: a fibby holder and its agent with one minted key
      local d="$dir/p$1"
      mkdir -p "$d"
      PCSCLITE_CSOCK_NAME="$d/pcscd.comm" "$holder" --socket "$d/pcscd.comm" \
        --control-socket "$d/ctl.sock" --model yk5.7 >"$d/fibby.log" 2>&1 &
      echo $! >"$d/fibby.pid"
      pids+=($!)
      for _ in $(seq 1 100); do [[ -S $d/ctl.sock ]] && break; sleep 0.1; done
      "$holder" ctl --socket "$d/ctl.sock" destroy "Virtual PCD piggy fibby 00 00" >/dev/null 2>&1 || true
      PCSCLITE_CSOCK_NAME="$d/pcscd.comm" "$piggy" agent --holder --holder-fibby-ctl "$d/ctl.sock" \
        --scope piggy-mint-v1=caller --scope-poll-interval 1 -a "$d/agent.sock" >"$d/agent.log" 2>&1 &
      echo $! >"$d/agent.pid"
      pids+=($!)
      for _ in $(seq 1 100); do [[ -S $d/agent.sock ]] && break; sleep 0.1; done
      SSH_AUTH_SOCK="$d/agent.sock" "$piggy" holder mint --scope piggy-mint-v1 >"$d/key.pub"
    }
    sign_once() { # sign_once INDEX
      local d="$dir/p$1"
      echo "piggy-test: memory probe" >"$d/data"
      SSH_AUTH_SOCK="$d/agent.sock" ssh-keygen -Y sign -f "$d/key.pub" -U -n file "$d/data" >/dev/null 2>&1
    }
    # Both processes are non-dumpable on purpose (FDR 0006 phase (b): no core
    # dump, no same-user ptrace, /proc/PID/smaps* owned by root), so a
    # same-uid reader gets "Permission denied" on smaps_rollup and no PSS is
    # available. /proc/PID/status stays world-readable and splits RSS into
    # anonymous (private to the process: the cost of one more pair), file-backed
    # (the binary and libraries, shared across pairs) and shmem pages.
    # report LABEL N: per-pair means from /proc/PID/status, fibby then agent.
    report() {
      local label="$1" n="$2" i who pid k
      for who in fibby agent; do
        local -A sum=([VmRSS]=0 [RssAnon]=0 [RssFile]=0 [RssShmem]=0 [VmHWM]=0 [VmData]=0 [VmLck]=0 [Threads]=0)
        for i in $(seq 1 "$n"); do
          pid="$(cat "$dir/p$i/$who.pid")"
          for k in "${!sum[@]}"; do
            sum[$k]=$((sum[$k] + $(field "/proc/$pid/status" "$k")))
          done
        done
        printf '%-11s N=%-2s %-5s per process (kB): rss %6d = anon %6d + file %6d + shmem %4d | peak %6d data %6d locked %4d threads %d\n' \
          "$label" "$n" "$who" $((sum[VmRSS] / n)) $((sum[RssAnon] / n)) $((sum[RssFile] / n)) \
          $((sum[RssShmem] / n)) $((sum[VmHWM] / n)) $((sum[VmData] / n)) $((sum[VmLck] / n)) $((sum[Threads] / n))
      done
    }
    echo "# holder fibby: $holder"
    echo "# piggy:        $piggy"
    started=0
    for n in {{ COUNTS }}; do
      ((n >= 1)) || { echo "# skipping a count of $n (a pair count is at least 1)"; continue; }
      while ((started < n)); do
        started=$((started + 1))
        start_pair "$started"
      done
      sleep 2
      report idle "$n"
      for i in $(seq 1 "$n"); do sign_once "$i"; done
      sleep 1
      report "after-sign" "$n"
    done
    for who in fibby agent; do
      pid="$(cat "$dir/p1/$who.pid")"
      printf '# %s (pair 1): VmSize %s kB, VmStk %s kB, VmExe %s kB, VmLib %s kB, VmSwap %s kB\n' \
        "$who" "$(field /proc/$pid/status VmSize)" "$(field /proc/$pid/status VmStk)" \
        "$(field /proc/$pid/status VmExe)" "$(field /proc/$pid/status VmLib)" "$(field /proc/$pid/status VmSwap)"
    done

# UNRUN AGAINST A REAL CARD (drafted 2026-11-19 while the card was away;
# its guards are exercised with fake tools by explore_fdr0007_root_cert_
# guard.bats, the card path is not): the ykcs11 object label, the
# provider's PIN prompt and the key URI are from memory; notBefore is
# "now" (no skew), printed in the read-back and not asserted. The root's
# CN, its validity and the permitted DNS set are the OPERATOR's choice
# (FDR 0007's open questions), and running this at all is the operator's
# decision at the card hour, not a default of any lane. A failed card read
# in step 1 (the rollback or the evidence not saved) bails out BEFORE the
# card is asked to sign.
#
# The pilot root certificate on the operator's card (FDR 0007, slot 82),
# in one command instead of a transcript: the card reads (public key,
# the placeholder certificate, the attestation: the rollback and the
# evidence), the openssl extension file carrying the root profile
# (CA:TRUE pathlen:1, keyCertSign+cRLSign, name constraints with every IP
# excluded, SKI/AKI), the signature by the card through OpenSSL 3's
# PKCS#11 provider (ONE PIN, ONE touch), and the read-back checks as TAP.
# It never writes the card: the `write-cert` line and its rollback are
# printed for the operator to run by hand after judging the read-back.
# DRAFTED UNRUN on 2026-11-19 (edit-only; the card was away): the PKCS#11
# object label and the provider's PIN handling are from memory of ykcs11
# and pkcs11-provider, not verified; `KEY_URI` and the printed object list
# are there so a wrong label is seen before any PIN is typed. Phase (ii)'s
# `piggy ca root-cert` (#391) replaces this recipe.
#   CN      the root's common name (required; FDR 0007: operator's choice)
#   NAMES   permitted DNS names, comma-separated (DNS:github.com already
#           covers api./codeload.github.com under RFC 5280)
#   DAYS    validity in days (FDR 0007: years; default ten)
#   MODULE  the PKCS#11 module: yubico-piv-tool's libykcs11.so (nixpkgs
#           `yubico-piv-tool`, lib/libykcs11.so) or opensc-pkcs11.so (the
#           dev shell's `opensc`, lib/opensc-pkcs11.so)
#   PROVIDER_PATH  the directory holding OpenSSL 3's pkcs11.so provider
#           (nixpkgs `pkcs11-provider`, lib/ossl-modules)
#   KEY_URI the PKCS#11 URI of slot 82's private key (ykcs11 labels it
#           "Private key for Retired Key 1"; OpenSC labels differ)
#   OUT     where the PEMs land (default: a new directory under $PWD)
#
# stage the FDR 0007 pilot root certificate from slot 82: card reads, openssl profile, one card signature, read-back (never writes the card)
[group('explore')]
[linux]
explore-fdr0007-root-cert CN NAMES="github.com" DAYS="3650" MODULE="" PROVIDER_PATH="" KEY_URI="pkcs11:object=Private%20key%20for%20Retired%20Key%201;type=private" OUT="" CARD="virtual":
    #!/usr/bin/env bash
    set -euo pipefail
    cn={{ quote(CN) }} names={{ quote(NAMES) }} days={{ quote(DAYS) }}
    module={{ quote(MODULE) }} provider_path={{ quote(PROVIDER_PATH) }} key_uri={{ quote(KEY_URI) }}
    out={{ quote(OUT) }} card={{ quote(CARD) }} slot=82
    if [[ $card != real ]]; then
      echo "explore-fdr0007-root-cert: this signs with the OPERATOR'S CARD (slot $slot, one PIN, one touch)." >&2
      echo "Run it as: CN=... MODULE=... PROVIDER_PATH=... just explore-fdr0007-root-cert ... CARD=real" >&2
      exit 2
    fi
    [[ -n $cn ]] || { echo "CN is required" >&2; exit 2; }
    [[ -f $module ]] || { echo "MODULE must name the PKCS#11 module (libykcs11.so or opensc-pkcs11.so), got '$module'" >&2; exit 2; }
    [[ -f $provider_path/pkcs11.so ]] || { echo "PROVIDER_PATH must hold OpenSSL 3's pkcs11.so provider, got '$provider_path'" >&2; exit 2; }
    for tool in piggy openssl ssh-keygen pkcs11-tool; do
      command -v "$tool" >/dev/null || { echo "$tool is not on PATH" >&2; exit 2; }
    done
    [[ -n $out ]] || out="$PWD/fdr0007-root-$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$out"
    chmod 700 "$out"
    n=0 fails=0
    check() { # check DESCRIPTION COMMAND...; a failing check's output is printed as diagnostics
      n=$((n + 1))
      if "${@:2}" >"$out/check.out" 2>&1; then
        echo "ok $n - $1"
      else
        echo "not ok $n - $1"
        sed 's/^/#   /' "$out/check.out"
        fails=$((fails + 1))
      fi
    }
    echo "TAP version 14"
    echo "# 1. card reads (no PIN, no touch): the rollback and the evidence"
    check "slot $slot public key saved ($out/slot$slot.pub)"            bash -c "piggy tool pubkey $slot > '$out/slot$slot.pub'"
    check "slot $slot stored certificate saved (the rollback)"            bash -c "piggy tool cert $slot > '$out/slot$slot-placeholder.pem'"
    check "slot $slot attestation saved"                                   bash -c "piggy tool attest $slot > '$out/slot$slot-attest.pem'"
    echo "# The attested policy, as piggy lists it (expect pin_policy always, touch_policy always, P-256):"
    piggy list --format=ndjson 2>/dev/null | grep -i '"slot": *"82"' | sed 's/^/#   /' || echo "#   (piggy list printed no slot 82 line; read the attestation PEM by hand)"
    echo "# step 1: $fails of $n card reads failed"
    if [[ $fails -gt 0 ]]; then
      echo "Bail out! a card read failed: the rollback or the evidence is not saved, so the card is not asked to sign"
      exit 1
    fi

    echo "# 2. the root profile as an openssl extension section"
    permitted=""
    IFS=, read -ra name_list <<<"$names"
    for name in "${name_list[@]}"; do permitted+="permitted;DNS:${name},"; done
    cat >"$out/root.cnf" <<EOF
    [ req ]
    distinguished_name = dn
    prompt = no
    [ dn ]
    CN = $cn
    [ v3_root ]
    basicConstraints = critical, CA:TRUE, pathlen:1
    keyUsage = critical, keyCertSign, cRLSign
    nameConstraints = critical, ${permitted}excluded;IP:0.0.0.0/0.0.0.0, excluded;IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0
    subjectKeyIdentifier = hash
    authorityKeyIdentifier = keyid:always
    EOF
    sed 's/^/#   /' "$out/root.cnf"

    echo "# 3. the key as PKCS#11 sees it (check KEY_URI against this list BEFORE typing the PIN)"
    # Without --login this lists PUBLIC objects only: the private key's label
    # ("Private key for Retired Key 1") may be absent here and still exist;
    # the matching public key / certificate for Retired Key 1 is the check.
    echo "# (public objects only, no login: look for Retired Key 1's public key or certificate; the private key shows after login)"
    pkcs11-tool --module "$module" --list-objects 2>&1 | sed 's/^/#   /' || true
    echo "# KEY_URI: $key_uri"
    echo "# The next step signs with the card: it asks for the PIN once, then the key waits for ONE touch."
    read -r -p "# Press Enter to sign the root with slot $slot, or Ctrl-C to stop: " _
    export PKCS11_PROVIDER_MODULE="$module"
    # openssl acts on each provider option as it parses it: -provider-path
    # must come BEFORE -provider pkcs11, or pkcs11 is looked up in openssl's
    # own module directory (seen on the card host, 2026-11-19, before any
    # PIN). OPENSSL_MODULES set to the same directory also works.
    if openssl req -new -x509 -provider-path "$provider_path" -provider pkcs11 -provider default \
        -key "$key_uri" -config "$out/root.cnf" -extensions v3_root -days "$days" -sha256 \
        -out "$out/root.pem"; then
      echo "ok $((n += 1)) - the card signed the root certificate ($out/root.pem)"
    else
      echo "not ok $((n += 1)) - the card signature failed; nothing was written to the card"
      echo "1..$n"
      exit 1
    fi

    echo "# 4. read-back"
    openssl x509 -in "$out/root.pem" -noout -text >"$out/root.txt"
    check "the root verifies against itself"                        openssl verify -CAfile "$out/root.pem" "$out/root.pem"
    check "basicConstraints critical CA:TRUE pathlen:1"            bash -c "grep -A1 'X509v3 Basic Constraints: critical' '$out/root.txt' | grep -q 'CA:TRUE, pathlen:1'"
    check "keyUsage keyCertSign, cRLSign"                           bash -c "grep -A1 'X509v3 Key Usage: critical' '$out/root.txt' | grep -q 'Certificate Sign, CRL Sign'"
    check "name constraints permit exactly the given DNS names"     bash -c "grep -q 'Name Constraints: critical' '$out/root.txt' && for name in ${names//,/ }; do grep -q \"DNS:\$name\" '$out/root.txt' || exit 1; done"
    check "name constraints exclude every IPv4 and IPv6 address"    bash -c "grep -q 'IP:0.0.0.0/0.0.0.0' '$out/root.txt' && grep -qE 'IP:(0:0:0:0:0:0:0:0|::)/' '$out/root.txt'"
    check "subject and authority key identifiers present"          bash -c "grep -q 'Subject Key Identifier' '$out/root.txt' && grep -q 'Authority Key Identifier' '$out/root.txt'"
    check "the certificate's key is slot $slot's key"               bash -c "cmp -s <(openssl x509 -in '$out/root.pem' -pubkey -noout) <(ssh-keygen -e -m PKCS8 -f '$out/slot$slot.pub')"
    check "the serial has at least 64 bits"                         bash -c "[[ \$(openssl x509 -in '$out/root.pem' -noout -serial | cut -d= -f2 | wc -c) -ge 17 ]]"
    # Each `attest` makes the card sign a fresh attestation; whether the
    # signature's nonce is deterministic on real firmware is not known, so
    # the bytes are not compared: the attested key and the YubicoPIV policy
    # extension (1.3.6.1.4.1.41482.3.8, [pin, touch]) are.
    check "slot $slot's attested key is unchanged"                  bash -c "cmp -s <(piggy tool attest $slot | openssl x509 -noout -pubkey) <(openssl x509 -in '$out/slot$slot-attest.pem' -noout -pubkey)"
    check "slot $slot's attested PIN and touch policy are unchanged"  bash -c "cmp -s <(piggy tool attest $slot | openssl x509 -noout -text | grep -A1 '1.3.6.1.4.1.41482.3.8') <(openssl x509 -in '$out/slot$slot-attest.pem' -noout -text | grep -A1 '1.3.6.1.4.1.41482.3.8')"
    echo "1..$n"
    if ((fails > 0)); then
      echo "# $fails read-back check(s) failed AFTER the signature: the signature was made and $out/root.pem exists."
      echo "# Nothing was written to the card. Compare root.pem by hand (openssl x509 -text) before any write-cert."
    fi
    grep -E 'Not Before|Not After|Subject:|Permitted|Excluded|DNS:|IP:' "$out/root.txt" | sed 's/^/#   /'
    echo "# NEXT, by hand, after judging the read-back (the only step that changes the card; needs the management key the store escrowed, no PIN, no touch unless the management key is touch-protected):"
    echo "#   piggy tool -K <management-key> write-cert $slot < $out/root.pem"
    echo "#   piggy tool cert $slot | diff - $out/root.pem      # must be identical"
    echo "# ROLLBACK (the key is never changed by write-cert):"
    echo "#   piggy tool -K <management-key> write-cert $slot < $out/slot$slot-placeholder.pem"
    echo "# Then root.pem travels to circus by reviewed commit; nix's curl trusts it per process through NIX_SSL_CERT_FILE."
    ((fails == 0))

# FDR 0007, the chain test (operator priority 2026-11-20): the card-free
# half. A holder (fibby + `piggy agent --holder`) bound to this shell's own
# cgroup mints the intermediate key and signs its request with `piggy ca
# csr`; the leaf's key file and request come from `piggy ca leaf-csr` (a
# piggy without that verb mints a second holder key and uses `ca csr`).
# No card, no PIN, no touch. The holder is stopped at the end, so the
# intermediate key dies with it: this proves the signing path; the
# production key is services.piggy-ca's. RUN=dry (default) prints the
# steps, RUN=go runs them. OUT holds int.pub, int.csr, leaf.key (0600),
# leaf.csr and the logs; int.csr and leaf.csr go to the card half.
# UNRUN against a real holder at the time of writing (the holder flags are
# the ca-csr lane's, minus its staged cgroup root).
#   CN_INT   the intermediate profile's CN (the card half's INT_CN must equal it)
#   CN_LEAF  the leaf request's CN: one of the leaf profile's names
#   OUT      the output directory (default: a new one under $PWD)
#
# stage the FDR 0007 chain test's card-free half: the holder-minted intermediate request and the leaf key and request (no card)
[group('explore')]
[linux]
explore-fdr0007-chain-holder CN_INT="circus-pigtrough-github-intermediate" CN_LEAF="github.com" OUT="" RUN="dry" FIBBY="" PIGGY="":
    #!/usr/bin/env bash
    set -euo pipefail
    cn_int={{ quote(CN_INT) }} cn_leaf={{ quote(CN_LEAF) }} out={{ quote(OUT) }} run={{ quote(RUN) }} fibby_bin={{ quote(FIBBY) }} piggy_bin={{ quote(PIGGY) }}
    # piggy: the PIGGY argument (a path, e.g. from `nix build .#default
    # --no-link --print-out-paths` plus /bin/piggy), else the one on PATH.
    # An installed piggy from before FDR 0006 phase (d) has no holder.
    if [[ -n $piggy_bin ]]; then
      [[ -x $piggy_bin ]] || { echo "PIGGY '$piggy_bin' is not an executable" >&2; exit 2; }
    else
      piggy_bin=$(command -v piggy) || { echo "piggy is not on PATH: pass PIGGY=<path to piggy>" >&2; exit 2; }
    fi
    piggy() { "$piggy_bin" "$@"; }
    echo "# piggy: $piggy_bin $(piggy --version 2>&1 | head -n1)"
    # fibby: the FIBBY argument (a path, e.g. from `nix build .#fibby
    # --no-link --print-out-paths` plus /bin/fibby), else the one on PATH.
    if [[ -n $fibby_bin ]]; then
      [[ -x $fibby_bin ]] || { echo "FIBBY '$fibby_bin' is not an executable" >&2; exit 2; }
    else
      fibby_bin=$(command -v fibby) || { echo "fibby is not on PATH: pass FIBBY=<path to fibby> (nix build .#fibby --no-link --print-out-paths, then /bin/fibby under it)" >&2; exit 2; }
    fi
    echo "# fibby: $fibby_bin (a nix store path carries its rev; fibby has no version flag)"
    [[ -n $out ]] || out="$PWD/fdr0007-chain-$(date -u +%Y%m%dT%H%M%SZ)"
    if [[ $run != go ]]; then
      cat <<EOF
    dry-run: explore-fdr0007-chain-holder would run, with no card, no PIN and no touch:
      1. fibby (virtual, yk5.7) and a holder agent bound to this shell's own cgroup; sockets under a short /tmp dir, logs in $out
      2. piggy holder mint --scope piggy-ca-intermediate-v1 --type p256 > $out/int.pub
      3. piggy ca csr --key $out/int.pub --cn $cn_int --out $out/int.csr           (signed through the holder)
      4. piggy ca leaf-csr --key-out $out/leaf.key --cn $cn_leaf --out $out/leaf.csr   (a piggy without leaf-csr: a second holder key and ca csr)
      5. stop the holder (the intermediate key dies with it); int.csr and leaf.csr go to explore-fdr0007-chain-card
    Run it: just explore-fdr0007-chain-holder '$cn_int' '$cn_leaf' '$out' go '$fibby_bin' '$piggy_bin'
    EOF
      exit 0
    fi
    mkdir -p "$out"
    chmod 700 "$out"
    own=$(sed -n 's/^0:://p' /proc/self/cgroup | head -n1)
    [[ -n $own ]] || { echo "no cgroup v2 line in /proc/self/cgroup: the holder cannot bind a scope here" >&2; exit 1; }
    # AF_UNIX sun_path is 108 bytes: the sockets live under a short /tmp dir.
    sockdir=$(mktemp -d /tmp/fc.XXXXXX)
    pcsc="$sockdir/pcscd.comm" ctl="$sockdir/ctl.sock" agent="$sockdir/a.sock"
    fibby_pid= agent_pid=
    stop() {
      [[ -n $agent_pid ]] && kill "$agent_pid" 2>/dev/null || true
      [[ -n $fibby_pid ]] && kill "$fibby_pid" 2>/dev/null || true
      wait 2>/dev/null || true
      rm -rf "$sockdir"
    }
    trap stop EXIT
    wait_sock() {
      local i
      for i in $(seq 1 100); do [[ -S $1 ]] && return 0; sleep 0.1; done
      echo "$1 never appeared; the logs ($out/fibby.log, $out/holder.log) end with:" >&2
      tail -n 20 "$out/fibby.log" "$out/holder.log" >&2 2>/dev/null || true
      return 1
    }
    FIBBY_LOG=wire "$fibby_bin" --socket "$pcsc" --backend virtual --model yk5.7 --control-socket "$ctl" >"$out/fibby.log" 2>&1 &
    fibby_pid=$!
    wait_sock "$pcsc"
    wait_sock "$ctl"
    # Only minted cards live in this holder: the default virtual card goes.
    "$fibby_bin" ctl --socket "$ctl" destroy "Virtual PCD piggy fibby 00 00" >/dev/null
    PCSCLITE_CSOCK_NAME="$pcsc" "$piggy_bin" agent --holder --holder-fibby-ctl "$ctl" \
      --scope "piggy-ca-intermediate-v1=cgroup:$own" --scope "piggy-ca-leaf-v1=cgroup:$own" \
      --scope-poll-interval 1 -a "$agent" >"$out/holder.log" 2>&1 &
    agent_pid=$!
    wait_sock "$agent"
    export SSH_AUTH_SOCK="$agent"
    unset PIGGY_AUTH_SOCK
    n=0 fails=0
    check() { # check DESCRIPTION COMMAND...; a failing check's output is printed as diagnostics
      n=$((n + 1))
      if "${@:2}" >"$out/check.out" 2>&1; then
        echo "ok $n - $1"
      else
        echo "not ok $n - $1"
        sed 's/^/#   /' "$out/check.out"
        fails=$((fails + 1))
      fi
    }
    echo "TAP version 14"
    check "the intermediate key is minted in the holder ($out/int.pub)" bash -c "'$piggy_bin' holder mint --scope piggy-ca-intermediate-v1 --type p256 > '$out/int.pub'"
    check "the intermediate request is signed through the holder ($out/int.csr)" "$piggy_bin" ca csr --key "$out/int.pub" --cn "$cn_int" --out "$out/int.csr"
    if "$piggy_bin" ca leaf-csr --help >/dev/null 2>&1; then
      check "the leaf key and request are made by piggy ca leaf-csr ($out/leaf.key 0600, $out/leaf.csr)" "$piggy_bin" ca leaf-csr --key-out "$out/leaf.key" --cn "$cn_leaf" --out "$out/leaf.csr"
    else
      echo "# this piggy has no 'ca leaf-csr': the leaf key is a second holder key, and dies with the holder"
      check "the leaf key is minted in the holder ($out/leaf.pub)" bash -c "'$piggy_bin' holder mint --scope piggy-ca-leaf-v1 --type p256 > '$out/leaf.pub'"
      check "the leaf request is signed through the holder ($out/leaf.csr)" "$piggy_bin" ca csr --key "$out/leaf.pub" --cn "$cn_leaf" --out "$out/leaf.csr"
    fi
    echo "1..$n"
    echo "# intermediate public key: $(cat "$out/int.pub" 2>/dev/null || echo none)"
    echo "# NEXT, on the host with the card: just explore-fdr0007-chain-card <card GUID> $out/int.csr $out/leaf.csr '$cn_int' ... CARD=real"
    echo "# The holder stops now and the intermediate key dies with it: this run proves the signing path; the production key is services.piggy-ca's."
    ((fails == 0))

# FDR 0007, the chain test: the card half, at the card, with the operator's
# own piggy agent (the one serving slot 9C) on SSH_AUTH_SOCK. S0 reads the
# pilot root from slot 82 and proves its key on-card (no PIN); S2 `piggy ca
# sign` certifies the holder's intermediate request under the root (PIN +
# touch twice: the certificate, then its act on 9C); S4' `piggy ca issue`
# signs a leaf under the root directly (PIN + touch twice again: the
# operator's interim ruling of 2026-11-20 until the holder issues leaves,
# piggy#392); then the read-back: the acts through `piggy act`, the chain
# through openssl until `piggy ca verify` exists. Scratch config and state
# under OUT; nothing is deployed and the card is never written (slot 82 is
# read back unchanged at the end). CARD=real is required; without it the
# steps are printed. UNRUN against a real card at the time of writing.
#   GUID       the card's GUID (32 hex), as `piggy tool -j list` prints it
#   INT_CSR    the intermediate request from explore-fdr0007-chain-holder
#   LEAF_CSR   the leaf request from the same (or any one-CN P-256 request)
#   INT_CN     the intermediate profile's CN: must equal the request's
#   NAMES      the permitted DNS names, comma-separated (the pilot root
#              permits github.com, which covers every name under it)
#   INT_HOURS, LEAF_HOURS  lifetimes (FDR 0007 levers: days for the
#              intermediate, about 30 days for the interim leaf)
#   OUT        the output directory (default: a new one under $PWD)
#
# stage the FDR 0007 chain test's card half: root read-back, ca sign of the intermediate, ca issue of a leaf, read-back (never writes the card)
[group('explore')]
[linux]
explore-fdr0007-chain-card GUID INT_CSR LEAF_CSR INT_CN="circus-pigtrough-github-intermediate" NAMES="github.com,api.github.com,codeload.github.com" INT_HOURS="168" LEAF_HOURS="720" OUT="" CARD="virtual" PIGGY="":
    #!/usr/bin/env bash
    set -euo pipefail
    guid={{ quote(GUID) }} int_csr={{ quote(INT_CSR) }} leaf_csr={{ quote(LEAF_CSR) }} int_cn={{ quote(INT_CN) }}
    names={{ quote(NAMES) }} int_hours={{ quote(INT_HOURS) }} leaf_hours={{ quote(LEAF_HOURS) }} out={{ quote(OUT) }} card={{ quote(CARD) }} piggy_bin={{ quote(PIGGY) }} slot=82
    # piggy: the PIGGY argument (a path), else the one on PATH; every piggy
    # call below goes through this function.
    if [[ -n $piggy_bin ]]; then
      [[ -x $piggy_bin ]] || { echo "PIGGY '$piggy_bin' is not an executable" >&2; exit 2; }
    else
      piggy_bin=$(command -v piggy) || { echo "piggy is not on PATH: pass PIGGY=<path to piggy>" >&2; exit 2; }
    fi
    piggy() { "$piggy_bin" "$@"; }
    export -f piggy
    export piggy_bin
    if [[ $card != real ]]; then
      cat <<EOF >&2
    explore-fdr0007-chain-card: this signs with the OPERATOR'S CARD (slot $slot): PIN + touch twice for the intermediate, twice for the leaf.
    It would run, in order (scratch config and state under OUT; nothing deployed; the card is never written):
      S0   piggy tool cert $slot > root.pem; piggy tool attest-verify $slot                 (no PIN)
      S2   piggy ca sign  --profile int  --out int.pem  < $int_csr    (PIN + touch: the certificate, then its act on 9C)
      S4'  piggy ca issue --profile leaf --out leaf.pem < $leaf_csr   (PIN + touch: the certificate, then its act on 9C)
      read-back: piggy act verify and canon on both acts; openssl verify of int.pem and leaf.pem under root.pem; slot $slot unchanged
    Run it as: just explore-fdr0007-chain-card $guid '$int_csr' '$leaf_csr' '$int_cn' '$names' $int_hours $leaf_hours '' real '$piggy_bin'
    EOF
      exit 2
    fi
    [[ $guid =~ ^[0-9A-Fa-f]{32}$ ]] || { echo "GUID must be 32 hex digits, got '$guid'" >&2; exit 2; }
    [[ -f $int_csr ]] || { echo "INT_CSR '$int_csr' is not a file" >&2; exit 2; }
    [[ -f $leaf_csr ]] || { echo "LEAF_CSR '$leaf_csr' is not a file" >&2; exit 2; }
    [[ -n ${SSH_AUTH_SOCK:-}${PIGGY_AUTH_SOCK:-} ]] || { echo "SSH_AUTH_SOCK is not set: the certificate acts are sealed through the operator's piggy agent (slot 9C)" >&2; exit 2; }
    [[ -n $out ]] || out="$PWD/fdr0007-chain-card-$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$out/config/ca-profiles" "$out/state"
    chmod 700 "$out"
    export PIGGY_CONFIG_HOME="$out/config" PIGGY_CA_STATE="$out/state"
    IFS=, read -ra name_list <<<"$names"
    toml_names=$(printf '"%s", ' "${name_list[@]}")
    toml_names="[${toml_names%, }]"
    cat >"$out/config/ca-profiles/int.toml" <<EOF
    kind = "intermediate"
    common_name = "$int_cn"
    names = $toml_names
    key_types = ["p256"]
    lifetime_hours = $int_hours
    [issuer]
    slot = "82"
    guid = "$guid"
    EOF
    cat >"$out/config/ca-profiles/leaf.toml" <<EOF
    kind = "leaf"
    names = $toml_names
    key_types = ["p256"]
    lifetime_hours = $leaf_hours
    [issuer]
    slot = "82"
    guid = "$guid"
    EOF
    n=0 fails=0
    check() { # check DESCRIPTION COMMAND...; a failing check's output is printed as diagnostics
      n=$((n + 1))
      if "${@:2}" >"$out/check.out" 2>&1; then
        echo "ok $n - $1"
      else
        echo "not ok $n - $1"
        sed 's/^/#   /' "$out/check.out"
        fails=$((fails + 1))
      fi
    }
    echo "TAP version 14"
    echo "# piggy: $piggy_bin $(piggy --version 2>&1 | head -n1); agent: ${PIGGY_AUTH_SOCK:-$SSH_AUTH_SOCK}"
    echo "# S0. card reads (no PIN, no touch): the pilot root and its key proven on-card"
    check "slot $slot certificate (the pilot root) saved ($out/root.pem)" bash -c "piggy tool cert $slot > '$out/root.pem'"
    check "slot $slot key attested as this card's (piggy tool attest-verify)" piggy tool attest-verify "$slot"
    if command -v openssl >/dev/null; then
      openssl x509 -in "$out/root.pem" -noout -subject -enddate 2>/dev/null | sed 's/^/#   /' || true
    fi
    if ((fails > 0)); then
      echo "Bail out! a card read failed: the card is not asked to sign"
      exit 1
    fi
    echo "# S2. the intermediate under the root (2 PIN + 2 touch): the verb asks for the PIN and a touch for the certificate, then the agent asks for the PIN and a touch for its act (under the certificate banner)."
    read -r -p "# Press Enter to run piggy ca sign (2 PIN + 2 touch), or Ctrl-C to stop: " _
    if piggy ca sign --profile int --out "$out/int.pem" <"$int_csr"; then
      echo "ok $((n += 1)) - ca sign: $out/int.pem and $out/int.pem.act"
    else
      echo "not ok $((n += 1)) - ca sign failed (exit $?); nothing was written to the card"
      echo "1..$n"
      exit 1
    fi
    check "the intermediate's act seal verifies (piggy act verify --seal-only)" piggy act verify --seal-only "$out/int.pem.act"
    check "the intermediate's act is a piggy:x509-ca link (piggy act canon)" bash -c "piggy act canon '$out/int.pem.act' | grep -q -- '- right = piggy:x509-ca'"
    echo "# S4'. a leaf under the root directly (2 PIN + 2 touch; the interim until the holder issues leaves, piggy#392)."
    read -r -p "# Press Enter to run piggy ca issue (2 PIN + 2 touch), or Ctrl-C to stop: " _
    if piggy ca issue --profile leaf --out "$out/leaf.pem" <"$leaf_csr"; then
      echo "ok $((n += 1)) - ca issue: $out/leaf.pem and $out/leaf.pem.act"
    else
      echo "not ok $((n += 1)) - ca issue failed (exit $?); the intermediate above stands; nothing was written to the card"
      echo "1..$n"
      exit 1
    fi
    check "the leaf's act seal verifies (piggy act verify --seal-only)" piggy act verify --seal-only "$out/leaf.pem.act"
    check "the leaf's act is a piggy:x509-leaf link (piggy act canon)" bash -c "piggy act canon '$out/leaf.pem.act' | grep -q -- '- right = piggy:x509-leaf'"
    check "two audit lines, one per certificate ($out/state/audit)" bash -c "[[ \$(wc -l < '$out/state/audit') -eq 2 ]]"
    check "slot $slot still serves the same root: the card was not written" bash -c "cmp -s <(piggy tool cert $slot) '$out/root.pem'"
    if command -v openssl >/dev/null; then
      echo "# read-back through openssl (interim: piggy ca verify is not built yet)"
      check "int.pem verifies under root.pem" openssl verify -CAfile "$out/root.pem" "$out/int.pem"
      check "leaf.pem verifies under root.pem" openssl verify -CAfile "$out/root.pem" "$out/leaf.pem"
      check "int.pem is a CA with pathlen 0" bash -c "openssl x509 -in '$out/int.pem' -noout -text | grep -q 'CA:TRUE, pathlen:0'"
      check "leaf.pem names every permitted name and is not a CA" bash -c "t=\$(openssl x509 -in '$out/leaf.pem' -noout -text); for name in ${names//,/ }; do grep -q \"DNS:\$name\" <<<\"\$t\" || exit 1; done; grep -q 'CA:FALSE' <<<\"\$t\""
      check "int.pem's key is the request's" bash -c "cmp -s <(openssl x509 -in '$out/int.pem' -noout -pubkey) <(openssl req -in '$int_csr' -noout -pubkey)"
      check "leaf.pem's key is the request's" bash -c "cmp -s <(openssl x509 -in '$out/leaf.pem' -noout -pubkey) <(openssl req -in '$leaf_csr' -noout -pubkey)"
    else
      echo "# openssl is not on PATH: the openssl read-back is skipped"
    fi
    if piggy ca verify --help >/dev/null 2>&1; then
      echo "# read-back in piggy: ca verify (the leaf under the root, its key the request's) and cert show"
      check "leaf.pem verifies under root.pem with the request's key (piggy ca verify)" bash -c "piggy ca verify --root '$out/root.pem' --untrusted '$out/int.pem' --key '$leaf_csr' '$out/leaf.pem' > '$out/verify-leaf.tap'"
      check "int.pem is a CA with pathlen 0 (piggy cert show)" bash -c "piggy cert show '$out/int.pem' | grep -q 'CA:TRUE pathlen:0'"
      check "leaf.pem names every permitted name and is not a CA (piggy cert show)" bash -c "t=\$(piggy cert show '$out/leaf.pem'); for name in \$(tr , ' ' <<<'$names'); do grep -q \"\$name\" <<<\"\$t\" || exit 1; done; grep -q 'CA:FALSE' <<<\"\$t\""
      piggy cert show "$out/int.pem" "$out/leaf.pem" 2>/dev/null | sed 's/^/#   /' || true
    else
      echo "# this piggy has no 'ca verify': the piggy read-back is skipped"
    fi
    echo "1..$n"
    echo "# outputs in $out: root.pem int.pem int.pem.act leaf.pem leaf.pem.act state/audit. Nothing deployed; nothing written to the card."
    ((fails == 0))

# The X.509 key identifiers of an SSH public key (FDR 0007): what an
# authority key identifier would carry for a certificate this key issued,
# so a repository can be searched for one. KEY is an OpenSSH public key
# line or its bare base64 (ecdsa-sha2-nistp256 only: the point is the last
# 65 bytes of the blob). Prints RFC 5280 method 1 (SHA-1 of the point,
# what openssl's `subjectKeyIdentifier=hash` writes) and RFC 7093 method 1
# (SHA-256 truncated to 160 bits, what piggy-piv's profile builders write),
# each as plain hex and colon-separated. Pure reads; no card.
#
# print the SKI forms (SHA-1 and RFC 7093) of an ecdsa-sha2-nistp256 OpenSSH public key
[group('debug')]
debug-ssh-key-identifiers KEY:
    #!/usr/bin/env bash
    set -euo pipefail
    key={{ quote(KEY) }}
    # Accept "ecdsa-sha2-nistp256 AAAA... comment" or the bare base64.
    if [[ $key == *" "* ]]; then key="$(awk '{print $2}' <<<"$key")"; fi
    blob="$(printf %s "$key" | base64 -d | od -An -v -tx1 | tr -d ' \n')"
    len=$(( ${#blob} / 2 ))
    [[ $len -eq 104 ]] || { echo "not an ecdsa-sha2-nistp256 blob: $len bytes, want 104" >&2; exit 2; }
    point="${blob:78}"   # bytes 39..104: 04 || X || Y
    [[ ${point:0:2} == 04 ]] || { echo "the point is not uncompressed (first byte ${point:0:2})" >&2; exit 2; }
    colons() { sed 's/../&:/g; s/:$//' <<<"$1" | tr a-f A-F; }
    sha1="$(printf %s "$point" | xxd -r -p | sha1sum | cut -d' ' -f1)"
    r7093="$(printf %s "$point" | xxd -r -p | sha256sum | cut -c1-40)"
    echo "point:            $point"
    echo "ski-sha1:         $sha1"
    echo "ski-sha1-colons:  $(colons "$sha1")"
    echo "ski-rfc7093:      $r7093"
    echo "ski-rfc7093-cols: $(colons "$r7093")"

# stage the piggy#382 hand pass: fibby holder build, profiles, test-flag refusal
[group('explore')]
[linux]
explore-fdr0006-c BIN_DIR="":
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -n "{{ BIN_DIR }}" ]]; then
      bin="$(realpath "{{ BIN_DIR }}")"
      holder="$bin/fibby-holder" testdouble="$bin/fibby" piggy="$bin/piggy"
    else
      holder="$(nix build .#fibby-holder --no-link --print-out-paths)/bin/fibby"
      testdouble="$(nix build .#fibby --no-link --print-out-paths)/bin/fibby"
      piggy="$(nix build .#default --no-link --print-out-paths)/bin/piggy"
    fi
    dir="$(mktemp -d -t fdr6c.XXXXXX)"
    export SSH_ASKPASS="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
    export SSH_ASKPASS_REQUIRE=force DISPLAY="" PIGGY_TEST_FIB_PIN=123456
    unset WAYLAND_DISPLAY
    pids=()
    cleanup() { kill "${pids[@]}" 2>/dev/null || true; rm -rf "$dir"; }
    trap cleanup EXIT
    trap 'exit 130' INT TERM HUP

    n=0 fails=0
    check() { # check DESCRIPTION COMMAND...
      n=$((n + 1))
      if "${@:2}" >/dev/null 2>&1; then echo "ok $n - $1"; else echo "not ok $n - $1"; fails=$((fails + 1)); fi
    }
    exits() { # exits WANT COMMAND...
      local rc=0
      timeout 10 "${@:2}" </dev/null >"$dir/last.out" 2>&1 || rc=$?
      [[ $rc == "$1" ]]
    }
    serves() { # serves COMMAND...: fibby comes up on $FIBBY_SOCK, then is stopped
      local sock="$dir/probe.sock" pid
      rm -f "$sock"
      FIBBY_SOCK="$sock" "$@" >"$dir/probe.log" 2>&1 &
      pid=$!
      for _ in $(seq 1 50); do [[ -S $sock ]] && break; sleep 0.1; done
      local up=0
      [[ -S $sock ]] && up=1
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      ((up == 1))
    }
    "$testdouble" --test-flags >"$dir/flags"
    echo "# holder:      $holder"
    echo "# test double: $testdouble"
    echo "# test-only flags: $(wc -l <"$dir/flags")"
    echo "TAP version 14"
    check "holder reports profile holder"            test "$("$holder" --build-profile)" = holder
    check "test double reports profile test-double"  test "$("$testdouble" --build-profile)" = test-double
    while IFS= read -r flag; do
      check "holder refuses $flag (exit 2)"          exits 2 "$holder" --socket "$dir/refuse.sock" "$flag"
    done <"$dir/flags"
    check "holder refuses FIBBY_LOG=wire (exit 2)"   exits 2 env FIBBY_LOG=wire "$holder" --socket "$dir/wire.sock"
    check "holder refuses --backend hardware"        exits 1 "$holder" --socket "$dir/hw.sock" --backend hardware
    check "test double serves with seed flags"       serves "$testdouble" --seed-rfc6979-slot-9a-cert --auto-touch
    check "test double serves with FIBBY_LOG=wire"   serves env FIBBY_LOG=wire "$testdouble"
    check "test double serves an Ed25519 yk5.7 card" serves "$testdouble" --model yk5.7 \
      --seed-slot-9a-ed25519 4242424242424242424242424242424242424242424242424242424242424242
    check "holder serves a yk5.7 card"               serves "$holder" --model yk5.7 --card "piggy-test yk5.7"
    check "holder serves a blank --card"             serves "$holder" --card "piggy-test holder"

    # A running holder (yk5.7, so Ed25519 can be minted), driven over its
    # control socket: create a card, read its attestation with piggy, list,
    # destroy (piggy#382 item 6).
    ctl="$dir/ctl.sock"
    export PCSCLITE_CSOCK_NAME="$dir/pcscd.comm"
    "$holder" --socket "$PCSCLITE_CSOCK_NAME" --control-socket "$ctl" --model yk5.7 \
      --card "piggy-test holder" >"$dir/holder.log" 2>&1 &
    holder_pid=$!
    pids+=($holder_pid)
    for _ in $(seq 1 50); do [[ -S $ctl ]] && break; sleep 0.1; done
    hctl() { "$holder" ctl --socket "$ctl" "$@"; }
    minted="piggy-test minted"
    check "holder: /proc/<pid>/environ belongs to root" test "$(stat -c %U "/proc/$holder_pid/environ")" = root
    check "holder: core limit 0"                     test "$(awk '/^Max core file size/ {print $5}' "/proc/$holder_pid/limits")" = 0
    check "holder: ctl profile is holder"            test "$(hctl profile)" = "ok holder"
    check "holder: ctl fault is unknown"             exits 1 "$holder" ctl --socket "$ctl" fault 20 63C2 "piggy-test holder"
    check "holder: create an Ed25519 card"           hctl create alg=ed25519 pin=once touch=never "$minted"
    check "holder: the card is listed"               grep -qF "$minted" <(hctl list)
    check "holder: piggy reads its 9A attestation"   "$piggy" card export-attestation 9a --reader "$minted"
    check "holder: a second card of that name is refused" exits 1 "$holder" ctl --socket "$ctl" create "$minted"
    check "holder: destroy it"                       hctl destroy "$minted"
    check "holder: it is no longer listed"           bash -c "! \"$holder\" ctl --socket \"$ctl\" list | grep -qF \"$minted\""
    check "holder: destroying it again is refused"   exits 1 "$holder" ctl --socket "$ctl" destroy "$minted"
    echo "1..$n"

    echo "# NOTE: a created card's key goes in slot 9A with the factory PIN (123456). That is"
    echo "#       phase (c)'s placeholder, not the design: slot and PIN policy are phase (d)'s"
    echo "#       to settle with mint@piggy (FDR 0006)."
    if [[ "${NO_SHELL:-}" == 1 ]]; then
      echo "# NO_SHELL=1: no shell; $fails of $n checks failed."
      ((fails == 0))
      exit
    fi
    echo "# A holder is serving $PCSCLITE_CSOCK_NAME (control socket $ctl)."
    echo "# Try: \"\$FIBBY\" ctl --socket \"\$FIBBY_CTL\" profile | list | create [alg=…] NAME | destroy NAME"
    echo "#      \"\$PIGGY\" card export-attestation 9a --reader NAME"
    echo "#      \"\$FIBBY\" --help; \"\$FIBBY_TEST_DOUBLE\" --help; cat \"$dir/holder.log\""
    echo "# exit the shell to stop it."
    FIBBY="$holder" FIBBY_TEST_DOUBLE="$testdouble" FIBBY_CTL="$ctl" PIGGY="$piggy" \
      "${SHELL:-bash}" -i || true
    ((fails == 0))
