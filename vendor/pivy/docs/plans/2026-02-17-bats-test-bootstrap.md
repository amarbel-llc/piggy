# BATS Test Infrastructure Bootstrap — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Bootstrap CLI smoke tests for pivy-tool, pivy-agent, and pivy-box using bats + batman + sandcastle, verifying basic usage/version/error behavior without PIV hardware.

**Architecture:** Standard robin/bats-testing layout under `zz-tests_bats/`. Flake inputs for batman (assertion libs) and sandcastle (isolation). Root justfile delegates to test justfile. Built binaries from `nix build` are put on PATH via justfile.

**Tech Stack:** bats-core, batman (bats-support + bats-assert + bats-assert-additions), sandcastle (bubblewrap isolation), just, nix flakes

---

### Task 1: Add batman and sandcastle flake inputs and update devShell

**Files:**
- Modify: `flake.nix`

**Step 1: Add flake inputs**

Add after the existing `utils` input:

```nix
batman.url = "github:amarbel-llc/batman";
sandcastle.url = "github:amarbel-llc/sandcastle";
```

Add `batman` and `sandcastle` to the outputs function parameters:

```nix
outputs =
  {
    self,
    nixpkgs,
    nixpkgs-master,
    utils,
    batman,
    sandcastle,
  }:
```

**Step 2: Add test dependencies to devShell**

Replace the existing `devShells.default` with:

```nix
devShells.default = pkgs.mkShell {
  packages = buildInputs ++ nativeBuildInputs ++ (with pkgs; [
    bats
    just
    gum
  ]) ++ [
    batman.packages.${system}.bats-libs
    sandcastle.packages.${system}.default
  ];
};
```

**Step 3: Lock the new inputs**

Run: `nix flake lock` (use the nix MCP flake_lock tool)
Expected: flake.lock updated with batman and sandcastle entries

**Step 4: Verify devShell builds**

Run: `nix develop -c bash -c 'bats --version && sandcastle --help'`
Expected: bats version printed, sandcastle help printed

**Step 5: Commit**

```
git add flake.nix flake.lock
git commit -m "feat: add batman and sandcastle flake inputs for bats testing"
```

---

### Task 2: Create zz-tests_bats directory structure and common files

**Files:**
- Create: `zz-tests_bats/common.bash`
- Create: `zz-tests_bats/bin/run-sandcastle-bats.bash`

**Step 1: Create common.bash**

```bash
bats_load_library bats-support
bats_load_library bats-assert
bats_load_library bats-assert-additions

chflags_and_rm() {
  chflags -R nouchg "$BATS_TEST_TMPDIR" 2>/dev/null || true
  rm -rf "$BATS_TEST_TMPDIR"
}
```

**Step 2: Create sandcastle wrapper**

Create `zz-tests_bats/bin/run-sandcastle-bats.bash`:

```bash
#!/usr/bin/env bash
set -e

srt_config="$(mktemp)"
trap 'rm -f "$srt_config"' EXIT

cat >"$srt_config" <<SETTINGS
{
  "filesystem": {
    "denyRead": [
      "$HOME/.ssh",
      "$HOME/.aws",
      "$HOME/.gnupg",
      "$HOME/.config",
      "$HOME/.local",
      "$HOME/.password-store",
      "$HOME/.kube"
    ],
    "denyWrite": [],
    "allowWrite": [
      "/tmp"
    ]
  },
  "network": {
    "allowedDomains": [],
    "deniedDomains": []
  }
}
SETTINGS

exec sandcastle \
  --shell bash \
  --config "$srt_config" \
  "$@"
```

Mark executable: `chmod +x zz-tests_bats/bin/run-sandcastle-bats.bash`

**Step 3: Commit**

```
git add zz-tests_bats/common.bash zz-tests_bats/bin/run-sandcastle-bats.bash
git commit -m "feat: add bats common helper and sandcastle wrapper"
```

---

### Task 3: Create zz-tests_bats justfile

**Files:**
- Create: `zz-tests_bats/justfile`

**Step 1: Write the test justfile**

```makefile
bats_timeout := "5"

test-targets *targets="*.bats":
  BATS_TEST_TIMEOUT="{{bats_timeout}}" ./bin/run-sandcastle-bats.bash \
    bats --tap --jobs {{num_cpus()}} {{targets}}

test-tags *tags:
  BATS_TEST_TIMEOUT="{{bats_timeout}}" ./bin/run-sandcastle-bats.bash \
    bats --tap --jobs {{num_cpus()}} --filter-tags {{tags}} *.bats

test: (test-targets "*.bats")
```

**Step 2: Commit**

```
git add zz-tests_bats/justfile
git commit -m "feat: add bats test justfile with sandcastle runner"
```

---

### Task 4: Wire root justfile to delegate to bats tests

**Files:**
- Modify: `justfile`

**Step 1: Update root justfile**

Replace contents with:

```makefile
build:
  nix build

test-bats: build
  just zz-tests_bats/test

test: test-bats
```

Note: `nix build` produces `./result/bin/` with pivy-tool, pivy-agent, pivy-box.
The bats tests will need these on PATH. The test justfile will handle this via
the sandcastle wrapper inheriting PATH from the root justfile.

Actually, we need to put the built binaries on PATH. Update:

```makefile
build:
  nix build

test-bats: build
  PATH="$(readlink -f ./result)/bin:$PATH" just zz-tests_bats/test

test: test-bats
```

**Step 2: Commit**

```
git add justfile
git commit -m "feat: wire root justfile to bats test suite"
```

---

### Task 5: Write pivy-tool smoke tests

**Files:**
- Create: `zz-tests_bats/pivy_tool.bats`

**Step 1: Write the test file**

```bash
#! /usr/bin/env bats

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output
}

teardown() {
  chflags_and_rm
}

function no_args_prints_usage_and_fails { # @test
  run pivy-tool
  assert_failure
  assert_output --partial "usage: pivy-tool"
}

function version_prints_semver_and_succeeds { # @test
  run pivy-tool version
  assert_success
  assert_output --regexp "^[0-9]+\.[0-9]+\.[0-9]+"
}

function bad_subcommand_fails { # @test
  run pivy-tool nonexistent-command
  assert_failure
}
```

**Step 2: Run tests to verify they pass**

Run: `just test-bats` (from repo root)
Expected: TAP output, 3 tests pass

Note on pivy-tool behavior:
- No args → prints "usage: pivy-tool ..." to stderr, exits 2
- `version` → prints "0.12.1" to stdout, exits 0
- Bad subcommand → will attempt piv_open()/piv_establish_context() and likely
  fail or print error, exits non-zero

**Step 3: Commit**

```
git add zz-tests_bats/pivy_tool.bats
git commit -m "feat: add pivy-tool CLI smoke tests"
```

---

### Task 6: Write pivy-agent smoke tests

**Files:**
- Create: `zz-tests_bats/pivy_agent.bats`

**Step 1: Write the test file**

pivy-agent with no args (and no -g/-A) calls usage() and exits 1.
pivy-agent with a bad option calls usage() and exits 1.

```bash
#! /usr/bin/env bats

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output
}

teardown() {
  chflags_and_rm
}

function no_args_prints_usage_and_fails { # @test
  run pivy-agent
  assert_failure
  assert_output --partial "usage: pivy-agent"
}

function bad_option_prints_usage_and_fails { # @test
  run pivy-agent -Q
  assert_failure
  assert_output --partial "usage: pivy-agent"
}
```

**Step 2: Run tests to verify they pass**

Run: `just test-bats`
Expected: TAP output, 2 tests pass (plus previous 3)

Note: pivy-agent without -g or -A calls usage() which prints to stderr and
exits 1. The `-Q` option is not in the getopt string so triggers default case.

**Step 3: Commit**

```
git add zz-tests_bats/pivy_agent.bats
git commit -m "feat: add pivy-agent CLI smoke tests"
```

---

### Task 7: Write pivy-box smoke tests

**Files:**
- Create: `zz-tests_bats/pivy_box.bats`

**Step 1: Write the test file**

pivy-box with no args prints "type and operation required" + usage, exits 1.
pivy-box with only one arg (type but no op) prints "operation required" + usage, exits 1.

```bash
#! /usr/bin/env bats

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output
}

teardown() {
  chflags_and_rm
}

function no_args_prints_usage_and_fails { # @test
  run pivy-box
  assert_failure
  assert_output --partial "type and operation required"
}

function type_without_op_prints_usage_and_fails { # @test
  run pivy-box key
  assert_failure
  assert_output --partial "operation required"
}

function bad_type_and_op_fails { # @test
  run pivy-box nonexistent badop
  assert_failure
}
```

**Step 2: Run tests to verify they pass**

Run: `just test-bats`
Expected: TAP output, 3 tests pass (plus previous 5, 8 total)

**Step 3: Commit**

```
git add zz-tests_bats/pivy_box.bats
git commit -m "feat: add pivy-box CLI smoke tests"
```

---

### Task 8: Run full test suite and verify

**Step 1: Run all tests**

Run: `just test`
Expected: 8 tests pass with TAP output

**Step 2: Verify nix build still works**

Run: `nix build` (use nix MCP build tool)
Expected: builds successfully

**Step 3: Final commit if any fixups needed**

Only if adjustments were required during the run.
