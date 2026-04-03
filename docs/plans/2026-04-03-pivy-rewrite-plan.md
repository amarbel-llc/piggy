# Piggy Pivy Rewrite Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Rewrite piggy (a passwordstore.org fork) to use pivy-box
stream/templates for encryption instead of GPG.

**Architecture:** In-place rewrite of the main shell script
(`src/password-store.sh` → `src/piggy.sh`). Replace all GPG calls with
`pivy-box stream encrypt/decrypt`. Replace `.gpg-id` files with `.pivy-id` ebox
template files. Update tests to use a mock `pivy-box` for CI. Update emacs
integration (`piggy.el`).

**Tech Stack:** bash, pivy-box, pivy-tool, sharness (tests), emacs lisp

**Rollback:** N/A --- piggy is a separate command from pass. Both coexist.

**Key reference files:**

- Design doc: `docs/plans/2026-04-03-pivy-rewrite-design.md`
- pivy-box CLI: encrypts via `pivy-box stream encrypt <tpl-path>`, decrypts via
  `pivy-box stream decrypt`
- pivy-tool: `pivy-tool -k <pubkey> box` (low-level, not used here),
  `pivy-tool pubkey 9a` (get public key from card)
- ebox template: binary file, base64-encoded by pivy-box CLI, stored in
  `.pivy-id`

--------------------------------------------------------------------------------

### Task 1: Create mock pivy-box for tests

The mock enables all tests to run without a physical PIV card. It uses base64
encode/decode as a stand-in for real encryption.

**Promotion criteria:** N/A

**Files:**

- Create: `tests/mock-pivy-box.sh`
- Create: `tests/mock-pivy-tool.sh`

**Step 1: Write mock-pivy-box.sh**

This script handles the `stream encrypt`, `stream decrypt`, `tpl create`,
`tpl show`, and `tpl edit` subcommands using base64. Templates are stored as
plain text listing public keys.

``` bash
#!/usr/bin/env bash
# Mock pivy-box for testing without a real PIV card.
# Encrypts with base64 (no real security), decrypts with base64 -d.
# Supports: stream encrypt/decrypt, tpl create/show

set -euo pipefail

case "${1:-}" in
  stream)
    case "${2:-}" in
      encrypt)
        # Usage: mock-pivy-box stream encrypt <tpl-path>
        tpl="${3:-}"
        [[ -f "$tpl" ]] || { echo "error: template not found: $tpl" >&2; exit 1; }
        base64
        ;;
      decrypt)
        # Usage: mock-pivy-box stream decrypt < encrypted-data
        base64 -d
        ;;
      *) echo "error: unknown stream operation: ${2:-}" >&2; exit 1 ;;
    esac
    ;;
  tpl)
    case "${2:-}" in
      create)
        # Usage: mock-pivy-box tpl create <name> (non-interactive)
        # In tests, we pre-create .pivy-id files directly
        echo "error: use tests/create-test-template.sh instead" >&2
        exit 1
        ;;
      show)
        # Usage: mock-pivy-box tpl show < template-file
        # or: mock-pivy-box tpl show <tpl-path>
        if [[ -n "${3:-}" && -f "${3:-}" ]]; then
          cat "${3}"
        else
          cat
        fi
        ;;
      *) echo "error: unknown tpl operation: ${2:-}" >&2; exit 1 ;;
    esac
    ;;
  *) echo "error: unknown command: ${1:-}" >&2; exit 1 ;;
esac
```

**Step 2: Write mock-pivy-tool.sh**

``` bash
#!/usr/bin/env bash
# Mock pivy-tool for testing without a real PIV card.
set -euo pipefail

case "${1:-}" in
  pubkey)
    # Usage: mock-pivy-tool pubkey <slot>
    echo "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFAKEKEYDATA= PIV_slot_${2:-9A}@TESTGUID"
    ;;
  list)
    cat <<'EOF'
      card: TESTGUID
    device: Test Virtual PIV
     chuid: ok
      guid: TESTGUID1234567890ABCDEF
     slots:
           ID   TYPE     BITS  CERTIFICATE
           9a   ECDSA    256   /CN=test
EOF
    ;;
  *) echo "error: unknown operation: ${1:-}" >&2; exit 1 ;;
esac
```

**Step 3: Make both executable**

Run: `chmod +x tests/mock-pivy-box.sh tests/mock-pivy-tool.sh`

**Step 4: Commit**

    git add tests/mock-pivy-box.sh tests/mock-pivy-tool.sh
    git commit -m "tests: Add mock pivy-box and pivy-tool for cardless testing"

--------------------------------------------------------------------------------

### Task 2: Rename and strip the main script

Rename `src/password-store.sh` to `src/piggy.sh`. Remove GPG initialization,
extension support, GPG signing, and cygwin/freebsd/openbsd platforms. Update env
var names. This task does not add pivy-box calls yet --- it strips GPG and
prepares the skeleton.

**Promotion criteria:** N/A

**Files:**

- Rename: `src/password-store.sh` → `src/piggy.sh`
- Delete: `src/platform/cygwin.sh`
- Delete: `src/platform/freebsd.sh`
- Delete: `src/platform/openbsd.sh`
- Modify: `Makefile`

**Step 1: Rename the main script**

Run: `git mv src/password-store.sh src/piggy.sh`

**Step 2: Delete unused platform files**

Run:
`git rm src/platform/cygwin.sh src/platform/freebsd.sh src/platform/openbsd.sh`

**Step 3: Strip GPG initialization from src/piggy.sh**

Replace lines 6--22 (GPG setup, env vars) with:

``` bash
umask "${PIGGY_UMASK:-077}"
set -o pipefail

PREFIX="${PIGGY_STORE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/piggy}"
X_SELECTION="${PIGGY_X_SELECTION:-clipboard}"
CLIP_TIME="${PIGGY_CLIP_TIME:-45}"
GENERATED_LENGTH="${PIGGY_GENERATED_LENGTH:-25}"
CHARACTER_SET="${PIGGY_CHARACTER_SET:-[:punct:][:alnum:]}"
CHARACTER_SET_NO_SYMBOLS="${PIGGY_CHARACTER_SET_NO_SYMBOLS:-[:alnum:]}"
```

**Step 4: Remove extension-related code**

Remove the `EXTENSIONS` variable, `cmd_extension()`, `cmd_extension_or_show()`,
`SYSTEM_EXTENSION_DIR`, `PASSWORD_STORE_ENABLE_EXTENSIONS` references, and the
`verify_file()` function (GPG signing). Remove the extension prune from find
commands.

**Step 5: Remove GPG-specific helper functions**

Remove `set_gpg_recipients()` entirely. Remove `verify_file()`. Remove the
`$GPG` variable and all `GPG_OPTS`, `GPG_RECIPIENT_ARGS`, `GPG_RECIPIENTS`
references. Remove `PASSWORD_STORE_SIGNING_KEY` references.

These will be replaced by pivy-box calls in Task 3.

**Step 6: Update version and usage text**

Replace `cmd_version()` with piggy branding. Update `cmd_usage()` to reflect
piggy commands (remove gpg-id references, add template references).

**Step 7: Update the dispatch table**

Replace `cmd_extension_or_show` fallthrough with just `cmd_show`:

``` bash
*)  COMMAND="show"; cmd_show "$@" ;;
```

**Step 8: Update Makefile**

- Change `password-store.sh` → `piggy.sh`
- Change installed binary name from `pass` to `piggy`
- Change `password-store` lib dir to `piggy`
- Remove extension directory install
- Remove SYSTEM_EXTENSION_DIR sed replacement
- Update man page references (pass.1 → piggy.1, or remove man install for now)

**Step 9: Commit**

    git add -A
    git commit -m "Rename to piggy, strip GPG and extension support"

--------------------------------------------------------------------------------

### Task 3: Add pivy-box crypto layer

Add the new encryption/decryption functions using pivy-box. Replace all GPG
encrypt/decrypt calls in the command functions.

**Promotion criteria:** N/A

**Files:**

- Modify: `src/piggy.sh`

**Step 1: Add set_pivy_template() helper**

This replaces `set_gpg_recipients()`. It walks up the directory tree looking for
`.pivy-id` files, just like pass walks for `.gpg-id`.

``` bash
set_pivy_template() {
    local current="$PREFIX/$1"
    while [[ $current != "$PREFIX" && ! -f $current/.pivy-id ]]; do
        current="${current%/*}"
    done
    PIVY_TPL="$current/.pivy-id"

    if [[ ! -f $PIVY_TPL ]]; then
        cat >&2 <<-_EOF
        Error: You must run:
            $PROGRAM init
        before you may use the password store.

        _EOF
        cmd_usage
        exit 1
    fi
}
```

**Step 2: Add encrypt/decrypt wrapper functions**

``` bash
piggy_encrypt() {
    # Usage: echo "secret" | piggy_encrypt <output-file> <tpl-path>
    local outfile="$1" tpl="$2"
    pivy-box stream encrypt "$tpl" > "$outfile" || die "Encryption aborted."
}

piggy_decrypt() {
    # Usage: piggy_decrypt <input-file>
    pivy-box stream decrypt < "$1" || exit $?
}
```

**Step 3: Add reencrypt_path() using pivy-box**

``` bash
reencrypt_path() {
    local passfile passfile_dir passfile_display passfile_temp
    while read -r -d "" passfile; do
        [[ -L $passfile ]] && continue
        passfile_dir="${passfile%/*}"
        passfile_dir="${passfile_dir#$PREFIX}"
        passfile_dir="${passfile_dir#/}"
        passfile_display="${passfile#$PREFIX/}"
        passfile_display="${passfile_display%.ebox}"
        passfile_temp="${passfile}.tmp.${RANDOM}.${RANDOM}.${RANDOM}.${RANDOM}.--"

        set_pivy_template "$passfile_dir"
        echo "$passfile_display: reencrypting"
        pivy-box stream decrypt < "$passfile" | pivy-box stream encrypt "$PIVY_TPL" > "$passfile_temp" &&
        mv "$passfile_temp" "$passfile" || rm -f "$passfile_temp"
    done < <(find "$1" -path '*/.git' -prune -o -iname '*.ebox' -print0)
}
```

Note: unlike GPG, pivy-box doesn't support checking which keys a file was
encrypted to, so we always re-encrypt (no skip optimization). This is acceptable
because re-encryption is rare.

**Step 4: Update cmd_show()**

Replace `$GPG -d` calls with `piggy_decrypt`. Change `.gpg` to `.ebox` in file
paths. Replace `set_gpg_recipients` with `set_pivy_template`.

Key changes:

- `local passfile="$PREFIX/$path.gpg"` → `local passfile="$PREFIX/$path.ebox"`
- `$GPG -d "${GPG_OPTS[@]}" "$passfile"` → `piggy_decrypt "$passfile"`
- tree sed: `s/\.gpg(` → `s/\.ebox(`

**Step 5: Update cmd_find()**

Change tree sed from `.gpg` to `.ebox`.

**Step 6: Update cmd_grep()**

Replace `$GPG -d` with `piggy_decrypt`. Change find pattern from `*.gpg` to
`*.ebox`. Change `passfile="${passfile%.gpg}"` to
`passfile="${passfile%.ebox}"`. Remove `.extensions` prune.

**Step 7: Update cmd_insert()**

Replace all `$GPG -e` calls with `piggy_encrypt`. Change `.gpg` to `.ebox`.
Replace `set_gpg_recipients` with `set_pivy_template`.

Key patterns:

- `$GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$passfile" "${GPG_OPTS[@]}"` →
  `piggy_encrypt "$passfile" "$PIVY_TPL"`
- stdin piping: `echo "$password" | piggy_encrypt "$passfile" "$PIVY_TPL"`
- multiline: pipe stdin through `piggy_encrypt "$passfile" "$PIVY_TPL"`

**Step 8: Update cmd_edit()**

Replace decrypt/encrypt calls. Change `.gpg` to `.ebox`.

**Step 9: Update cmd_generate()**

Replace encrypt/decrypt calls. Change `.gpg` to `.ebox`. For in-place
generation, decrypt via `piggy_decrypt`, pipe through `piggy_encrypt`.

**Step 10: Update cmd_delete()**

Change `.gpg` to `.ebox`.

**Step 11: Update cmd_copy_move()**

Change `.gpg` to `.ebox`.

**Step 12: Update cmd_git()**

Change `.gitattributes` from `*.gpg diff=gpg` to `*.ebox diff=ebox`. Change
textconv from GPG to `pivy-box stream decrypt`. Change config keys from
`diff.gpg.*` to `diff.ebox.*`. Change `pass.signcommits` to `piggy.signcommits`.

**Step 13: Commit**

    git add src/piggy.sh
    git commit -m "Replace GPG crypto layer with pivy-box stream encrypt/decrypt"

--------------------------------------------------------------------------------

### Task 4: Rewrite cmd_init() for pivy-box templates

The init command needs three modes: interactive (pivy-box tpl create),
non-interactive (-k pubkey), and edit (-e).

**Promotion criteria:** N/A

**Files:**

- Modify: `src/piggy.sh`

**Step 1: Write the new cmd_init()**

``` bash
cmd_init() {
    local opts id_path="" pubkey="" edit=0
    opts="$($GETOPT -o p:k:e -l path:,key:,edit -n "$PROGRAM" -- "$@")"
    local err=$?
    eval set -- "$opts"
    while true; do case $1 in
        -p|--path) id_path="$2"; shift 2 ;;
        -k|--key) pubkey="$2"; shift 2 ;;
        -e|--edit) edit=1; shift ;;
        --) shift; break ;;
    esac done

    [[ $err -ne 0 ]] && die "Usage: $PROGRAM $COMMAND [-p subfolder] [-k pubkey] [-e]"
    [[ -n $id_path ]] && check_sneaky_paths "$id_path"
    [[ -n $id_path && ! -d $PREFIX/$id_path && -e $PREFIX/$id_path ]] && die "Error: $PREFIX/$id_path exists but is not a directory."

    local pivy_id="$PREFIX/$id_path/.pivy-id"
    set_git "$pivy_id"

    if [[ $edit -eq 1 ]]; then
        # Edit existing template
        [[ ! -f "$pivy_id" ]] && die "Error: $pivy_id does not exist. Run '$PROGRAM init' first."
        pivy-box tpl edit "$pivy_id" || die "Template editing failed."
    elif [[ -n $pubkey ]]; then
        # Non-interactive: create single-recipient template from pubkey
        mkdir -v -p "$PREFIX/$id_path"
        pivy-box tpl create -k "$pubkey" "$pivy_id" || die "Template creation failed."
    else
        # Interactive: run pivy-box tpl create
        mkdir -v -p "$PREFIX/$id_path"
        pivy-box tpl create -i "$pivy_id" || die "Template creation failed."
    fi

    echo "Password store initialized${id_path:+ ($id_path)}"
    git_add_file "$pivy_id" "Set pivy template${id_path:+ ($id_path)}."

    reencrypt_path "$PREFIX/$id_path"
    git_add_file "$PREFIX/$id_path" "Reencrypt password store using new pivy template${id_path:+ ($id_path)}."
}
```

Note: The exact `pivy-box tpl create` flags need verification against the actual
CLI. The `-k` and `-i` flags are placeholders --- the implementer must check
`pivy-box tpl create --help` and adjust. If pivy-box tpl create doesn't support
non-interactive single-key creation, we may need to construct the template
programmatically or use `pivy-tool -k <pubkey> box` as a fallback for the init
path only.

**Step 2: Run test to verify init works**

This depends on Task 5 (test updates), but can be manually tested:

``` bash
mkdir -p /tmp/piggy-test
PIGGY_STORE_DIR=/tmp/piggy-test src/piggy.sh init -k "$(pivy-tool pubkey 9a)"
ls -la /tmp/piggy-test/.pivy-id
pivy-box tpl show /tmp/piggy-test/.pivy-id
```

**Step 3: Commit**

    git add src/piggy.sh
    git commit -m "Rewrite init command for pivy-box template management"

--------------------------------------------------------------------------------

### Task 5: Update test setup and sanity tests

Replace GPG test infrastructure with mock pivy-box. Update setup.sh and the
sanity check test.

**Promotion criteria:** N/A

**Files:**

- Modify: `tests/setup.sh`
- Modify: `tests/t0001-sanity-checks.sh`

**Step 1: Rewrite tests/setup.sh**

``` bash
# This file should be sourced by all test-scripts
#
# This scripts sets the following:
#   $PIGGY      Full path to piggy script to test
#   $TEST_HOME  This folder

# Unset config vars
unset PIGGY_STORE_DIR
unset PIGGY_GIT
unset PIGGY_X_SELECTION
unset PIGGY_CLIP_TIME
unset PIGGY_UMASK
unset PIGGY_GENERATED_LENGTH
unset PIGGY_CHARACTER_SET
unset PIGGY_CHARACTER_SET_NO_SYMBOLS
unset EDITOR

# We must be called from tests/
TEST_HOME="$(pwd)"

. ./sharness.sh

export PIGGY_STORE_DIR="$SHARNESS_TRASH_DIRECTORY/test-store/"
rm -rf "$PIGGY_STORE_DIR"
mkdir -p "$PIGGY_STORE_DIR"
if [[ ! -d $PIGGY_STORE_DIR ]]; then
    echo "Could not create $PIGGY_STORE_DIR"
    exit 1
fi

export GIT_DIR="$PIGGY_STORE_DIR/.git"
export GIT_WORK_TREE="$PIGGY_STORE_DIR"
git config --global user.email "Piggy-Automated-Testing-Suite@test.local"
git config --global user.name "Piggy Automated Testing Suite"

PIGGY="$TEST_HOME/../src/piggy.sh"
if [[ ! -e $PIGGY ]]; then
    echo "Could not find piggy.sh"
    exit 1
fi

# Use mock pivy-box and pivy-tool for testing without a real PIV card
export PATH="$TEST_HOME:$PATH"
# Create symlinks so the mocks are found as pivy-box and pivy-tool
ln -sf "$TEST_HOME/mock-pivy-box.sh" "$SHARNESS_TRASH_DIRECTORY/pivy-box"
ln -sf "$TEST_HOME/mock-pivy-tool.sh" "$SHARNESS_TRASH_DIRECTORY/pivy-tool"
export PATH="$SHARNESS_TRASH_DIRECTORY:$PATH"

# Create a test .pivy-id template (just a marker file for the mock)
create_test_template() {
    local dir="${1:-$PIGGY_STORE_DIR}"
    mkdir -p "$dir"
    echo "MOCK_PIVY_TEMPLATE_v1" > "$dir/.pivy-id"
}
```

**Step 2: Rewrite tests/t0001-sanity-checks.sh**

``` bash
#!/usr/bin/env bash

test_description='Sanity checks'
cd "$(dirname "$0")"
. ./setup.sh

test_expect_success 'Make sure we can run piggy' '
    "$PIGGY" --help | grep "piggy"
'

test_expect_success 'Make sure we can initialize our test store' '
    create_test_template &&
    [[ -e "$PIGGY_STORE_DIR/.pivy-id" ]]
'

test_done
```

**Step 3: Run the sanity test**

Run: `cd tests && bash t0001-sanity-checks.sh` Expected: Both tests pass.

**Step 4: Commit**

    git add tests/setup.sh tests/t0001-sanity-checks.sh
    git commit -m "tests: Update setup and sanity checks for piggy with mock pivy-box"

--------------------------------------------------------------------------------

### Task 6: Update insert and show tests

**Promotion criteria:** N/A

**Files:**

- Modify: `tests/t0100-insert-tests.sh`
- Modify: `tests/t0020-show-tests.sh`

**Step 1: Rewrite t0100-insert-tests.sh**

``` bash
#!/usr/bin/env bash

test_description='Test insert'
cd "$(dirname "$0")"
. ./setup.sh

test_expect_success 'Test "insert" command' '
    create_test_template &&
    echo "Hello world" | "$PIGGY" insert -e cred1 &&
    [[ $("$PIGGY" show cred1) == "Hello world" ]]
'

test_done
```

**Step 2: Rewrite t0020-show-tests.sh**

``` bash
#!/usr/bin/env bash

test_description='Test show'
cd "$(dirname "$0")"
. ./setup.sh

test_expect_success 'Test "show" command' '
    create_test_template &&
    "$PIGGY" generate cred1 20 &&
    "$PIGGY" show cred1
'

test_expect_success 'Test "show" command with spaces' '
    "$PIGGY" insert -e "I am a cred with lots of spaces"<<<"BLAH!!" &&
    [[ $("$PIGGY" show "I am a cred with lots of spaces") == "BLAH!!" ]]
'

test_expect_success 'Test "show" command with unicode' '
    "$PIGGY" generate 🏠 &&
    "$PIGGY" show | grep -q "🏠"
'

test_expect_success 'Test "show" of nonexistant password' '
    test_must_fail "$PIGGY" show cred2
'

test_done
```

**Step 3: Run tests**

Run: `cd tests && bash t0100-insert-tests.sh && bash t0020-show-tests.sh`
Expected: All tests pass.

**Step 4: Commit**

    git add tests/t0100-insert-tests.sh tests/t0020-show-tests.sh
    git commit -m "tests: Update insert and show tests for piggy"

--------------------------------------------------------------------------------

### Task 7: Update generate, edit, rm, mv, grep, find tests

**Promotion criteria:** N/A

**Files:**

- Modify: `tests/t0010-generate-tests.sh`
- Modify: `tests/t0200-edit-tests.sh`
- Modify: `tests/t0060-rm-tests.sh`
- Modify: `tests/t0050-mv-tests.sh`
- Modify: `tests/t0400-grep.sh`
- Modify: `tests/t0500-find.sh`

**Step 1: Update each test file**

For each file, the changes are mechanical:

- Replace `"$PASS"` with `"$PIGGY"`
- Replace `$KEY1` (and other `$KEYn`) with `create_test_template` call at start
- Replace `"$PASS" init $KEY1` with `create_test_template`
- Replace `.gpg` with `.ebox` in file existence checks
- Replace `$PASSWORD_STORE_DIR` with `$PIGGY_STORE_DIR`

Example for `t0010-generate-tests.sh`:

``` bash
#!/usr/bin/env bash

test_description='Test generate'
cd "$(dirname "$0")"
. ./setup.sh

test_expect_success 'Test "generate" command' '
    create_test_template &&
    "$PIGGY" generate cred 19 &&
    [[ $("$PIGGY" show cred | wc -m) -eq 20 ]]
'

test_expect_success 'Test replacement of first line' '
    "$PIGGY" insert -m cred2 <<<"$(printf "this is a big\\npassword\\nwith\\nmany\\nlines\\nin it bla bla")" &&
    "$PIGGY" generate -i cred2 23 &&
    [[ $("$PIGGY" show cred2) == "$(printf "%s\\npassword\\nwith\\nmany\\nlines\\nin it bla bla" "$("$PIGGY" show cred2 | head -n 1)")" ]]
'

test_done
```

Example for `t0060-rm-tests.sh`:

``` bash
#!/usr/bin/env bash

test_description='Test rm'
cd "$(dirname "$0")"
. ./setup.sh

test_expect_success 'Test "rm" command' '
    create_test_template &&
    "$PIGGY" generate cred1 43 &&
    "$PIGGY" rm cred1 &&
    [[ ! -e $PIGGY_STORE_DIR/cred1.ebox ]]
'

test_expect_success 'Test "rm" command with spaces' '
    "$PIGGY" generate "hello i have spaces" 43 &&
    [[ -e $PIGGY_STORE_DIR/"hello i have spaces".ebox ]] &&
    "$PIGGY" rm "hello i have spaces" &&
    [[ ! -e $PIGGY_STORE_DIR/"hello i have spaces".ebox ]]
'

test_expect_success 'Test "rm" of non-existent password' '
    test_must_fail "$PIGGY" rm does-not-exist
'

test_done
```

Example for `t0050-mv-tests.sh`:

``` bash
#!/usr/bin/env bash

test_description='Test mv command'
cd "$(dirname "$0")"
. ./setup.sh

INITIAL_PASSWORD="bla bla bla will we make it!!"

test_expect_success 'Basic move command' '
    create_test_template &&
    "$PIGGY" git init &&
    "$PIGGY" insert -e cred1 <<<"$INITIAL_PASSWORD" &&
    "$PIGGY" mv cred1 cred2 &&
    [[ -e $PIGGY_STORE_DIR/cred2.ebox && ! -e $PIGGY_STORE_DIR/cred1.ebox ]]
'

test_expect_success 'Directory creation' '
    "$PIGGY" mv cred2 directory/ &&
    [[ -d $PIGGY_STORE_DIR/directory && -e $PIGGY_STORE_DIR/directory/cred2.ebox ]]
'

test_expect_success 'Directory creation with file rename and empty directory removal' '
    "$PIGGY" mv directory/cred2 "new directory with spaces"/cred &&
    [[ -d $PIGGY_STORE_DIR/"new directory with spaces" && -e $PIGGY_STORE_DIR/"new directory with spaces"/cred.ebox && ! -e $PIGGY_STORE_DIR/directory ]]
'

test_expect_success 'Directory rename' '
    "$PIGGY" mv "new directory with spaces" anotherdirectory &&
    [[ -d $PIGGY_STORE_DIR/anotherdirectory && -e $PIGGY_STORE_DIR/anotherdirectory/cred.ebox && ! -e $PIGGY_STORE_DIR/"new directory with spaces" ]]
'

test_expect_success 'Directory move into new directory' '
    "$PIGGY" mv anotherdirectory "new directory with spaces"/ &&
    [[ -d $PIGGY_STORE_DIR/"new directory with spaces"/anotherdirectory && -e $PIGGY_STORE_DIR/"new directory with spaces"/anotherdirectory/cred.ebox && ! -e $PIGGY_STORE_DIR/anotherdirectory ]]
'

test_expect_success 'Multi-directory creation and multi-directory empty removal' '
    "$PIGGY" mv "new directory with spaces"/anotherdirectory/cred new1/new2/new3/new4/thecred &&
    "$PIGGY" mv new1/new2/new3/new4/thecred cred &&
    [[ ! -d $PIGGY_STORE_DIR/"new directory with spaces"/anotherdirectory && ! -d $PIGGY_STORE_DIR/new1/new2/new3/new4 && -e $PIGGY_STORE_DIR/cred.ebox ]]
'

test_expect_success 'Password made it until the end' '
    [[ $("$PIGGY" show cred) == "$INITIAL_PASSWORD" ]]
'

test_expect_success 'Git is consistent' '
    [[ -z $(git status --porcelain 2>&1) ]]
'

test_done
```

Example for `t0200-edit-tests.sh`:

``` bash
#!/usr/bin/env bash

test_description='Test edit'
cd "$(dirname "$0")"
. ./setup.sh

test_expect_success 'Test "edit" command' '
    create_test_template &&
    "$PIGGY" generate cred1 90 &&
    export FAKE_EDITOR_PASSWORD="big fat fake password" &&
    export PATH="$TEST_HOME:$PATH"
    export EDITOR="fake-editor-change-password.sh" &&
    "$PIGGY" edit cred1 &&
    [[ $("$PIGGY" show cred1) == "$FAKE_EDITOR_PASSWORD" ]]
'

test_done
```

Example for `t0400-grep.sh`:

``` bash
#!/usr/bin/env bash

test_description='Grep check'
cd "$(dirname "$0")"
. ./setup.sh

test_expect_success 'Make sure grep prints normal lines' '
    create_test_template &&
    "$PIGGY" insert -e blah1 <<<"hello" &&
    "$PIGGY" insert -e blah2 <<<"my name is" &&
    "$PIGGY" insert -e folder/blah3 <<<"I hate computers" &&
    "$PIGGY" insert -e blah4 <<<"me too!" &&
    "$PIGGY" insert -e folder/where/blah5 <<<"They are hell" &&
    results="$("$PIGGY" grep hell)" &&
    [[ $(wc -l <<<"$results") -eq 4 ]] &&
    grep -q blah5 <<<"$results" &&
    grep -q blah1 <<<"$results" &&
    grep -q "They are" <<<"$results"
'

test_expect_success 'Test passing the "-i" option to grep' '
    create_test_template &&
    "$PIGGY" insert -e blah1 <<<"I wonder..." &&
    "$PIGGY" insert -e blah2 <<<"Will it ignore" &&
    "$PIGGY" insert -e blah3 <<<"case when searching?" &&
    "$PIGGY" insert -e folder/blah4 <<<"Yes, it does. Wonderful!" &&
    results="$("$PIGGY" grep -i wonder)" &&
    [[ $(wc -l <<<"$results") -eq 4 ]] &&
    grep -q blah1 <<<"$results" &&
    grep -q blah4 <<<"$results"
'

test_done
```

Example for `t0500-find.sh`:

``` bash
#!/usr/bin/env bash

test_description='Find check'
cd "$(dirname "$0")"
. ./setup.sh

test_expect_success 'Make sure find resolves correct files' '
    create_test_template &&
    "$PIGGY" generate Something/neat 19 &&
    "$PIGGY" generate Anotherthing/okay 38 &&
    "$PIGGY" generate Fish 12 &&
    "$PIGGY" generate Fishthings 122 &&
    "$PIGGY" generate Fishies/stuff 21 &&
    "$PIGGY" generate Fishies/otherstuff 1234 &&
    [[ $("$PIGGY" find fish | sed "s/^[ \`|-]*//g;s/$(printf \\x1b)\\[[0-9;]*[a-zA-Z]//g" | tr "\\n" -) == "Search Terms: fish-Fish-Fishies-otherstuff-stuff-Fishthings-" ]]
'

test_done
```

**Step 2: Run all tests**

Run: `cd tests && for t in t0*.sh; do echo "=== $t ===" && bash "$t"; done`
Expected: All tests pass.

**Step 3: Commit**

    git add tests/t0010-generate-tests.sh tests/t0200-edit-tests.sh \
           tests/t0060-rm-tests.sh tests/t0050-mv-tests.sh \
           tests/t0400-grep.sh tests/t0500-find.sh
    git commit -m "tests: Update all remaining tests for piggy"

--------------------------------------------------------------------------------

### Task 8: Update reencryption tests

The reencryption tests are the most complex because they test key changes and
hierarchical recipients. With pivy-box templates, the concept changes: instead
of multiple GPG key IDs, we swap `.pivy-id` template files.

**Promotion criteria:** N/A

**Files:**

- Modify: `tests/t0300-reencryption.sh`

**Step 1: Rewrite t0300-reencryption.sh**

Remove all GPG key canonicalization helpers. Test reencryption by:

1.  Creating a password with one template
2.  Changing the template (overwrite `.pivy-id`)
3.  Running `piggy init` to trigger reencryption
4.  Verifying the password still decrypts

``` bash
#!/usr/bin/env bash

test_description='Reencryption consistency'
cd "$(dirname "$0")"
. ./setup.sh

INITIAL_PASSWORD="will this password live? a big question indeed..."

test_expect_success 'Setup initial template and git' '
    create_test_template &&
    "$PIGGY" git init
'

test_expect_success 'Root template encryption' '
    "$PIGGY" insert -e folder/cred1 <<<"$INITIAL_PASSWORD" &&
    [[ -f "$PIGGY_STORE_DIR/folder/cred1.ebox" ]]
'

test_expect_success 'Reencryption after template change' '
    echo "MOCK_PIVY_TEMPLATE_v2" > "$PIGGY_STORE_DIR/.pivy-id" &&
    "$PIGGY" init &&
    [[ -f "$PIGGY_STORE_DIR/folder/cred1.ebox" ]]
'

test_expect_success 'Reencryption subfolder, copy' '
    create_test_template "$PIGGY_STORE_DIR/anotherfolder" &&
    "$PIGGY" cp folder/cred1 anotherfolder/ &&
    [[ -f "$PIGGY_STORE_DIR/anotherfolder/cred1.ebox" ]]
'

test_expect_success 'Reencryption subfolder, move' '
    create_test_template "$PIGGY_STORE_DIR/anotherfolder2" &&
    "$PIGGY" mv -f anotherfolder anotherfolder2/ &&
    [[ -f "$PIGGY_STORE_DIR/anotherfolder2/anotherfolder/cred1.ebox" ]]
'

test_expect_success 'Reencryption skips links' '
    ln -s "$PIGGY_STORE_DIR/folder/cred1.ebox" "$PIGGY_STORE_DIR/folder/linked_cred.ebox" &&
    [[ -L $PIGGY_STORE_DIR/folder/linked_cred.ebox ]] &&
    git add "$PIGGY_STORE_DIR/folder/linked_cred.ebox" &&
    git commit "$PIGGY_STORE_DIR/folder/linked_cred.ebox" -m "Added linked cred" &&
    create_test_template "$PIGGY_STORE_DIR/folder" &&
    "$PIGGY" init -p folder &&
    [[ -L $PIGGY_STORE_DIR/folder/linked_cred.ebox ]]
'

test_expect_success 'Password lived through all transformations' '
    [[ $("$PIGGY" show anotherfolder2/anotherfolder/cred1) == "$INITIAL_PASSWORD" ]]
'

test_expect_success 'Git picked up all changes throughout' '
    [[ -z $(git status --porcelain 2>&1) ]]
'

test_done
```

**Step 2: Run test**

Run: `cd tests && bash t0300-reencryption.sh` Expected: All tests pass.

**Step 3: Commit**

    git add tests/t0300-reencryption.sh
    git commit -m "tests: Rewrite reencryption tests for pivy-box templates"

--------------------------------------------------------------------------------

### Task 9: Update darwin platform file

**Promotion criteria:** N/A

**Files:**

- Modify: `src/platform/darwin.sh`

**Step 1: Update darwin.sh**

Minimal changes --- the platform file mostly handles clipboard and tmpdir, which
are crypto-agnostic. Only update:

- The `sleep_argv0` string from `"password store sleep"` to `"piggy sleep"`

``` bash
local sleep_argv0="piggy sleep for user $(id -u)"
```

**Step 2: Commit**

    git add src/platform/darwin.sh
    git commit -m "Update darwin platform file for piggy branding"

--------------------------------------------------------------------------------

### Task 10: Rewrite emacs integration

Rename `password-store.el` to `piggy.el` and update all references.

**Promotion criteria:** N/A

**Files:**

- Rename: `contrib/emacs/password-store.el` → `contrib/emacs/piggy.el`
- Modify: `contrib/emacs/piggy.el`

**Step 1: Rename the file**

Run: `git mv contrib/emacs/password-store.el contrib/emacs/piggy.el`

**Step 2: Update piggy.el**

Apply these replacements throughout the file:

- `password-store` → `piggy` (in all symbol names, comments, strings)
- `"pass"` → `"piggy"` (executable name)
- `".gpg"` → `".ebox"` (file extension)
- `PASSWORD_STORE_DIR` → `PIGGY_STORE_DIR` (env var)
- `PASSWORD_STORE_CLIP_TIME` → `PIGGY_CLIP_TIME` (env var)
- `"~/.password-store"` → `"~/.local/share/piggy"` (default dir)
- Remove `(require 'auth-source-pass)` line
- Remove `auth-source-pass-filename` reference in `piggy-dir`
- Replace `auth-source-pass-parse-entry` with a local parser
- Replace `auth-source-pass-get` calls with local `piggy--run-show` calls

The `piggy-parse-entry` function replaces `auth-source-pass-parse-entry`:

``` elisp
(defun piggy-parse-entry (entry)
  "Return an alist of the data associated with ENTRY.
First line is the secret, subsequent lines are key: value pairs."
  (let* ((data (piggy--run-show entry))
         (lines (split-string (string-trim-right data) "\n"))
         (secret (car lines))
         (fields (cdr lines))
         (result (list (cons 'secret secret))))
    (dolist (line fields)
      (when (string-match "\\`\\([^:]+\\): \\(.*\\)\\'" line)
        (push (cons (match-string 1 line) (match-string 2 line)) result)))
    (nreverse result)))
```

The `piggy-get` function replaces `password-store-get`:

``` elisp
(defun piggy-get (entry &optional callback)
  "Return password for ENTRY (first line).
When CALLBACK is non-nil, call CALLBACK with the first line instead."
  (let* ((data (piggy--run-show entry))
         (secret (car (split-string data "\n"))))
    (if callback
        (funcall callback secret)
      secret)))
```

The `piggy-get-field` function:

``` elisp
(defun piggy-get-field (entry field &optional callback)
  "Return FIELD for ENTRY.
If FIELD is the symbol `secret', return the first line."
  (let ((value (if (eq field 'secret)
                   (piggy-get entry)
                 (cdr (assoc field (piggy-parse-entry entry))))))
    (if callback
        (funcall callback value)
      value)))
```

**Step 3: Update contrib/emacs/README.md**

Replace `password-store` references with `piggy`.

**Step 4: Commit**

    git add contrib/emacs/
    git commit -m "Rename password-store.el to piggy.el, remove auth-source-pass dependency"

--------------------------------------------------------------------------------

### Task 11: Update Makefile and final cleanup

**Promotion criteria:** N/A

**Files:**

- Modify: `Makefile`
- Delete: `contrib/emacs/Cask` (development dependency file for old package)
- Modify: `contrib/emacs/CHANGELOG.md` (add entry for piggy rewrite)

**Step 1: Update Makefile**

The full updated Makefile:

``` makefile
PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib
MANDIR ?= $(PREFIX)/share/man

PLATFORMFILE := src/platform/$(shell uname | cut -d _ -f 1 | tr '[:upper:]' '[:lower:]').sh

BASHCOMPDIR ?= $(PREFIX)/share/bash-completion/completions
ZSHCOMPDIR ?= $(PREFIX)/share/zsh/site-functions
FISHCOMPDIR ?= $(PREFIX)/share/fish/vendor_completions.d

ifneq ($(WITH_ALLCOMP),)
WITH_BASHCOMP := $(WITH_ALLCOMP)
WITH_ZSHCOMP := $(WITH_ALLCOMP)
WITH_FISHCOMP := $(WITH_ALLCOMP)
endif
ifeq ($(WITH_BASHCOMP),)
ifneq ($(strip $(wildcard $(BASHCOMPDIR))),)
WITH_BASHCOMP := yes
endif
endif
ifeq ($(WITH_ZSHCOMP),)
ifneq ($(strip $(wildcard $(ZSHCOMPDIR))),)
WITH_ZSHCOMP := yes
endif
endif
ifeq ($(WITH_FISHCOMP),)
ifneq ($(strip $(wildcard $(FISHCOMPDIR))),)
WITH_FISHCOMP := yes
endif
endif

all:
    @echo "piggy is a shell script, so there is nothing to do. Try \"make install\" instead."

install-common:

ifneq ($(strip $(wildcard $(PLATFORMFILE))),)
install: install-common
    @install -v -d "$(DESTDIR)$(LIBDIR)/piggy" && install -m 0644 -v "$(PLATFORMFILE)" "$(DESTDIR)$(LIBDIR)/piggy/platform.sh"
    @install -v -d "$(DESTDIR)$(BINDIR)/"
    @trap 'rm -f src/.piggy' EXIT; sed 's:.*PLATFORM_FUNCTION_FILE.*:source "$(LIBDIR)/piggy/platform.sh":' src/piggy.sh > src/.piggy && \
    install -v -d "$(DESTDIR)$(BINDIR)/" && install -m 0755 -v src/.piggy "$(DESTDIR)$(BINDIR)/piggy"
else
install: install-common
    @install -v -d "$(DESTDIR)$(BINDIR)/"
    @trap 'rm -f src/.piggy' EXIT; sed '/PLATFORM_FUNCTION_FILE/d' src/piggy.sh > src/.piggy && \
    install -v -d "$(DESTDIR)$(BINDIR)/" && install -m 0755 -v src/.piggy "$(DESTDIR)$(BINDIR)/piggy"
endif

uninstall:
    @rm -vrf \
        "$(DESTDIR)$(BINDIR)/piggy" \
        "$(DESTDIR)$(LIBDIR)/piggy"

TESTS = $(sort $(wildcard tests/t[0-9][0-9][0-9][0-9]-*.sh))

test: $(TESTS)

$(TESTS):
    @$@ $(PIGGY_TEST_OPTS)

clean:
    $(RM) -rf tests/test-results/ tests/trash\ directory.*/

.PHONY: install uninstall install-common test clean $(TESTS)
```

**Step 2: Commit**

    git add Makefile
    git commit -m "Update Makefile for piggy rename, remove extension/man installs"

--------------------------------------------------------------------------------

### Task 12: Run full test suite and fix issues

**Promotion criteria:** N/A

**Files:**

- Potentially any file if fixes are needed

**Step 1: Run all tests**

Run:
`cd tests && for t in t0*.sh; do echo "=== $t ===" && bash "$t" || true; done`

**Step 2: Fix any failures**

Debug and fix issues found in the test run. Common issues to watch for:

- `base64` command differences between macOS and Linux (the mock uses plain
  `base64`, not `openssl base64`)
- Missing `create_test_template` calls
- `.ebox` extension not consistently replaced
- `$PASS` still referenced somewhere
- `piggy init` being called by tests but cmd_init expecting different args

**Step 3: Commit fixes**

    git add -A
    git commit -m "Fix test failures from pivy rewrite"

--------------------------------------------------------------------------------

### Task 13: Manual verification with real pivy-box

This task is not automated --- it requires a real YubiKey.

**Promotion criteria:** N/A

**Step 1: Create a real store**

``` bash
mkdir -p /tmp/piggy-real-test
export PIGGY_STORE_DIR=/tmp/piggy-real-test
pivy-box tpl create -i /tmp/piggy-real-test/.pivy-id
# (use interactive editor to add your card's 9a key)
```

**Step 2: Test basic operations**

``` bash
src/piggy.sh insert -e test/cred1 <<< "my secret password"
src/piggy.sh show test/cred1
src/piggy.sh generate test/cred2 32
src/piggy.sh show test/cred2
src/piggy.sh grep secret
src/piggy.sh rm test/cred2
```

**Step 3: Document results in commit message**

    git commit --allow-empty -m "Verified piggy with real pivy-box and YubiKey

    Tested: init, insert, show, generate, grep, rm
    Card: YubiKey 5 (GUID: <your-guid>)
    pivy-box version: <version>"
