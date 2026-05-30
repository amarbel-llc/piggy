#!/usr/bin/env bash

# piggy: a password store using pivy-box and ebox templates
# Based on pass by Jason A. Donenfeld <Jason@zx2c4.com>
# Licensed under the GPLv2+. Please see COPYING for more information.

umask "${PIGGY_UMASK:-077}"
set -o pipefail

PREFIX="${PIGGY_STORE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/piggy}"
X_SELECTION="${PIGGY_X_SELECTION:-clipboard}"
CLIP_TIME="${PIGGY_CLIP_TIME:-45}"
GENERATED_LENGTH="${PIGGY_GENERATED_LENGTH:-25}"
CHARACTER_SET="${PIGGY_CHARACTER_SET:-[:punct:][:alnum:]}"
CHARACTER_SET_NO_SYMBOLS="${PIGGY_CHARACTER_SET_NO_SYMBOLS:-[:alnum:]}"

PROGRAM_TOP="piggy"
PROGRAM_PASS="piggy pass"

unset GIT_DIR GIT_WORK_TREE GIT_NAMESPACE GIT_INDEX_FILE GIT_INDEX_VERSION GIT_OBJECT_DIRECTORY GIT_COMMON_DIR
export GIT_CEILING_DIRECTORIES="$PREFIX/.."

#
# BEGIN helper functions
#

set_git() {
  INNER_GIT_DIR="${1%/*}"
  while [[ ! -d $INNER_GIT_DIR && ${INNER_GIT_DIR%/*}/ == "${PREFIX%/}/"* ]]; do
    INNER_GIT_DIR="${INNER_GIT_DIR%/*}"
  done
  [[ $(git -C "$INNER_GIT_DIR" rev-parse --is-inside-work-tree 2>/dev/null) == true ]] || INNER_GIT_DIR=""
}
git_add_file() {
  [[ -n $INNER_GIT_DIR ]] || return
  git -C "$INNER_GIT_DIR" add "$1" || return
  [[ -n $(git -C "$INNER_GIT_DIR" status --porcelain "$1") ]] || return
  git_commit "$2"
}
git_commit() {
  local sign=""
  [[ -n $INNER_GIT_DIR ]] || return
  [[ $(git -C "$INNER_GIT_DIR" config --bool --get piggy.signcommits) == "true" ]] && sign="-S"
  git -C "$INNER_GIT_DIR" commit $sign -m "$1"
}
yesno() {
  [[ -t 0 ]] || return 0
  local response
  read -r -p "$1 [y/N] " response
  [[ $response == [yY] ]] || exit 1
}
die() {
  echo "$@" >&2
  exit 1
}
find_piggy_ids() {
  # Walk up from $PREFIX/$1 looking for piggy-ids; sets $PIGGY_IDS.
  # Replaces the legacy set_pivy_template walker (#75 phase 5).
  local current="$PREFIX/$1"
  while [[ $current != "$PREFIX" && ! -f $current/piggy-ids ]]; do
    current="${current%/*}"
  done
  PIGGY_IDS="$current/piggy-ids"

  if [[ ! -f $PIGGY_IDS ]]; then
    cat >&2 <<-_EOF
		Error: You must run:
		    $PROGRAM_PASS init -k <markl-id>
		before you may use the password store.

		_EOF
    cmd_usage
    exit 1
  fi
}
piggy_encrypt() {
  # Usage: echo "secret" | piggy_encrypt <output-file> <piggy-ids-path>
  # Shells to the piggy-ids Rust helper (PIGGY_IDS_PATH baked in by
  # flake.nix's makeWrapper; falls back to a `piggy-ids` on PATH for
  # bats-driven tests where the mock symlink takes over).
  local outfile="$1" piggy_ids="$2"
  "${PIGGY_IDS_PATH:-piggy-ids}" encrypt "$piggy_ids" >"$outfile" || die "Encryption aborted."
}
piggy_decrypt() {
  # Usage: piggy_decrypt <input-file>
  # Route the decrypt at piggy's own agent (PIGGY_AUTH_SOCK) when set, so
  # it doesn't go through an ssh-agent-mux that may not advertise the
  # ecdh@joyent.com extension. Falls back to the ambient SSH_AUTH_SOCK.
  # See #123 (and ssh-agent-mux#10 for the mux-side capability drop).
  if [[ -n ${PIGGY_AUTH_SOCK:-} ]]; then
    SSH_AUTH_SOCK="$PIGGY_AUTH_SOCK" pivy-box stream decrypt <"$1" || exit $?
  else
    pivy-box stream decrypt <"$1" || exit $?
  fi
}
reencrypt_path() {
  # Delegates to the Rust handler. The sole remaining bash caller
  # (cmd_init) keeps its existing invocation unchanged; only the body
  # of this function has moved to Rust.
  #
  # $PIGGY_BIN is set by the Rust dispatcher's exec_bash before
  # exec-ing piggy.sh, so this shim always has an absolute path to
  # the same binary that invoked us.
  "${PIGGY_BIN:?reencrypt_path: PIGGY_BIN not set (called outside the piggy dispatcher?)}" \
    internal-reencrypt-path "$1"
}
check_sneaky_paths() {
  local path
  for path in "$@"; do
    [[ $path =~ /\.\.$ || $path =~ ^\.\./ || $path =~ /\.\./ || $path =~ ^\.\.$ ]] && die "Error: You've attempted to pass a sneaky path to piggy. Go home."
  done
}

#
# END helper functions
#

#
# BEGIN platform definable
#

clip() {
  if [[ -n $WAYLAND_DISPLAY ]] && command -v wl-copy &>/dev/null; then
    local copy_cmd=(wl-copy)
    local paste_cmd=(wl-paste -n)
    if [[ $X_SELECTION == primary ]]; then
      copy_cmd+=(--primary)
      paste_cmd+=(--primary)
    fi
    local display_name="$WAYLAND_DISPLAY"
  elif [[ -n $DISPLAY ]] && command -v xclip &>/dev/null; then
    local copy_cmd=(xclip -selection "$X_SELECTION")
    local paste_cmd=(xclip -o -selection "$X_SELECTION")
    local display_name="$DISPLAY"
  else
    die "Error: No X11 or Wayland display and clipper detected"
  fi
  local sleep_argv0="piggy sleep on display $display_name"

  # This base64 business is because bash cannot store binary data in a shell
  # variable. Specifically, it cannot store nulls nor (non-trivally) store
  # trailing new lines.
  pkill -f "^$sleep_argv0" 2>/dev/null && sleep 0.5
  local before="$("${paste_cmd[@]}" 2>/dev/null | $BASE64)"
  echo -n "$1" | "${copy_cmd[@]}" || die "Error: Could not copy data to the clipboard"
  (
    (exec -a "$sleep_argv0" bash <<<"trap 'kill %1' TERM; sleep '$CLIP_TIME' & wait")
    local now="$("${paste_cmd[@]}" | $BASE64)"
    [[ $now != $(echo -n "$1" | $BASE64) ]] && before="$now"

    # It might be nice to programatically check to see if klipper exists,
    # as well as checking for other common clipboard managers. But for now,
    # this works fine -- if qdbus isn't there or if klipper isn't running,
    # this essentially becomes a no-op.
    #
    # Clipboard managers frequently write their history out in plaintext,
    # so we axe it here:
    qdbus org.kde.klipper /klipper org.kde.klipper.klipper.clearClipboardHistory &>/dev/null

    echo "$before" | $BASE64 -d | "${copy_cmd[@]}"
  ) >/dev/null 2>&1 &
  disown
  echo "Copied $2 to clipboard. Will clear in $CLIP_TIME seconds."
}

qrcode() {
  if [[ -n $DISPLAY || -n $WAYLAND_DISPLAY ]]; then
    if type feh >/dev/null 2>&1; then
      echo -n "$1" | qrencode --size 10 -o - | feh -x --title "piggy: $2" -g +200+200 -
      return
    elif type gm >/dev/null 2>&1; then
      echo -n "$1" | qrencode --size 10 -o - | gm display -title "piggy: $2" -geometry +200+200 -
      return
    elif type display >/dev/null 2>&1; then
      echo -n "$1" | qrencode --size 10 -o - | display -title "piggy: $2" -geometry +200+200 -
      return
    fi
  fi
  echo -n "$1" | qrencode -t utf8
}

tmpdir() {
  [[ -n $SECURE_TMPDIR ]] && return
  local warn=1
  [[ $1 == "nowarn" ]] && warn=0
  local template="$PROGRAM.XXXXXXXXXXXXX"
  if [[ -d /dev/shm && -w /dev/shm && -x /dev/shm ]]; then
    SECURE_TMPDIR="$(mktemp -d "/dev/shm/$template")"
    remove_tmpfile() {
      rm -rf "$SECURE_TMPDIR"
    }
    trap remove_tmpfile EXIT
  else
    [[ $warn -eq 1 ]] && yesno "$(
      cat <<-_EOF
		Your system does not have /dev/shm, which means that it may
		be difficult to entirely erase the temporary non-encrypted
		password file after editing.

		Are you sure you would like to continue?
		_EOF
    )"
    SECURE_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/$template")"
    shred_tmpfile() {
      find "$SECURE_TMPDIR" -type f -exec $SHRED {} +
      rm -rf "$SECURE_TMPDIR"
    }
    trap shred_tmpfile EXIT
  fi

}
GETOPT="getopt"
SHRED="shred -f -z"
BASE64="base64"

source "$(dirname "$0")/platform/$(uname | cut -d _ -f 1 | tr '[:upper:]' '[:lower:]').sh" 2>/dev/null # PLATFORM_FUNCTION_FILE

#
# END platform definable
#

#
# BEGIN subcommand functions
#

# Self-identification line for the `help` banner (cmd_usage). The `version`
# subcommand itself is a native Rust handler (crates/piggy/src/version.rs,
# piggy #96); this helper survives only to head the usage text.
# PIGGY_VERSION/PIGGY_COMMIT come from flake.nix's makeWrapper (PIGGY_VERSION
# also via the rust dispatcher's set_piggy_version on the dev `cargo build`
# path); each falls back when bypassed.
piggy_version_line() {
  printf 'piggy %s+%s\n' "${PIGGY_VERSION:-dev}" "${PIGGY_COMMIT:-unknown}"
}

cmd_usage() {
  piggy_version_line
  echo
  cat <<-_EOF
	Usage:
	    $PROGRAM_PASS init [-p subfolder] [-k <markl-id> | -g <guid>]
	        Initialize new password storage with a piggy-recipient-v1
	        markl ID. Writes <store>/[subfolder/]piggy-ids.
	        With no -k, auto-detects from the attached PIV card's slot 9D.
	        Use -g <guid> to disambiguate when multiple cards are attached.
	    $PROGRAM_PASS recipients <list|add|remove|sync> [-p subfolder] ...
	        Manage recipients in piggy-ids. See "$PROGRAM_PASS recipients --help".
	    $PROGRAM_PASS ls [subfolder]
	        List passwords.
	    $PROGRAM_PASS find pass-names...
	    	List passwords that match pass-names.
	    $PROGRAM_PASS show [--clip[=line-number],-c[line-number]] pass-name
	        Show existing password and optionally put it on the clipboard.
	        If put on the clipboard, it will be cleared in $CLIP_TIME seconds.
	    $PROGRAM_PASS grep [GREPOPTIONS] search-string
	        Search for password files containing search-string when decrypted.
	    $PROGRAM_PASS insert [--echo,-e | --multiline,-m] [--force,-f] pass-name
	        Insert new password. Optionally, echo the password back to the console
	        during entry. Or, optionally, the entry may be multiline. Prompt before
	        overwriting existing password unless forced.
	    $PROGRAM_PASS edit pass-name
	        Insert a new password or edit an existing password using ${EDITOR:-vi}.
	    $PROGRAM_PASS generate [--no-symbols,-n] [--clip,-c] [--in-place,-i | --force,-f] pass-name [pass-length]
	        Generate a new password of pass-length (or $GENERATED_LENGTH if unspecified) with optionally no symbols.
	        Optionally put it on the clipboard and clear board after $CLIP_TIME seconds.
	        Prompt before overwriting existing password unless forced.
	        Optionally replace only the first line of an existing file with a new password.
	    $PROGRAM_PASS rm [--recursive,-r] [--force,-f] pass-name
	        Remove existing password or directory, optionally forcefully.
	    $PROGRAM_PASS mv [--force,-f] old-path new-path
	        Renames or moves old-path to new-path, optionally forcefully, selectively reencrypting.
	    $PROGRAM_PASS cp [--force,-f] old-path new-path
	        Copies old-path to new-path, optionally forcefully, selectively reencrypting.
	    $PROGRAM_PASS git git-command-args...
	        If the password store is a git repository, execute a git command
	        specified by git-command-args.
	    $PROGRAM_TOP list [--format human|ndjson]
	        Enumerate every populated PIV slot across all attached cards
	        (9A/9C/9D/9E + retired 82-95) with their markl IDs. See
	        piggy(1) for the per-slot purpose mapping.
	    $PROGRAM_TOP help
	        Show this text.
	    $PROGRAM_TOP version
	        Show version information.
	_EOF
}

cmd_show() {
  local opts selected_line clip=0 qrcode=0
  opts="$($GETOPT -o q::c:: -l qrcode::,clip:: -n "$PROGRAM" -- "$@")"
  local err=$?
  eval set -- "$opts"
  while true; do case $1 in
    -q | --qrcode)
      qrcode=1
      selected_line="${2:-1}"
      shift 2
      ;;
    -c | --clip)
      clip=1
      selected_line="${2:-1}"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    esac done

  [[ $err -ne 0 || ($qrcode -eq 1 && $clip -eq 1) ]] && die "Usage: $PROGRAM_PASS $COMMAND [--clip[=line-number],-c[line-number]] [--qrcode[=line-number],-q[line-number]] [pass-name]"

  local pass
  local path="$1"
  local passfile="$PREFIX/$path.ebox"
  check_sneaky_paths "$path"
  if [[ -f $passfile ]]; then
    if [[ $clip -eq 0 && $qrcode -eq 0 ]]; then
      pass="$(piggy_decrypt "$passfile" | $BASE64)" || exit $?
      echo "$pass" | $BASE64 -d
    else
      [[ $selected_line =~ ^[0-9]+$ ]] || die "Clip location '$selected_line' is not a number."
      pass="$(piggy_decrypt "$passfile" | tail -n +${selected_line} | head -n 1)" || exit $?
      [[ -n $pass ]] || die "There is no password to put on the clipboard at line ${selected_line}."
      if [[ $clip -eq 1 ]]; then
        clip "$pass" "$path"
      elif [[ $qrcode -eq 1 ]]; then
        qrcode "$pass" "$path"
      fi
    fi
  elif [[ -d $PREFIX/$path ]]; then
    if [[ -z $path ]]; then
      echo "Password Store"
    else
      echo "${path%\/}"
    fi
    tree -N -C -l --noreport "$PREFIX/$path" 3>&- | tail -n +2 | sed -E 's/\.ebox(\x1B\[[0-9]+m)?( ->|$)/\1\2/g'
  elif [[ -z $path ]]; then
    die 'Error: password store is empty. Try "piggy pass init".'
  else
    die "Error: $path is not in the password store."
  fi
}

cmd_insert() {
  local opts multiline=0 noecho=1 force=0
  opts="$($GETOPT -o mef -l multiline,echo,force -n "$PROGRAM" -- "$@")"
  local err=$?
  eval set -- "$opts"
  while true; do case $1 in
    -m | --multiline)
      multiline=1
      shift
      ;;
    -e | --echo)
      noecho=0
      shift
      ;;
    -f | --force)
      force=1
      shift
      ;;
    --)
      shift
      break
      ;;
    esac done

  [[ $err -ne 0 || ($multiline -eq 1 && $noecho -eq 0) || $# -ne 1 ]] && die "Usage: $PROGRAM_PASS $COMMAND [--echo,-e | --multiline,-m] [--force,-f] pass-name"
  local path="${1%/}"
  local passfile="$PREFIX/$path.ebox"
  check_sneaky_paths "$path"
  set_git "$passfile"

  [[ $force -eq 0 && -e $passfile ]] && yesno "An entry already exists for $path. Overwrite it?"

  mkdir -p -v "$PREFIX/$(dirname -- "$path")"
  find_piggy_ids "$(dirname -- "$path")"

  if [[ $multiline -eq 1 ]]; then
    echo "Enter contents of $path and press Ctrl+D when finished:"
    echo
    piggy_encrypt "$passfile" "$PIGGY_IDS"
  elif [[ $noecho -eq 1 ]]; then
    local password password_again
    while true; do
      read -r -p "Enter password for $path: " -s password || exit 1
      echo
      read -r -p "Retype password for $path: " -s password_again || exit 1
      echo
      if [[ $password == "$password_again" ]]; then
        echo "$password" | piggy_encrypt "$passfile" "$PIGGY_IDS"
        break
      else
        die "Error: the entered passwords do not match."
      fi
    done
  else
    local password
    read -r -p "Enter password for $path: " -e password
    echo "$password" | piggy_encrypt "$passfile" "$PIGGY_IDS"
  fi
  git_add_file "$passfile" "Add given password for $path to store."
}

cmd_edit() {
  [[ $# -ne 1 ]] && die "Usage: $PROGRAM_PASS $COMMAND pass-name"

  local path="${1%/}"
  check_sneaky_paths "$path"
  mkdir -p -v "$PREFIX/$(dirname -- "$path")"
  find_piggy_ids "$(dirname -- "$path")"
  local passfile="$PREFIX/$path.ebox"
  set_git "$passfile"

  tmpdir #Defines $SECURE_TMPDIR
  local tmp_file="$(mktemp -u "$SECURE_TMPDIR/XXXXXX")-${path//\//-}.txt"

  local action="Add"
  if [[ -f $passfile ]]; then
    piggy_decrypt "$passfile" >"$tmp_file" || exit 1
    action="Edit"
  fi
  ${EDITOR:-vi} "$tmp_file"
  [[ -f $tmp_file ]] || die "New password not saved."
  piggy_decrypt "$passfile" 2>/dev/null | diff - "$tmp_file" &>/dev/null && die "Password unchanged."
  while ! cat "$tmp_file" | piggy_encrypt "$passfile" "$PIGGY_IDS"; do
    yesno "Encryption failed. Would you like to try again?"
  done
  git_add_file "$passfile" "$action password for $path using ${EDITOR:-vi}."
}

cmd_generate() {
  local opts qrcode=0 clip=0 force=0 characters="$CHARACTER_SET" inplace=0 pass
  opts="$($GETOPT -o nqcif -l no-symbols,qrcode,clip,in-place,force -n "$PROGRAM" -- "$@")"
  local err=$?
  eval set -- "$opts"
  while true; do case $1 in
    -n | --no-symbols)
      characters="$CHARACTER_SET_NO_SYMBOLS"
      shift
      ;;
    -q | --qrcode)
      qrcode=1
      shift
      ;;
    -c | --clip)
      clip=1
      shift
      ;;
    -f | --force)
      force=1
      shift
      ;;
    -i | --in-place)
      inplace=1
      shift
      ;;
    --)
      shift
      break
      ;;
    esac done

  [[ $err -ne 0 || ($# -ne 2 && $# -ne 1) || ($force -eq 1 && $inplace -eq 1) || ($qrcode -eq 1 && $clip -eq 1) ]] && die "Usage: $PROGRAM_PASS $COMMAND [--no-symbols,-n] [--clip,-c] [--qrcode,-q] [--in-place,-i | --force,-f] pass-name [pass-length]"
  local path="$1"
  local length="${2:-$GENERATED_LENGTH}"
  check_sneaky_paths "$path"
  [[ $length =~ ^[0-9]+$ ]] || die "Error: pass-length \"$length\" must be a number."
  [[ $length -gt 0 ]] || die "Error: pass-length must be greater than zero."
  mkdir -p -v "$PREFIX/$(dirname -- "$path")"
  find_piggy_ids "$(dirname -- "$path")"
  local passfile="$PREFIX/$path.ebox"
  set_git "$passfile"

  [[ $inplace -eq 0 && $force -eq 0 && -e $passfile ]] && yesno "An entry already exists for $path. Overwrite it?"

  read -r -n $length pass < <(LC_ALL=C tr -dc "$characters" </dev/urandom)
  [[ ${#pass} -eq $length ]] || die "Could not generate password from /dev/urandom."
  if [[ $inplace -eq 0 ]]; then
    echo "$pass" | piggy_encrypt "$passfile" "$PIGGY_IDS"
  else
    local passfile_temp="${passfile}.tmp.${RANDOM}.${RANDOM}.${RANDOM}.${RANDOM}.--"
    if {
      echo "$pass"
      piggy_decrypt "$passfile" | tail -n +2
    } | piggy_encrypt "$passfile_temp" "$PIGGY_IDS"; then
      mv "$passfile_temp" "$passfile"
    else
      rm -f "$passfile_temp"
      die "Could not reencrypt new password."
    fi
  fi
  local verb="Add"
  [[ $inplace -eq 1 ]] && verb="Replace"
  git_add_file "$passfile" "$verb generated password for ${path}."

  if [[ $clip -eq 1 ]]; then
    clip "$pass" "$path"
  elif [[ $qrcode -eq 1 ]]; then
    qrcode "$pass" "$path"
  else
    printf "\e[1mThe generated password for \e[4m%s\e[24m is:\e[0m\n\e[1m\e[93m%s\e[0m\n" "$path" "$pass"
  fi
}

#
# END subcommand functions
#

PROGRAM="${0##*/}"
COMMAND="$1"

case "$1" in
help | --help)
  shift
  cmd_usage "$@"
  ;;
show | ls | list)
  shift
  cmd_show "$@"
  ;;
insert | add)
  shift
  cmd_insert "$@"
  ;;
edit)
  shift
  cmd_edit "$@"
  ;;
generate)
  shift
  cmd_generate "$@"
  ;;
*)
  COMMAND="show"
  cmd_show "$@"
  ;;
esac
exit 0
