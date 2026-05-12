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
  pivy-box stream decrypt <"$1" || exit $?
}
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

    find_piggy_ids "$passfile_dir"
    echo "$passfile_display: reencrypting"
    pivy-box stream decrypt <"$passfile" | "${PIGGY_IDS_PATH:-piggy-ids}" encrypt "$PIGGY_IDS" >"$passfile_temp" &&
      mv "$passfile_temp" "$passfile" || rm -f "$passfile_temp"
  done < <(find "$1" -path '*/.git' -prune -o -iname '*.ebox' -print0)
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

cmd_version() {
  cat <<-_EOF
	=================================
	=    piggy: PIV password store  =
	=                               =
	=            v0.1.0             =
	=================================
	_EOF
}

cmd_usage() {
  cmd_version
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
	    $PROGRAM_TOP help
	        Show this text.
	    $PROGRAM_TOP version
	        Show version information.
	_EOF
}

cmd_init() {
  # piggy 2.x: writes a piggy-owned `piggy-ids` text file (RFC 0003)
  # instead of pivy's binary `.pivy-id`. The recipient is identified
  # by a markl ID of format `pivy_ecdh_p256_pub` carrying the
  # `piggy-recipient-v1` purpose tag — see madder RFC 0002.
  #
  # Modes:
  #   -k <markl-id>   declarative; user supplies the recipient (any
  #                   shape that piggy-ids canonicalize accepts).
  #   no -k           auto-detect; shells to `piggy-ids detect-pubkey`
  #                   to read slot 9D of the attached PIV card. -g is
  #                   forwarded as `--guid` for multi-card setups.
  local opts id_path="" key="" guid=""
  opts="$($GETOPT -o p:k:g: -l path:,key:,guid: -n "$PROGRAM" -- "$@")"
  local err=$?
  eval set -- "$opts"
  while true; do case $1 in
    -p | --path)
      id_path="$2"
      shift 2
      ;;
    -k | --key)
      key="$2"
      shift 2
      ;;
    -g | --guid)
      guid="$2"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    esac done

  [[ $err -ne 0 ]] && die "Usage: $PROGRAM_PASS $COMMAND [-p subfolder] [-k <markl-id> | -g <guid>]"
  [[ -n $key && -n $guid ]] && die "Error: -k and -g are mutually exclusive (-g only applies to auto-detect)."
  [[ -n $id_path ]] && check_sneaky_paths "$id_path"
  [[ -n $id_path && ! -d $PREFIX/$id_path && -e $PREFIX/$id_path ]] && die "Error: $PREFIX/$id_path exists but is not a directory."

  local piggy_ids="$PREFIX/$id_path/piggy-ids"
  local tpl_dir="$PREFIX/$id_path"
  set_git "$piggy_ids"

  mkdir -v -p "$tpl_dir"

  if [[ -z $key ]]; then
    local detect_args=()
    [[ -n $guid ]] && detect_args+=(--guid "$guid")
    key="$("${PIGGY_IDS_PATH:-piggy-ids}" detect-pubkey "${detect_args[@]}")" ||
      die "Error: piggy-ids detect-pubkey failed; pass -k <markl-id> if no PIV card is attached."
  fi

  # Validate the markl-id has the piggy 2.x recipient shape — bare
  # `pivy_ecdh_p256_pub-...` or purpose-tagged
  # `piggy-recipient-v1@pivy_ecdh_p256_pub-...`. RFC 0003 permits
  # both as input; the next `piggy pass recipients` rewrite will
  # canonicalise to the purpose-tagged form via the Rust
  # piggy-markl codec (which re-checksums under the combined HRP).
  # Canonicalising here in bash would need re-checksumming and
  # bash can't do blech32, so we write the user's input verbatim.
  if [[ $key != pivy_ecdh_p256_pub-* &&
        $key != piggy-recipient-v1@pivy_ecdh_p256_pub-* ]]; then
    die "Error: -k value must be a markl ID with format=pivy_ecdh_p256_pub (got: ${key%%-*}...)."
  fi

  # Atomic write: build the file, then mv into place.
  local tmp="${piggy_ids}.tmp.$$"
  {
    echo "# piggy-ids — piggy 2.x recipient template"
    echo "# format: piggy-recipient-v1@pivy_ecdh_p256_pub-<blech32>  # optional comment"
    echo "$key"
  } >"$tmp"
  mv "$tmp" "$piggy_ids" || {
    rm -f "$tmp"
    die "Error: failed to write $piggy_ids."
  }

  echo "Password store initialized${id_path:+ ($id_path)}"
  git_add_file "$piggy_ids" "Set piggy recipients${id_path:+ ($id_path)}."

  # Re-encrypt any pre-existing entries against the new recipient
  # set. Fresh init is a no-op (no `.ebox` files in the tree); for
  # re-init over an existing store, reencrypt_path now drives the
  # Rust `piggy-ids encrypt` path (#75 phase 5).
  reencrypt_path "$PREFIX/$id_path"
  git_add_file "$PREFIX/$id_path" "Reencrypt password store using new piggy recipients${id_path:+ ($id_path)}."
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

cmd_find() {
  [[ $# -eq 0 ]] && die "Usage: $PROGRAM_PASS $COMMAND pass-names..."
  IFS="," eval 'echo "Search Terms: $*"'
  local terms="*$(printf '%s*|*' "$@")"
  tree -N -C -l --noreport -P "${terms%|*}" --prune --matchdirs --ignore-case "$PREFIX" 3>&- | tail -n +2 | sed -E 's/\.ebox(\x1B\[[0-9]+m)?( ->|$)/\1\2/g'
}

cmd_grep() {
  [[ $# -lt 1 ]] && die "Usage: $PROGRAM_PASS $COMMAND [GREPOPTIONS] search-string"
  local passfile grepresults
  while read -r -d "" passfile; do
    grepresults="$(piggy_decrypt "$passfile" | grep --color=always "$@")"
    [[ $? -ne 0 ]] && continue
    passfile="${passfile%.ebox}"
    passfile="${passfile#$PREFIX/}"
    local passfile_dir="${passfile%/*}/"
    [[ $passfile_dir == "${passfile}/" ]] && passfile_dir=""
    passfile="${passfile##*/}"
    printf "\e[94m%s\e[1m%s\e[0m:\n" "$passfile_dir" "$passfile"
    echo "$grepresults"
  done < <(find -L "$PREFIX" -path '*/.git' -prune -o -iname '*.ebox' -print0)
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

cmd_delete() {
  local opts recursive="" force=0
  opts="$($GETOPT -o rf -l recursive,force -n "$PROGRAM" -- "$@")"
  local err=$?
  eval set -- "$opts"
  while true; do case $1 in
    -r | --recursive)
      recursive="-r"
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
  [[ $# -ne 1 ]] && die "Usage: $PROGRAM_PASS $COMMAND [--recursive,-r] [--force,-f] pass-name"
  local path="$1"
  check_sneaky_paths "$path"

  local passdir="$PREFIX/${path%/}"
  local passfile="$PREFIX/$path.ebox"
  [[ -f $passfile && -d $passdir && $path == */ || ! -f $passfile ]] && passfile="${passdir%/}/"
  [[ -e $passfile ]] || die "Error: $path is not in the password store."
  set_git "$passfile"

  [[ $force -eq 1 ]] || yesno "Are you sure you would like to delete $path?"

  rm $recursive -f -v "$passfile"
  set_git "$passfile"
  if [[ -n $INNER_GIT_DIR && ! -e $passfile ]]; then
    git -C "$INNER_GIT_DIR" rm -qr "$passfile"
    set_git "$passfile"
    git_commit "Remove $path from store."
  fi
  rmdir -p "${passfile%/*}" 2>/dev/null
}

cmd_copy_move() {
  local opts move=1 force=0
  [[ $1 == "copy" ]] && move=0
  shift
  opts="$($GETOPT -o f -l force -n "$PROGRAM" -- "$@")"
  local err=$?
  eval set -- "$opts"
  while true; do case $1 in
    -f | --force)
      force=1
      shift
      ;;
    --)
      shift
      break
      ;;
    esac done
  [[ $# -ne 2 ]] && die "Usage: $PROGRAM_PASS $COMMAND [--force,-f] old-path new-path"
  check_sneaky_paths "$@"
  local old_path="$PREFIX/${1%/}"
  local old_dir="$old_path"
  local new_path="$PREFIX/$2"

  if ! [[ -f $old_path.ebox && -d $old_path && $1 == */ || ! -f $old_path.ebox ]]; then
    old_dir="${old_path%/*}"
    old_path="${old_path}.ebox"
  fi
  echo "$old_path"
  [[ -e $old_path ]] || die "Error: $1 is not in the password store."

  mkdir -p -v "${new_path%/*}"
  [[ -d $old_path || -d $new_path || $new_path == */ ]] || new_path="${new_path}.ebox"

  local interactive="-i"
  [[ ! -t 0 || $force -eq 1 ]] && interactive="-f"

  set_git "$new_path"
  if [[ $move -eq 1 ]]; then
    mv $interactive -v "$old_path" "$new_path" || exit 1
    [[ -e $new_path ]] && reencrypt_path "$new_path"

    set_git "$new_path"
    if [[ -n $INNER_GIT_DIR && ! -e $old_path ]]; then
      git -C "$INNER_GIT_DIR" rm -qr "$old_path" 2>/dev/null
      set_git "$new_path"
      git_add_file "$new_path" "Rename ${1} to ${2}."
    fi
    set_git "$old_path"
    if [[ -n $INNER_GIT_DIR && ! -e $old_path ]]; then
      git -C "$INNER_GIT_DIR" rm -qr "$old_path" 2>/dev/null
      set_git "$old_path"
      [[ -n $(git -C "$INNER_GIT_DIR" status --porcelain "$old_path") ]] && git_commit "Remove ${1}."
    fi
    rmdir -p "$old_dir" 2>/dev/null
  else
    cp $interactive -r -v "$old_path" "$new_path" || exit 1
    [[ -e $new_path ]] && reencrypt_path "$new_path"
    git_add_file "$new_path" "Copy ${1} to ${2}."
  fi
}

cmd_git() {
  set_git "$PREFIX/"
  if [[ $1 == "init" ]]; then
    INNER_GIT_DIR="$PREFIX"
    git -C "$INNER_GIT_DIR" "$@" || exit 1
    git_add_file "$PREFIX" "Add current contents of password store."

    echo '*.ebox diff=ebox' >"$PREFIX/.gitattributes"
    git_add_file .gitattributes "Configure git repository for ebox file diff."
    git -C "$INNER_GIT_DIR" config --local diff.ebox.binary true
    git -C "$INNER_GIT_DIR" config --local diff.ebox.textconv "pivy-box stream decrypt"
  elif [[ -n $INNER_GIT_DIR ]]; then
    tmpdir nowarn #Defines $SECURE_TMPDIR. We don't warn, because at most, this only copies encrypted files.
    export TMPDIR="$SECURE_TMPDIR"
    git -C "$INNER_GIT_DIR" "$@"
  else
    die "Error: the password store is not a git repository. Try \"$PROGRAM_PASS git init\"."
  fi
}

cmd_pass_recipients() {
  local sub="${1:-}"
  case "$sub" in
  list)
    shift
    cmd_pass_recipients_list "$@"
    ;;
  add)
    shift
    cmd_pass_recipients_add "$@"
    ;;
  remove)
    shift
    cmd_pass_recipients_remove "$@"
    ;;
  sync)
    shift
    cmd_pass_recipients_sync "$@"
    ;;
  "" | -h | --help)
    cat <<-_EOF
		Usage:
		    $PROGRAM_PASS recipients list [-p subfolder]
		        Print recipients in the relevant piggy-ids, one per line.
		    $PROGRAM_PASS recipients add <markl-id>... [-p subfolder]
		        Append recipients to piggy-ids and re-encrypt.
		    $PROGRAM_PASS recipients remove <markl-id>... [-p subfolder]
		        Remove recipients (matched by full markl ID) and re-encrypt.
		    $PROGRAM_PASS recipients sync <file> [-p subfolder]
		        Replace piggy-ids with <file>'s contents (idempotent).
		_EOF
    [[ $sub = "" ]] && exit 1 || exit 0
    ;;
  *)
    die "Error: unknown subcommand: $PROGRAM_PASS recipients $sub"
    ;;
  esac
}

cmd_pass_recipients_list() {
  local subfolder=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
    -p)
      subfolder="$2"
      shift 2
      ;;
    *)
      die "Error: unexpected argument to recipients list: $1"
      ;;
    esac
  done
  find_piggy_ids "$subfolder"
  cat "$PIGGY_IDS"
}

cmd_pass_recipients_add() {
  local subfolder=""
  local -a ids=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
    -p)
      subfolder="$2"
      shift 2
      ;;
    *)
      ids+=("$1")
      shift
      ;;
    esac
  done
  [[ ${#ids[@]} -gt 0 ]] || die "Usage: $PROGRAM_PASS recipients add <markl-id>... [-p subfolder]"
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

cmd_pass_recipients_remove() {
  local subfolder=""
  local -a ids=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
    -p)
      subfolder="$2"
      shift 2
      ;;
    *)
      ids+=("$1")
      shift
      ;;
    esac
  done
  [[ ${#ids[@]} -gt 0 ]] || die "Usage: $PROGRAM_PASS recipients remove <markl-id>... [-p subfolder]"
  find_piggy_ids "$subfolder"
  set_git "$PIGGY_IDS"

  # Canonicalise so user-supplied IDs (which may be bare-format) match
  # the on-disk form.
  "${PIGGY_IDS_PATH:-piggy-ids}" canonicalize "$PIGGY_IDS" || die "Error: existing piggy-ids invalid."

  local tmp="${PIGGY_IDS}.tmp.$$"
  awk -v target_blob="$(printf '%s\n' "${ids[@]}")" '
    BEGIN {
      n = split(target_blob, arr, "\n")
      for (i = 1; i <= n; i++) if (arr[i] != "") targets[arr[i]] = 1
    }
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { print; next }
    {
      id = $0
      sub(/[[:space:]]+#.*$/, "", id)
      sub(/^[[:space:]]+/, "", id)
      sub(/[[:space:]]+$/, "", id)
      if (!(id in targets)) print
    }
  ' "$PIGGY_IDS" >"$tmp"

  if cmp -s "$PIGGY_IDS" "$tmp"; then
    rm -f "$tmp"
    echo "No matching recipients in $PIGGY_IDS."
    return 0
  fi
  mv "$tmp" "$PIGGY_IDS"

  local id_dir="${PIGGY_IDS%/piggy-ids}"
  git_add_file "$PIGGY_IDS" "Remove recipient(s) from piggy-ids."
  reencrypt_path "$id_dir"
  git_add_file "$id_dir" "Reencrypt password store after removing recipient(s)."
}

cmd_pass_recipients_sync() {
  local subfolder=""
  local file=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
    -p)
      subfolder="$2"
      shift 2
      ;;
    *)
      [[ -z $file ]] || die "Error: only one <file> argument permitted."
      file="$1"
      shift
      ;;
    esac
  done
  [[ -n $file ]] || die "Usage: $PROGRAM_PASS recipients sync <file> [-p subfolder]"
  [[ -f $file ]] || die "Error: file not found: $file"

  find_piggy_ids "$subfolder"
  set_git "$PIGGY_IDS"

  "${PIGGY_IDS_PATH:-piggy-ids}" validate "$file" || die "Error: $file failed validation."

  # Idempotency: if no diff, no commit, no reencryption.
  if "${PIGGY_IDS_PATH:-piggy-ids}" diff "$PIGGY_IDS" "$file" >/dev/null 2>&1; then
    return 0
  fi

  cp "$file" "$PIGGY_IDS" || die "Error: failed to copy $file → $PIGGY_IDS."
  "${PIGGY_IDS_PATH:-piggy-ids}" canonicalize "$PIGGY_IDS" || die "Error: post-copy canonicalize failed."

  local id_dir="${PIGGY_IDS%/piggy-ids}"
  git_add_file "$PIGGY_IDS" "Sync recipients in piggy-ids."
  reencrypt_path "$id_dir"
  git_add_file "$id_dir" "Reencrypt password store after syncing recipients."
}

#
# END subcommand functions
#

PROGRAM="${0##*/}"
COMMAND="$1"

case "$1" in
init)
  shift
  cmd_init "$@"
  ;;
help | --help)
  shift
  cmd_usage "$@"
  ;;
version | --version)
  shift
  cmd_version "$@"
  ;;
show | ls | list)
  shift
  cmd_show "$@"
  ;;
find | search)
  shift
  cmd_find "$@"
  ;;
grep)
  shift
  cmd_grep "$@"
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
delete | rm | remove)
  shift
  cmd_delete "$@"
  ;;
rename | mv)
  shift
  cmd_copy_move "move" "$@"
  ;;
copy | cp)
  shift
  cmd_copy_move "copy" "$@"
  ;;
git)
  shift
  cmd_git "$@"
  ;;
recipients)
  shift
  cmd_pass_recipients "$@"
  ;;
*)
  COMMAND="show"
  cmd_show "$@"
  ;;
esac
exit 0
