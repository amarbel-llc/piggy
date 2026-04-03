#!/usr/bin/env bash

test_description='Reencryption consistency'
cd "$(dirname "$0")"
. ./setup.sh

INITIAL_PASSWORD="will this password live? a big question indeed..."

test_expect_success 'Setup initial template and git' '
	create_test_template && "$PIGGY" git init
'

test_expect_success 'Insert a credential' '
	"$PIGGY" insert -e folder/cred1 <<<"$INITIAL_PASSWORD" &&
	[[ -f "$PIGGY_STORE_DIR/folder/cred1.ebox" ]]
'

test_expect_success 'Reencryption after template change preserves content' '
	create_test_template &&
	"$PIGGY" show folder/cred1 | grep -q "$INITIAL_PASSWORD"
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
	[[ -L $PIGGY_STORE_DIR/folder/linked_cred.ebox ]]
'

test_expect_success 'Password lived through all transformations' '
	[[ $("$PIGGY" show anotherfolder2/anotherfolder/cred1) == "$INITIAL_PASSWORD" ]]
'

test_expect_success 'Git picked up all changes throughout' '
	[[ -z $(git status --porcelain 2>&1) ]]
'

test_done
