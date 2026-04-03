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
