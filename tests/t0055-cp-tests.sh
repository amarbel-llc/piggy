#!/usr/bin/env bash

test_description='Test cp command'
cd "$(dirname "$0")"
. ./setup.sh

INITIAL_PASSWORD="bla bla bla will we make it!!"

test_expect_success 'Basic copy command' '
	create_test_template &&
	"$PIGGY" git init &&
	"$PIGGY" insert -e cred1 <<<"$INITIAL_PASSWORD" &&
	"$PIGGY" cp cred1 cred2 &&
	[[ -e $PIGGY_STORE_DIR/cred1.ebox && -e $PIGGY_STORE_DIR/cred2.ebox ]]
'

test_expect_success 'Copy preserves original content' '
	[[ $("$PIGGY" show cred1) == "$INITIAL_PASSWORD" ]]
'

test_expect_success 'Copy destination has same content' '
	[[ $("$PIGGY" show cred2) == "$INITIAL_PASSWORD" ]]
'

test_expect_success 'Copy into directory' '
	"$PIGGY" cp cred1 directory/ &&
	[[ -d $PIGGY_STORE_DIR/directory && -e $PIGGY_STORE_DIR/directory/cred1.ebox ]]
'

test_expect_success 'Copy with rename into new directory' '
	"$PIGGY" cp cred1 "new directory"/newcred &&
	[[ -d $PIGGY_STORE_DIR/"new directory" && -e $PIGGY_STORE_DIR/"new directory"/newcred.ebox ]]
'

test_expect_success 'Copy directory recursively' '
	"$PIGGY" cp directory targetdir &&
	[[ -e $PIGGY_STORE_DIR/targetdir/cred1.ebox && -e $PIGGY_STORE_DIR/directory/cred1.ebox ]]
'

test_expect_success 'Force overwrite existing' '
	"$PIGGY" cp -f cred1 cred2 &&
	[[ $("$PIGGY" show cred2) == "$INITIAL_PASSWORD" ]]
'

test_expect_success 'Original still intact after all copies' '
	[[ $("$PIGGY" show cred1) == "$INITIAL_PASSWORD" ]]
'

test_expect_success 'Git is consistent' '
	[[ -z $(git status --porcelain 2>&1) ]]
'

test_done
