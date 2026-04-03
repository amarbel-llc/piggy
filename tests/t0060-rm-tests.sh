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
