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
