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
