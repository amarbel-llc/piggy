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
