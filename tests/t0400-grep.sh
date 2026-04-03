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
