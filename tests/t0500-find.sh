#!/usr/bin/env bash

test_description='Find check'
cd "$(dirname "$0")"
. ./setup.sh

test_expect_success 'Make sure find resolves correct files' '
	create_test_template &&
	"$PIGGY" generate Something/neat 19 &&
	"$PIGGY" generate Anotherthing/okay 38 &&
	"$PIGGY" generate Fish 12 &&
	"$PIGGY" generate Fishthings 122 &&
	"$PIGGY" generate Fishies/stuff 21 &&
	"$PIGGY" generate Fishies/otherstuff 1234 &&
	[[ $("$PIGGY" find fish | sed "s/^[ \`|-]*//g;s/$(printf \\x1b)\\[[0-9;]*[a-zA-Z]//g" | tr "\\n" -) == "Search Terms: fish-Fish-Fishies-otherstuff-stuff-Fishthings-" ]]
'

test_done
