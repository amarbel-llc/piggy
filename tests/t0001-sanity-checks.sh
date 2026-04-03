#!/usr/bin/env bash

test_description='Sanity checks'
cd "$(dirname "$0")"
. ./setup.sh

test_expect_success 'Make sure we can run piggy' '
	"$PIGGY" --help | grep "piggy"
'

test_expect_success 'Make sure we can initialize our test store' '
	create_test_template &&
	[[ -e "$PIGGY_STORE_DIR/.pivy-id" ]]
'

test_done
