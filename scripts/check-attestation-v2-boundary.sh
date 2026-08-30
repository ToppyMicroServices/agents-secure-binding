#!/bin/sh

set -eu

expected_module="github.com/ToppyMicroServices/agents-secure-binding/v2"
actual_module=$(awk '$1 == "module" { print $2; exit }' go.mod)

if [ "$actual_module" != "$expected_module" ]; then
	echo "v2 boundary check failed: root module is $actual_module, want $expected_module" >&2
	exit 1
fi

old_module="github.com/thinksyncs/agents-secure-binding"
if git grep -n -F "$old_module" -- '*.go' '*.proto' go.mod >/dev/null; then
	echo "v2 boundary check failed: Go or protobuf sources still refer to $old_module" >&2
	exit 1
fi
