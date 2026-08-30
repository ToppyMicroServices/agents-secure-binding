#!/bin/sh

set -eu

module_path=$(awk '$1 == "module" { print $2; exit }' go.mod)
if [ "$module_path" != "github.com/ToppyMicroServices/agents-secure-binding/v2" ]; then
	echo "release blocked: unsupported root module identity $module_path" >&2
	exit 1
fi

exec sh ./scripts/check-attestation-v2-release.sh
