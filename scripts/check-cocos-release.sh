#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
module_dir="$repo_root/integrations/cocos"
cd "$module_dir"

expected_module="github.com/ToppyMicroServices/agents-secure-binding/integrations/cocos"
actual_module=$(awk '$1 == "module" { print $2; exit }' go.mod)
if [ "$actual_module" != "$expected_module" ]; then
	echo "Cocos release blocked: module is $actual_module, want $expected_module" >&2
	exit 1
fi

if GOWORK=off go mod edit -json | grep -Eq '"Replace"[[:space:]]*:[[:space:]]*\['; then
	echo "Cocos release blocked: integrations/cocos/go.mod contains a replacement" >&2
	exit 1
fi

root_version=$(awk '$1 == "github.com/ToppyMicroServices/agents-secure-binding/v2" { print $2; exit }' go.mod)
if ! printf '%s\n' "$root_version" | grep -Eq '^v2\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
	echo "Cocos release blocked: ASB root must use a published v2 version" >&2
	exit 1
fi

for module in snp tdx; do
	module_path="github.com/ToppyMicroServices/agents-secure-binding/modules/attestation/$module"
	module_version=$(awk -v path="$module_path" '$1 == path { print $2; exit }' go.mod)
	if ! printf '%s\n' "$module_version" | grep -Eq '^v0\.[0-9]+\.[0-9]+$'; then
		echo "Cocos release blocked: $module_path must use a tagged v0.x version" >&2
		exit 1
	fi
done

GOWORK=off go mod tidy -diff
GOWORK=off go mod verify
GOWORK=off go list ./... >/dev/null
GOWORK=off go test ./...
