#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

sh ./scripts/check-attestation-v2-boundary.sh
sh ./scripts/check-asb-core-boundary.sh

if GOWORK=off go mod edit -json | grep -Eq '"Replace"[[:space:]]*:[[:space:]]*\['; then
	echo "release blocked: root go.mod contains a replacement" >&2
	exit 1
fi

concrete_modules='github.com/ToppyMicroServices/agents-secure-binding/modules/attestation/'
cocos_module='github.com/ToppyMicroServices/agents-secure-binding/integrations/cocos'

if grep -F "$concrete_modules" go.mod >/dev/null || grep -F "$cocos_module" go.mod >/dev/null; then
	echo "release blocked: root go.mod depends on a concrete attestation module" >&2
	exit 1
fi

GOWORK=off go mod tidy -diff
GOWORK=off go mod verify
module_graph=$(GOWORK=off go list -m all)
if printf '%s\n' "$module_graph" | grep -F "$concrete_modules" >/dev/null || \
	printf '%s\n' "$module_graph" | grep -F "$cocos_module" >/dev/null; then
	echo "release blocked: root module graph contains a concrete attestation module" >&2
	exit 1
fi

GOWORK=off go list ./... >/dev/null
GOWORK=off go test ./...
"$repo_root/scripts/check-attestation-vulnerabilities.sh" root
