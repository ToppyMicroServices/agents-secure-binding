#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
	echo "usage: $0 <root|snp|tdx|cocos>" >&2
	exit 2
fi

target=$1
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

case "$target" in
	root)
		module_dir="$script_dir/.."
		;;
	snp|tdx)
		module_dir="$script_dir/../modules/attestation/$target"
		;;
	cocos)
		module_dir="$script_dir/../integrations/cocos"
		;;
	*)
		echo "unsupported attestation target: $target" >&2
		exit 2
		;;
esac

dependencies=$(
	cd "$module_dir"
	GOWORK=off go list -deps -test ./...
)

if printf '%s\n' "$dependencies" |
	grep -Eq '^golang\.org/x/crypto/openpgp($|/)'; then
	echo "vulnerability gate blocked: $target imports unmaintained x/crypto/openpgp" >&2
	exit 1
fi

(
	cd "$module_dir"
	GOWORK=off go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 -scan=package ./...
)
