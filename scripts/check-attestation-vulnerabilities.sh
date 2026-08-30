#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
	echo "usage: $0 <snp|tdx>" >&2
	exit 2
fi

module=$1
case "$module" in
	snp|tdx) ;;
	*)
		echo "unsupported attestation module: $module" >&2
		exit 2
		;;
esac

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
module_dir="$script_dir/../modules/attestation/$module"

dependencies=$(
	cd "$module_dir"
	GOWORK=off go list -deps -test ./...
)

if printf '%s\n' "$dependencies" |
	grep -Eq '^golang\.org/x/crypto/openpgp($|/)'; then
	echo "vulnerability gate blocked: $module imports unmaintained x/crypto/openpgp" >&2
	exit 1
fi

(
	cd "$module_dir"
	GOWORK=off go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 -scan=package ./...
)
