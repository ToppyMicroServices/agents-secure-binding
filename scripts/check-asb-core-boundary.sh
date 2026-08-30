#!/bin/sh
# Copyright (c) 2026 ToppyMicroServices OÜ
# SPDX-License-Identifier: Apache-2.0

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

dependencies=$(GOWORK=off go list -deps -test \
	./pkg/atls/... \
	./pkg/clients \
	./pkg/clients/http \
	./pkg/clients/grpc \
	./pkg/agtp/... \
	./pkg/tls)

forbidden_dependencies=$(
	printf '%s\n' "$dependencies" | awk '
		/^github\.com\/google\/go-sev-guest(\/|$)/ ||
		/^github\.com\/google\/go-tdx-guest(\/|$)/ ||
		/^github\.com\/google\/go-tpm-tools(\/|$)/ ||
		/^github\.com\/google\/go-tpm(\/|$)/ ||
		/^github\.com\/virtee\/sev-snp-measure-go(\/|$)/ ||
		/^github\.com\/veraison\/corim(\/|$)/ ||
		/\/pkg\/attestation(\/|$)/ ||
		/\/integrations\/cocos(\/|$)/ ||
		/\/modules\/attestation\/(snp|tdx)(\/|$)/ {
			print
		}
	'
)

if [ -n "$forbidden_dependencies" ]; then
	printf '%s\n' "ASB core imports concrete attestation dependencies:" >&2
	printf '%s\n' "$forbidden_dependencies" >&2
	exit 1
fi

printf '%s\n' "ASB core dependency boundary passed"
