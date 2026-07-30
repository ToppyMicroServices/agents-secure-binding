#!/bin/sh
set -eu

base_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if command -v proverif >/dev/null 2>&1; then
  run_proverif() {
    proverif "$@"
  }
elif command -v opam >/dev/null 2>&1; then
  run_proverif() {
    opam exec -- proverif "$@"
  }
else
  echo "ProVerif is required (tested with version 2.05)." >&2
  exit 127
fi

output=$(run_proverif "${base_dir}/binding_acceptance.pv" 2>&1) || {
  printf '%s\n' "$output" >&2
  exit 1
}
printf '%s\n' "$output"

results=$(printf '%s\n' "$output" | grep '^RESULT ' || true)
if [ -z "$results" ]; then
  echo "No ProVerif RESULT line was produced." >&2
  exit 1
fi
if printf '%s\n' "$results" | grep -Eq \
  ' is false\.$| cannot be proved\.$'
then
  echo "A ProVerif query was not proved." >&2
  exit 1
fi
