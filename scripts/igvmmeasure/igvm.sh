#!/bin/bash
set -euo pipefail

# Optional integration build. The caller supplies an independently reviewed,
# local SVSM checkout; normal ASB builds never fetch or update this source.
if [[ -z "${IGVM_SOURCE_DIR:-}" || -z "${IGVM_SOURCE_REVISION:-}" ]]; then
    echo "Set IGVM_SOURCE_DIR to a reviewed local SVSM checkout and IGVM_SOURCE_REVISION to its full 40-character commit ID." >&2
    exit 2
fi
if [[ ! "$IGVM_SOURCE_REVISION" =~ ^[0-9a-f]{40}$ ]]; then
    echo "IGVM_SOURCE_REVISION must be a full lowercase 40-character commit ID, not a branch or tag." >&2
    exit 2
fi
if [[ "$IGVM_SOURCE_DIR" != /* || ! -d "$IGVM_SOURCE_DIR/tools/igvmmeasure" ]]; then
    echo "IGVM_SOURCE_DIR must be an absolute local SVSM path containing tools/igvmmeasure." >&2
    exit 2
fi

actual_revision=$(git -C "$IGVM_SOURCE_DIR" rev-parse --verify HEAD)
if [[ "$actual_revision" != "$IGVM_SOURCE_REVISION" ]]; then
    echo "SVSM checkout does not match IGVM_SOURCE_REVISION; no build was started." >&2
    exit 1
fi
working_changes=$(git -C "$IGVM_SOURCE_DIR" status --porcelain --untracked-files=normal --ignore-submodules=none)
if [[ -n "$working_changes" ]]; then
    echo "SVSM checkout must be clean, including its submodules; no build was started." >&2
    exit 1
fi
submodules=$(git -C "$IGVM_SOURCE_DIR" submodule status --recursive)
while IFS= read -r entry; do
    if [[ -n "$entry" && "${entry:0:1}" != " " ]]; then
        echo "SVSM submodules must be initialized at their pinned revisions; no build was started." >&2
        exit 1
    fi
done <<< "$submodules"

output_dir=${IGVM_OUTPUT_DIR:-"$(cd "$(dirname "$0")/../.." && pwd)/build"}
mkdir -p "$output_dir"
make -C "$IGVM_SOURCE_DIR" bin/igvmmeasure RELEASE=1 BUILDDIR="$output_dir"
install -m 755 "$IGVM_SOURCE_DIR/bin/igvmmeasure" "$output_dir/igvmmeasure"
echo "Binary stored in: $output_dir/igvmmeasure (SVSM $IGVM_SOURCE_REVISION)"
