// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import "strings"

// quoteReceiptPath formats a literal argument for the documented shell:
// PowerShell on Windows, or a POSIX shell on macOS/Linux. Go %q is not shell
// quoting: it doubles Windows backslashes and leaves variable expansion active.
func quoteReceiptPath(path, goos string) string {
	if goos == goosWindows {
		// PowerShell recognizes typographic single quotes as delimiters too.
		escape := strings.NewReplacer("'", "''", "‘", "‘‘", "’", "’’", "‚", "‚‚", "‛", "‛‛")
		return "'" + escape.Replace(path) + "'"
	}
	return "'" + strings.ReplaceAll(path, "'", "'\"'\"'") + "'"
}
