// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package operationjournal records the durable state of an accepted operation.
//
// A reservation is keyed by an application-defined operation ID and the
// SHA-256 digest of the exact request. Reusing an ID for different request
// bytes is rejected. Exact retries return the current record without changing
// it, which lets a caller recover a terminal or indeterminate decision after a
// response is lost.
//
// ResultStore can commit a SUCCEEDED record and an opaque AEAD envelope in the
// same transaction. The journal still receives no plaintext result or sealing
// key. The application must authenticate lookup, open the envelope, and verify
// its exact operation, request, outcome, media type, version, and length.
//
// FileStore is a single-process reference adapter. ReserveAcceptance commits a
// replay key and an operation reservation in one versioned state-file
// replacement, then syncs both the file and its directory. Package production
// provides a TLS Redis/Valkey adapter for shared replicas. No journal can make
// an external model call, tool call, or physical effect part of its storage
// transaction. A storage error can have an unknown commit outcome, so callers
// recover the exact operation before any retry.
package operationjournal
