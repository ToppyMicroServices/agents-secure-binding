// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package asbbinding turns an accepted ASB grant and session proof into one
// authorityquorum approval. Durable records use decision-scoped tags; raw JWTs,
// signatures, keys, stable principal identifiers, and TLS exporter values stay
// outside the core quorum record.
package asbbinding
