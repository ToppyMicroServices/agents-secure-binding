// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package peer runs the bounded single-host AGTP discovery product profile.
// Three Go nodes exchange Presence and ANS deltas over real loopback TLS ports,
// authenticate each peer action with ASB, route DHT lookups by XOR distance,
// and persist state needed for restart convergence.
//
// It is not a general AGTP wire implementation or a cross-host DHT. Peer trust,
// Manager-issued grants, certificates, and binding keys are verifier-local
// deployment configuration.
package peer
