// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package peer runs a bounded AGTP discovery profile for three Go nodes.
// Nodes exchange Presence and ANS deltas over loopback TLS ports by default,
// or fixed LAN/VPC addresses under an explicit NetworkPolicy. They
// authenticate each peer action with ASB, route DHT lookups by XOR distance,
// and persist state needed for restart convergence.
//
// It is not a general AGTP wire implementation or an open Internet DHT. Peer trust,
// Manager-issued grants, certificates, and binding keys are verifier-local
// deployment configuration.
package peer
