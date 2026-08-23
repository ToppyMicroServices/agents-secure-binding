// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package authorityquorum records independently authenticated authority
// approvals and atomically consumes a threshold of approvals for one exact
// operation.
//
// The package distributes approval authority. It does not store secret shares,
// fragments, reconstruction keys, or plaintext released by an application.
// An external release adapter must redeem ConsumptionID idempotently and may
// start a first effect only from a fresh direct ConsumeQuorum result.
// Store, Service.Approve, and the decoders are trusted internal boundaries;
// network approval input must pass through asbbinding.Profile.Submit.
package authorityquorum
