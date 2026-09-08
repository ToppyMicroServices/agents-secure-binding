// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package asbbinding binds exact TaskCoord requests attributed to a Human
// Participant to an accepted ASB grant and gateway Actor session proof without
// modelling the Human as an Agent.
//
// The implemented asb.taskcoord-human-request/v1 profile provides
// HumanAssuranceGatewayAssertedForHuman. Its proof is held by the gateway Actor,
// not by the Human Participant. It does not prove Human liveness, Human-facing
// UI confirmation, legal consent, authenticated-Human evidence, or a
// Human-held-key signature over the exact request.
package asbbinding
