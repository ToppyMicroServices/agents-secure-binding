// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package operationjournal

// ValidateReservation applies the Store input contract without changing
// durable state. Store adapters should call it before sending data to a remote
// backend.
func ValidateReservation(request Reservation) error {
	return validateReservation(request)
}

// ValidateAcceptanceReservation applies the atomic replay-plus-operation input
// contract without changing durable state.
func ValidateAcceptanceReservation(request AcceptanceReservation) error {
	return validateAcceptanceReservation(request)
}

// ValidateFinalization applies the terminal-state input contract without
// changing durable state.
func ValidateFinalization(final Finalization) error {
	return validateFinalization(final)
}
