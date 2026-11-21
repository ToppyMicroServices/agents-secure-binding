// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package protectedchange

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// This is the trusted application-store API after successful ASB verification.
// The HTTP recovery recipe additionally exercises real mTLS and fresh proofs.
func ExampleSQLiteChangeStore() {
	directory, err := os.MkdirTemp("", "asb-change-recipe-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(directory)
	ctx := context.Background()
	path := filepath.Join(directory, "changes.sqlite")
	store, err := OpenSQLiteChangeStore(ctx, path)
	if err != nil {
		panic(err)
	}
	change := e2eChange(true)
	accepted := recipeIdentity(change) // Synthetic stand-in for Profile.Verify output.
	if err := store.Apply(ctx, change, accepted); err != nil {
		panic(err)
	}
	if err := store.Close(); err != nil {
		panic(err)
	}
	reopened, err := OpenSQLiteChangeStore(ctx, path)
	if err != nil {
		panic(err)
	}
	defer reopened.Close()
	found, err := reopened.Outcome(ctx, change, accepted)
	if err != nil {
		panic(err)
	}
	fmt.Println("retained local commit:", found)
	// Output: retained local commit: true
}
