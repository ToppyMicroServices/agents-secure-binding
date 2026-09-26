// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package s3product

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
)

// Run exposes local administration and the ASB listener. It provides no command
// to bypass ASB authorization, reset a live journal, or repeat uncertain reads.
func Run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: asb-s3 serve|init-store|status|inspect|backup|restore [flags]")
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var directory, config, output, input, hash *string
	var operation, digest *string
	switch command {
	case "serve":
		config = flags.String("config", "", "private product configuration")
	case "init-store", "status":
		directory = flags.String("directory", "", "private journal directory")
	case "inspect":
		directory = flags.String("directory", "", "private journal directory")
		operation = flags.String("operation", "", "exact operation ID")
		digest = flags.String("request-digest", "", "exact request digest")
	case "backup":
		directory = flags.String("directory", "", "private journal directory")
		output = flags.String("output", "", "new backup file in a private directory")
	case "restore":
		directory = flags.String("directory", "", "new journal directory")
		input = flags.String("input", "", "sealed backup")
		hash = flags.String("sha256", "", "expected backup SHA-256")
	default:
		return errors.New("unknown S3 product command")
	}
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return errors.New("invalid S3 product command arguments")
	}
	if command == "serve" {
		return Serve(ctx, *config)
	}
	var store *lp.SQLiteStore
	var err error
	switch command {
	case "init-store":
		store, err = lp.CreateSQLiteStore(ctx, *directory)
	case "restore":
		store, err = lp.RestoreSQLiteStore(ctx, *input, *directory, *hash)
	default:
		store, err = lp.OpenSQLiteStore(ctx, *directory)
	}
	if err != nil {
		return err
	}
	defer store.Close()
	var result any
	if command == "backup" {
		result, err = store.Backup(ctx, *output)
	} else if command == "inspect" {
		result, err = store.Lookup(ctx, *operation, *digest)
	} else {
		result, err = store.Status(ctx)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}
