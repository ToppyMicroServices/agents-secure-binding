// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/s3product"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := s3product.Run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
