// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"context"
	"errors"
	"io"
	"os"
)

var errExtractionLimit = errors.New("OCI extraction limit exceeded")

type extractionLimits struct {
	expandedBytes int64
	fileBytes     int64
	metadataBytes int64
	entries       int
}

var defaultExtractionLimits = extractionLimits{
	expandedBytes: 1 << 30,
	fileBytes:     1 << 30,
	metadataBytes: 4 << 20,
	entries:       10_000,
}

type extractionBudget struct {
	ctx              context.Context
	remaining        int64
	contentRemaining int64
	entries          int
	limits           extractionLimits
}

func newExtractionBudget(ctx context.Context, limits extractionLimits) *extractionBudget {
	return &extractionBudget{ctx: ctx, remaining: limits.expandedBytes, contentRemaining: limits.expandedBytes, limits: limits}
}

func (b *extractionBudget) entry(size int64) error {
	if err := b.ctx.Err(); err != nil {
		return err
	}
	if b.entries >= b.limits.entries || size < 0 || size > b.limits.fileBytes || size > b.contentRemaining {
		return errExtractionLimit
	}
	// Sparse tar members may synthesize zeros without reading gzip bytes.
	// Bound their logical sizes independently of the decompressed tar stream.
	b.contentRemaining -= size
	b.entries++
	return nil
}

// budgetReader surrounds the gzip reader, so tar.Next's implicit skipping,
// padding, extension headers, and trailing decompressed data consume the same
// budget as selected file contents. One budget is shared by every layer.
type budgetReader struct {
	source io.Reader
	budget *extractionBudget
}

func (r *budgetReader) Read(p []byte) (int, error) {
	if err := r.budget.ctx.Err(); err != nil {
		return 0, err
	}
	if r.budget.remaining == 0 {
		var extra [1]byte
		n, err := r.source.Read(extra[:])
		if n != 0 {
			return 0, errExtractionLimit
		}
		return 0, err
	}
	if int64(len(p)) > r.budget.remaining {
		p = p[:int(r.budget.remaining)]
	}
	n, err := r.source.Read(p)
	r.budget.remaining -= int64(n)
	return n, err
}

func readMetadata(ctx context.Context, filename string, limit int64) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := &extractionBudget{ctx: ctx, remaining: limit}
	return io.ReadAll(&budgetReader{source: f, budget: b})
}
