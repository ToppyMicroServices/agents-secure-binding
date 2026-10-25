// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBoundedResourceDigest(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.txt"), []byte("world"), 0o600))
	_, err := digestData(context.Background(), dir, 9, 10)
	require.ErrorIs(t, err, ErrResourceLimit)
	_, err = digestData(context.Background(), dir, 1024, 1)
	require.ErrorIs(t, err, ErrResourceLimit)
	// The uncompressed bytes fit, but ZIP headers/output do not.
	_, err = digestData(context.Background(), dir, 10, 10)
	require.ErrorIs(t, err, ErrResourceLimit)
	got, _, err := DigestContext(context.Background(), dir)
	require.NoError(t, err)
	want, err := ZipDirectoryToMemory(dir)
	require.NoError(t, err)
	require.Equal(t, want, got)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = DigestContext(ctx, dir)
	require.ErrorIs(t, err, context.Canceled)
}

func TestReadFileBounded(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "data")
	require.NoError(t, os.WriteFile(filename, []byte("12345"), 0o600))
	_, err := ReadFileBounded(context.Background(), filename, 4)
	require.ErrorIs(t, err, ErrResourceLimit)
	data, err := ReadFileBounded(context.Background(), filename, 5)
	require.NoError(t, err)
	require.Equal(t, []byte("12345"), data)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = ReadFileBounded(ctx, filename, 5)
	require.ErrorIs(t, err, context.Canceled)
}

func TestBoundedResourceDigestSkipsDanglingSymlinkLikeLegacyZip(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "output.txt"), []byte("normal output"), 0o600))
	require.NoError(t, os.Symlink("missing.txt", filepath.Join(dir, "dangling-link")))
	want, err := ZipDirectoryToMemory(dir)
	require.NoError(t, err)
	got, _, err := DigestContext(context.Background(), dir)
	require.NoError(t, err)
	require.Equal(t, want, got)
	// Skipped entries still consume the traversal budget.
	_, err = digestData(context.Background(), dir, 1024, 1)
	require.ErrorIs(t, err, ErrResourceLimit)
}
