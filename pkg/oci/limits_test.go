// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type limitEntry struct{ name, data string }

func limitImage(t *testing.T, layers ...[]limitEntry) string {
	t.Helper()
	dir := t.TempDir()
	blobs := filepath.Join(dir, "blobs", "sha256")
	require.NoError(t, os.MkdirAll(blobs, 0o700))
	digests := make([]map[string]string, 0, len(layers))
	for i, entries := range layers {
		name := fmt.Sprintf("layer%d", i)
		f, err := os.Create(filepath.Join(blobs, name))
		require.NoError(t, err)
		gz := gzip.NewWriter(f)
		tw := tar.NewWriter(gz)
		for _, entry := range entries {
			require.NoError(t, tw.WriteHeader(&tar.Header{Name: entry.name, Size: int64(len(entry.data)), Mode: 0o700}))
			_, err := tw.Write([]byte(entry.data))
			require.NoError(t, err)
		}
		require.NoError(t, tw.Close())
		require.NoError(t, gz.Close())
		require.NoError(t, f.Close())
		digests = append(digests, map[string]string{"digest": "sha256:" + name})
	}
	manifest, err := json.Marshal(map[string]any{"layers": digests})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(blobs, "manifest"), manifest, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.json"), []byte(`{"manifests":[{"digest":"sha256:manifest"}]}`), 0o600))
	return dir
}

func TestExtractionBudgets(t *testing.T) {
	for _, kind := range []string{"algorithm", "dataset"} {
		t.Run(kind, func(t *testing.T) {
			extract := func(ctx context.Context, dir, dest string, limits extractionLimits) error {
				if kind == "algorithm" {
					_, _, err := extractAlgorithm(ctx, slog.Default(), dir, dest, "bin", limits)
					return err
				}
				_, err := extractDataset(ctx, dir, dest, limits)
				return err
			}
			selected := "main"
			if kind == "dataset" {
				selected = "data.csv"
			}
			limits := extractionLimits{expandedBytes: 8192, fileBytes: 4096, metadataBytes: 4096, entries: 10}
			t.Run("selected file", func(t *testing.T) {
				dir := limitImage(t, []limitEntry{{selected, strings.Repeat("x", 1025)}})
				small := limits
				small.fileBytes = 1024
				dest := t.TempDir()
				require.ErrorIs(t, extract(context.Background(), dir, dest, small), errExtractionLimit)
				_, err := os.Stat(filepath.Join(dest, selected))
				require.True(t, os.IsNotExist(err))
			})
			t.Run("skipped member expansion", func(t *testing.T) {
				dir := limitImage(t, []limitEntry{{"ignored.bin", strings.Repeat("x", 3000)}, {selected, "x"}})
				small := limits
				small.expandedBytes = 2048
				require.ErrorIs(t, extract(context.Background(), dir, t.TempDir(), small), errExtractionLimit)
			})
			t.Run("aggregate layers and no successful fallback", func(t *testing.T) {
				dir := limitImage(t, []limitEntry{{"ignored.bin", "x"}}, []limitEntry{{selected, "x"}})
				small := limits
				small.expandedBytes = 3000 // Each layer is 2048 bytes independently.
				require.ErrorIs(t, extract(context.Background(), dir, t.TempDir(), small), errExtractionLimit)
			})
			t.Run("aggregate entry count includes skipped members", func(t *testing.T) {
				dir := limitImage(t, []limitEntry{{"ignored.bin", "x"}}, []limitEntry{{selected, "x"}, {"skip.bin", "x"}})
				small := limits
				small.entries = 2
				require.ErrorIs(t, extract(context.Background(), dir, t.TempDir(), small), errExtractionLimit)
			})
			t.Run("trailing gzip output", func(t *testing.T) {
				dir := limitImage(t, []limitEntry{{selected, "x"}})
				layer := filepath.Join(dir, "blobs", "sha256", "layer0")
				compressed, err := os.ReadFile(layer)
				require.NoError(t, err)
				gz, err := gzip.NewReader(bytes.NewReader(compressed))
				require.NoError(t, err)
				data, err := io.ReadAll(gz)
				require.NoError(t, err)
				require.NoError(t, gz.Close())
				replaceLimitLayer(t, layer, append(data, bytes.Repeat([]byte{0}, 5000)...))
				small := limits
				small.expandedBytes = 4096
				require.ErrorIs(t, extract(context.Background(), dir, t.TempDir(), small), errExtractionLimit)
			})
			t.Run("sparse logical output across entries", func(t *testing.T) {
				dir := limitImage(t, nil)
				replaceLimitLayer(t, filepath.Join(dir, "blobs", "sha256", "layer0"), sparseLimitTar(t, selected))
				small := limits
				small.expandedBytes = 10000
				small.fileBytes = 8192
				require.ErrorIs(t, extract(context.Background(), dir, t.TempDir(), small), errExtractionLimit)
			})
			t.Run("metadata", func(t *testing.T) {
				dir := limitImage(t, []limitEntry{{selected, "x"}})
				small := limits
				small.metadataBytes = 8
				require.ErrorIs(t, extract(context.Background(), dir, t.TempDir(), small), errExtractionLimit)
			})
			t.Run("manifest metadata", func(t *testing.T) {
				dir := limitImage(t, []limitEntry{{selected, "x"}})
				manifest := filepath.Join(dir, "blobs", "sha256", "manifest")
				data, err := os.ReadFile(manifest)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(manifest, append(bytes.Repeat([]byte{' '}, 100), data...), 0o600))
				small := limits
				small.metadataBytes = 64
				require.ErrorIs(t, extract(context.Background(), dir, t.TempDir(), small), errExtractionLimit)
			})
			t.Run("cancellation", func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				dir := limitImage(t, []limitEntry{{selected, "x"}})
				dest := t.TempDir()
				require.ErrorIs(t, extract(ctx, dir, dest, limits), context.Canceled)
				files, err := os.ReadDir(dest)
				require.NoError(t, err)
				require.Empty(t, files)
			})
			t.Run("corrupt layer after a usable layer", func(t *testing.T) {
				dir := limitImage(t, []limitEntry{{"ignored.bin", "x"}}, []limitEntry{{selected, "x"}})
				require.NoError(t, os.WriteFile(filepath.Join(dir, "blobs", "sha256", "layer0"), []byte("invalid gzip"), 0o600))
				require.Error(t, extract(context.Background(), dir, t.TempDir(), limits))
			})
		})
	}
}

func replaceLimitLayer(t *testing.T, filename string, data []byte) {
	t.Helper()
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, err := gz.Write(data)
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	require.NoError(t, os.WriteFile(filename, compressed.Bytes(), 0o600))
}

func sparseLimitTar(t *testing.T, name string) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for i := 0; i < 2; i++ {
		var records string
		for _, record := range []string{"GNU.sparse.size=7000\n", "GNU.sparse.numblocks=1\n", "GNU.sparse.map=0,1\n"} {
			length := len(record) + 3
			for len(fmt.Sprintf("%d %s", length, record)) != length {
				length = len(fmt.Sprintf("%d %s", length, record))
			}
			records += fmt.Sprintf("%d %s", length, record)
		}
		offset := raw.Len()
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: "pax", Size: int64(len(records)), Mode: 0o600, Format: tar.FormatUSTAR}))
		_, err := tw.Write([]byte(records))
		require.NoError(t, err)
		require.NoError(t, tw.Flush())
		// archive/tar's writer intentionally omits GNU sparse PAX keys.
		// Turn this ordinary header into the independently encoded PAX header.
		header := raw.Bytes()[offset : offset+512]
		header[156] = tar.TypeXHeader
		copy(header[148:156], "        ")
		checksum := 0
		for _, b := range header {
			checksum += int(b)
		}
		copy(header[148:156], fmt.Sprintf("%06o\x00 ", checksum))
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Size: 1, Mode: 0o700, Format: tar.FormatUSTAR}))
		_, err = tw.Write([]byte("x"))
		require.NoError(t, err)
		require.NoError(t, tw.Flush())
	}
	require.NoError(t, tw.Close())
	return raw.Bytes()
}

func TestBudgetReaderChecksCancellationDuringRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	b := &extractionBudget{ctx: ctx, remaining: 10}
	r := &budgetReader{source: strings.NewReader("content"), budget: b}
	buf := make([]byte, 1)
	_, err := r.Read(buf)
	require.NoError(t, err)
	cancel()
	_, err = r.Read(buf)
	require.ErrorIs(t, err, context.Canceled)
}
