// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/crypto/sha3"
)

var ErrResourceLimit = errors.New("resource size or entry limit exceeded")

const maxResourceBytes int64 = 1 << 30

// ReadFileBounded checks both the file size and bytes actually read. The latter
// also covers a file that grows between stat and read.
func ReadFileBounded(ctx context.Context, filename string, limit int64) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, ErrResourceLimit
	}
	remaining := limit
	data, err := io.ReadAll(&resourceReader{ctx: ctx, source: f, remaining: &remaining})
	if err != nil {
		return nil, err
	}
	return data, nil
}

// DigestContext uses the existing deterministic ZIP representation for a
// directory, with limits on input bytes, entry count, and buffered ZIP output.
func DigestContext(ctx context.Context, filename string) ([]byte, []byte, error) {
	data, err := digestData(ctx, filename, maxResourceBytes, maxZipEntries)
	if err != nil {
		return nil, nil, err
	}
	sum := sha3.Sum256(data)
	return data, sum[:], nil
}

func digestData(ctx context.Context, filename string, limit int64, maxEntries int) ([]byte, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return ReadFileBounded(ctx, filename, limit)
	}
	var files []string
	var entries int
	remaining := limit
	err = filepath.WalkDir(filename, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if name == filename {
			return nil
		}
		if entries >= maxEntries {
			return ErrResourceLimit
		}
		entries++
		if entry.IsDir() {
			return nil
		}
		fileInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if !fileInfo.Mode().IsRegular() {
			return nil
		}
		if fileInfo.Size() > remaining {
			return ErrResourceLimit
		}
		remaining -= fileInfo.Size()
		files = append(files, name)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(&resourceWriter{buffer: buf, remaining: limit})
	remaining = limit
	for _, name := range files {
		if err := addResourceZipFile(ctx, zw, filename, name, &remaining); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func addResourceZipFile(ctx context.Context, zw *zip.Writer, root, name string, remaining *int64) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > *remaining {
		return ErrResourceLimit
	}
	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name, err = filepath.Rel(root, name)
	if err != nil {
		return err
	}
	header.Name = filepath.ToSlash(header.Name)
	header.Method = zip.Deflate
	header.Modified = time.Unix(0, 0)
	entry, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = io.Copy(entry, &resourceReader{ctx: ctx, source: f, remaining: remaining})
	return err
}

type resourceReader struct {
	ctx       context.Context
	source    io.Reader
	remaining *int64
}

func (r *resourceReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if *r.remaining == 0 {
		var extra [1]byte
		n, err := r.source.Read(extra[:])
		if n != 0 {
			return 0, ErrResourceLimit
		}
		return 0, err
	}
	if int64(len(p)) > *r.remaining {
		p = p[:int(*r.remaining)]
	}
	n, err := r.source.Read(p)
	*r.remaining -= int64(n)
	return n, err
}

type resourceWriter struct {
	buffer    *bytes.Buffer
	remaining int64
}

func (w *resourceWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, ErrResourceLimit
	}
	n, err := w.buffer.Write(p)
	w.remaining -= int64(n)
	return n, err
}
