// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/safearchive"
)

var errUnsafeZipPath = errors.New("unsafe zip entry path")

var errZipExpansionLimit = errors.New("zip extraction limit exceeded")

const (
	maxZipExpandedBytes  int64 = 1 << 30
	maxZipEntries              = 10_000
	maxZipDirectoryBytes       = 64 << 20
)

func ZipDirectoryToMemory(sourceDir string) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := writeZip(sourceDir, buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func ZipDirectoryToTempFile(sourceDir string) (*os.File, error) {
	tmpFile, err := os.CreateTemp("", "dataset*.zip")
	if err != nil {
		return nil, err
	}
	if err := writeZip(sourceDir, tmpFile); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return nil, err
	}
	if _, err := tmpFile.Seek(0, 0); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return nil, err
	}
	return tmpFile, nil
}

func writeZip(sourcePath string, dst io.Writer) error {
	if sourcePath == "" {
		return fmt.Errorf("zip source path is empty")
	}

	sourcePath = filepath.Clean(sourcePath)
	info, err := os.Stat(sourcePath)
	if err != nil {
		return err
	}

	files, err := zipSourceFiles(sourcePath, info)
	if err != nil {
		return err
	}
	sort.Strings(files)

	zipWriter := zip.NewWriter(dst)
	for _, filePath := range files {
		if err := addZipFile(zipWriter, sourcePath, info, filePath); err != nil {
			_ = zipWriter.Close()
			return err
		}
	}
	return zipWriter.Close()
}

func zipSourceFiles(sourcePath string, sourceInfo os.FileInfo) ([]string, error) {
	if !sourceInfo.IsDir() {
		return []string{sourcePath}, nil
	}

	var files []string
	err := filepath.Walk(sourcePath, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		files = append(files, filePath)
		return nil
	})
	return files, err
}

func addZipFile(zipWriter *zip.Writer, sourcePath string, sourceInfo os.FileInfo, filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return nil
	}

	name, err := zipEntryName(sourcePath, sourceInfo, filePath)
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = name
	header.Method = zip.Deflate
	header.Modified = time.Unix(0, 0)

	entry, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(entry, file)
	return err
}

func zipEntryName(sourcePath string, sourceInfo os.FileInfo, filePath string) (string, error) {
	if !sourceInfo.IsDir() {
		return filepath.ToSlash(filepath.Base(filePath)), nil
	}
	relPath, err := filepath.Rel(sourcePath, filePath)
	if err != nil {
		return "", err
	}
	if relPath == "." || relPath == "" {
		return "", fmt.Errorf("invalid zip entry path %q", relPath)
	}
	return filepath.ToSlash(relPath), nil
}

func UnzipFromMemory(zipData []byte, targetDir string) error {
	return UnzipFromMemoryContext(context.Background(), zipData, targetDir)
}

func UnzipFromMemoryContext(ctx context.Context, zipData []byte, targetDir string) error {
	return unzipFromMemory(ctx, zipData, targetDir, maxZipExpandedBytes, maxZipEntries)
}

func unzipFromMemory(ctx context.Context, zipData []byte, targetDir string, maxExpanded int64, maxEntries int) error {
	if ctx == nil || maxExpanded < 0 || maxEntries < 0 {
		return fmt.Errorf("invalid zip extraction limits")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if targetDir == "" {
		return fmt.Errorf("zip target path is empty")
	}
	if err := preflightZipDirectory(ctx, zipData, maxEntries); err != nil {
		return err
	}
	root, err := filepath.Abs(targetDir)
	if err != nil {
		return err
	}
	extractionRoot, err := safearchive.OpenRoot(root, 0o755)
	if err != nil {
		return err
	}
	defer extractionRoot.Close()

	reader := bytes.NewReader(zipData)
	zipReader, err := zip.NewReader(reader, int64(len(zipData)))
	if err != nil {
		return err
	}
	if len(zipReader.File) > maxEntries {
		return errZipExpansionLimit
	}
	remaining := maxExpanded
	for _, file := range zipReader.File {
		if file.UncompressedSize64 > uint64(remaining) {
			return errZipExpansionLimit
		}
		remaining -= int64(file.UncompressedSize64)
	}
	remaining = maxExpanded

	for _, file := range zipReader.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		cleanName, err := cleanZipEntryName(file.Name)
		if err != nil {
			return err
		}
		entryName := filepath.FromSlash(cleanName)

		mode := file.FileInfo().Mode()
		if mode&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink %q", errUnsafeZipPath, file.Name)
		}
		if file.FileInfo().IsDir() {
			if err := extractionRoot.MkdirAll(entryName, 0o755); err != nil {
				return err
			}
			continue
		}
		if mode&os.ModeType != 0 {
			return fmt.Errorf("%w: unsupported file type %q", errUnsafeZipPath, file.Name)
		}
		if err := extractZipFile(ctx, file, extractionRoot, entryName, &remaining); err != nil {
			return err
		}
	}
	return nil
}

// preflightZipDirectory bounds the work zip.NewReader does while it eagerly
// parses central directory entries. The record count in the end record is not
// sufficient: zip.NewReader reads headers until it finds a non-header, even
// when the advertised count is smaller.
func preflightZipDirectory(ctx context.Context, data []byte, maxEntries int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	end, directorySize, directoryOffset, records, err := zipDirectoryEnd(data)
	if err != nil {
		return err
	}
	if records > uint64(maxEntries) || directorySize > maxZipDirectoryBytes {
		return errZipExpansionLimit
	}
	if directorySize > uint64(end) {
		return zip.ErrFormat
	}
	start := end - int(directorySize)
	if err := scanZipDirectory(ctx, data, start, maxEntries); err != nil {
		return err
	}

	// The standard reader can use the declared offset instead when a ZIP has
	// a nonzero base offset. Check that path too, including malformed records
	// that claim a small directory size but point to many actual headers.
	if directoryOffset < uint64(start) && directoryOffset < uint64(len(data)) {
		if err := scanZipDirectory(ctx, data, int(directoryOffset), maxEntries); err != nil {
			return err
		}
	}
	return nil
}

func zipDirectoryEnd(data []byte) (end int, size, offset, records uint64, err error) {
	const endRecordLen = 22
	if len(data) < endRecordLen {
		return 0, 0, 0, 0, zip.ErrFormat
	}
	start := len(data) - (endRecordLen + 1<<16 - 1)
	if start < 0 {
		start = 0
	}
	end = -1
	for i := len(data) - endRecordLen; i >= start; i-- {
		if binary.LittleEndian.Uint32(data[i:]) == 0x06054b50 &&
			i+endRecordLen+int(binary.LittleEndian.Uint16(data[i+20:])) <= len(data) {
			end = i
			break
		}
	}
	if end < 0 {
		return 0, 0, 0, 0, zip.ErrFormat
	}
	records = uint64(binary.LittleEndian.Uint16(data[end+10:]))
	size = uint64(binary.LittleEndian.Uint32(data[end+12:]))
	offset = uint64(binary.LittleEndian.Uint32(data[end+16:]))
	// Match archive/zip's ZIP64 lookup conditions, including its 0xffff
	// directory-size condition. A different decision here could preflight a
	// different directory from the one zip.NewReader will parse.
	if records != 0xffff && size != 0xffff && offset != 0xffffffff {
		return end, size, offset, records, nil
	}

	const locatorLen, zip64EndLen = 20, 56
	locator := end - locatorLen
	if locator < 0 || binary.LittleEndian.Uint32(data[locator:]) != 0x07064b50 ||
		binary.LittleEndian.Uint32(data[locator+4:]) != 0 ||
		binary.LittleEndian.Uint32(data[locator+16:]) != 1 {
		return end, size, offset, records, nil
	}
	zip64Offset := binary.LittleEndian.Uint64(data[locator+8:])
	if locator < zip64EndLen || zip64Offset > uint64(locator-zip64EndLen) {
		return 0, 0, 0, 0, zip.ErrFormat
	}
	zip64End := int(zip64Offset)
	if binary.LittleEndian.Uint32(data[zip64End:]) != 0x06064b50 {
		return 0, 0, 0, 0, zip.ErrFormat
	}
	return zip64End,
		binary.LittleEndian.Uint64(data[zip64End+40:]),
		binary.LittleEndian.Uint64(data[zip64End+48:]),
		binary.LittleEndian.Uint64(data[zip64End+32:]), nil
}

func scanZipDirectory(ctx context.Context, data []byte, start, maxEntries int) error {
	const headerLen = 46
	entries := 0
	for pos := start; pos < len(data); {
		if err := ctx.Err(); err != nil {
			return err
		}
		if pos-start > maxZipDirectoryBytes {
			return errZipExpansionLimit
		}
		if len(data)-pos < headerLen {
			return nil
		}
		if binary.LittleEndian.Uint32(data[pos:]) != 0x02014b50 {
			return nil
		}
		if entries >= maxEntries {
			return errZipExpansionLimit
		}
		variableLen := int(binary.LittleEndian.Uint16(data[pos+28:])) +
			int(binary.LittleEndian.Uint16(data[pos+30:])) +
			int(binary.LittleEndian.Uint16(data[pos+32:]))
		if headerLen+variableLen > len(data)-pos {
			return zip.ErrFormat
		}
		pos += headerLen + variableLen
		if pos-start > maxZipDirectoryBytes {
			return errZipExpansionLimit
		}
		entries++
	}
	return nil
}

func cleanZipEntryName(name string) (string, error) {
	if name == "" || strings.Contains(name, "\x00") || strings.Contains(name, "\\") {
		return "", fmt.Errorf("%w: %q", errUnsafeZipPath, name)
	}
	if path.IsAbs(name) || filepath.IsAbs(name) {
		return "", fmt.Errorf("%w: %q", errUnsafeZipPath, name)
	}
	cleanName := path.Clean(name)
	if cleanName == "." || cleanName == ".." || strings.HasPrefix(cleanName, "../") {
		return "", fmt.Errorf("%w: %q", errUnsafeZipPath, name)
	}
	return cleanName, nil
}

func extractZipFile(ctx context.Context, file *zip.File, root *os.Root, filePath string, remaining *int64) error {
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	perm := file.FileInfo().Mode().Perm()
	if perm == 0 {
		perm = 0o644
	}
	return safearchive.WriteFile(root, filePath, perm, &zipExpansionReader{source: src, ctx: ctx, remaining: remaining})
}

type zipExpansionReader struct {
	source    io.Reader
	ctx       context.Context
	remaining *int64
}

func (r *zipExpansionReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if *r.remaining == 0 {
		var extra [1]byte
		n, err := r.source.Read(extra[:])
		if n != 0 {
			return 0, errZipExpansionLimit
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
