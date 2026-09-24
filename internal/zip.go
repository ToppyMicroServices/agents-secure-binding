// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"archive/zip"
	"bytes"
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
	if targetDir == "" {
		return fmt.Errorf("zip target path is empty")
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

	for _, file := range zipReader.File {
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
		if err := extractZipFile(file, extractionRoot, entryName); err != nil {
			return err
		}
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

func extractZipFile(file *zip.File, root *os.Root, filePath string) error {
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	perm := file.FileInfo().Mode().Perm()
	if perm == 0 {
		perm = 0o644
	}
	return safearchive.WriteFile(root, filePath, perm, src)
}
