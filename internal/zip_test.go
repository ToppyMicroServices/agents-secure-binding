// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package internal

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestZipDirectoryToMemory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "zip_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFiles := map[string]string{
		"file1.txt":        "Content of file 1",
		"file2.txt":        "Content of file 2",
		"subdir/file3.txt": "Content of file 3 in subdirectory",
	}

	for path, content := range testFiles {
		fullPath := filepath.Join(tempDir, path)
		err := os.MkdirAll(filepath.Dir(fullPath), 0o755)
		if err != nil {
			t.Fatalf("Failed to create directory: %v", err)
		}
		err = os.WriteFile(fullPath, []byte(content), 0o644)
		if err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}
	}

	zipData, err := ZipDirectoryToMemory(tempDir)
	if err != nil {
		t.Fatalf("ZipDirectoryToMemory failed: %v", err)
	}

	if len(zipData) == 0 {
		t.Error("Zip data is empty")
	}

	unzipDir, err := os.MkdirTemp("", "unzip_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory for unzip: %v", err)
	}
	defer os.RemoveAll(unzipDir)

	err = UnzipFromMemory(zipData, unzipDir)
	if err != nil {
		t.Fatalf("UnzipFromMemory failed: %v", err)
	}

	for path, expectedContent := range testFiles {
		fullPath := filepath.Join(unzipDir, path)
		content, err := os.ReadFile(fullPath)
		if err != nil {
			t.Errorf("Failed to read unzipped file %s: %v", path, err)
			continue
		}
		if string(content) != expectedContent {
			t.Errorf("Content mismatch for file %s. Expected: %s, Got: %s", path, expectedContent, string(content))
		}
	}
}

func TestZipDirectoryToMemory_EmptyDirectory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "empty_zip_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	zipData, err := ZipDirectoryToMemory(tempDir)
	if err != nil {
		t.Fatalf("ZipDirectoryToMemory failed on empty directory: %v", err)
	}

	if len(zipData) == 0 {
		t.Error("Zip data is empty for an empty directory")
	}
}

func TestUnzipFromMemory_InvalidZipData(t *testing.T) {
	invalidZipData := []byte("This is not a valid zip file")
	tempDir, err := os.MkdirTemp("", "invalid_unzip_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	err = UnzipFromMemory(invalidZipData, tempDir)
	if err == nil {
		t.Error("UnzipFromMemory should fail with invalid zip data")
	}
}

func TestZipDirectoryToMemory_NonExistentDirectory(t *testing.T) {
	nonExistentDir := "/path/to/non/existent/directory"
	_, err := ZipDirectoryToMemory(nonExistentDir)
	if err == nil {
		t.Error("ZipDirectoryToMemory should fail with non-existent directory")
	}
}

func TestZipDirectoryToTempFile(t *testing.T) {
	tests := []struct {
		name        string
		setupFiles  map[string]string // map of relative path to content
		expectError bool
	}{
		{
			name: "single file",
			setupFiles: map[string]string{
				"test.txt": "hello world",
			},
			expectError: false,
		},
		{
			name: "multiple files in root",
			setupFiles: map[string]string{
				"test1.txt": "content1",
				"test2.txt": "content2",
				"test3.txt": "content3",
			},
			expectError: false,
		},
		{
			name: "nested directory structure",
			setupFiles: map[string]string{
				"file1.txt":                "root file",
				"dir1/file2.txt":           "nested file",
				"dir1/dir2/file3.txt":      "deeply nested file",
				"dir1/dir2/dir3/file4.txt": "very deeply nested file",
			},
			expectError: false,
		},
		{
			name:        "empty directory",
			setupFiles:  map[string]string{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sourceDir, err := os.MkdirTemp("", "source")
			if err != nil {
				t.Fatalf("Failed to create temp source directory: %v", err)
			}
			defer os.RemoveAll(sourceDir)

			for relPath, content := range tt.setupFiles {
				fullPath := filepath.Join(sourceDir, relPath)
				dir := filepath.Dir(fullPath)

				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatalf("Failed to create directory %s: %v", dir, err)
				}

				if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
					t.Fatalf("Failed to write file %s: %v", fullPath, err)
				}
			}

			zipFile, err := ZipDirectoryToTempFile(sourceDir)
			if err != nil {
				if !tt.expectError {
					t.Fatalf("Unexpected error: %v", err)
				}
				return
			}
			defer os.Remove(zipFile.Name())
			defer zipFile.Close()

			if tt.expectError {
				t.Fatal("Expected error but got none")
			}

			zipReader, err := zip.OpenReader(zipFile.Name())
			if err != nil {
				t.Fatalf("Failed to open zip file: %v", err)
			}
			defer zipReader.Close()

			expectedFiles := make(map[string]string)
			for path, content := range tt.setupFiles {
				expectedFiles[filepath.ToSlash(path)] = content
			}

			for _, file := range zipReader.File {
				expectedContent, exists := expectedFiles[file.Name]
				if !exists {
					t.Errorf("Unexpected file in zip: %s", file.Name)
					continue
				}

				rc, err := file.Open()
				if err != nil {
					t.Errorf("Failed to open file in zip %s: %v", file.Name, err)
					continue
				}

				content, err := io.ReadAll(rc)
				rc.Close()
				if err != nil {
					t.Errorf("Failed to read file in zip %s: %v", file.Name, err)
					continue
				}

				if string(content) != expectedContent {
					t.Errorf("File %s content mismatch: got %s, want %s", file.Name, content, expectedContent)
				}

				delete(expectedFiles, file.Name)
			}

			for path := range expectedFiles {
				t.Errorf("Missing file in zip: %s", path)
			}
		})
	}
}

func TestUnzipFromMemory_ErrorPaths(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unzip_error_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a valid zip with one file
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create("file.txt")
	require.NoError(t, err)
	_, err = f.Write([]byte("content"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	t.Run("mkdir failure", func(t *testing.T) {
		// Create a file where a directory should be
		blockedDir := filepath.Join(tempDir, "subdir")
		require.NoError(t, os.WriteFile(blockedDir, []byte("blocked"), 0o644))
		defer os.Remove(blockedDir)

		// Create a zip that tries to create a file in that subdir
		var buf2 bytes.Buffer
		zw2 := zip.NewWriter(&buf2)
		_, err := zw2.Create("subdir/file.txt")
		require.NoError(t, err)
		require.NoError(t, zw2.Close())

		err = UnzipFromMemory(buf2.Bytes(), tempDir)
		assert.Error(t, err)
	})

	t.Run("create file failure", func(t *testing.T) {
		// Create a directory where a file should be
		blockedFile := filepath.Join(tempDir, "blocked_file.txt")
		require.NoError(t, os.MkdirAll(blockedFile, 0o755))
		defer os.RemoveAll(blockedFile)

		var buf2 bytes.Buffer
		zw2 := zip.NewWriter(&buf2)
		_, err := zw2.Create("blocked_file.txt")
		require.NoError(t, err)
		require.NoError(t, zw2.Close())

		err = UnzipFromMemory(buf2.Bytes(), tempDir)
		assert.Error(t, err)
	})
}

func TestZipDirectoryToMemory_ErrorPaths(t *testing.T) {
	t.Run("non-existent directory", func(t *testing.T) {
		_, err := ZipDirectoryToMemory("/non/existent/path")
		assert.Error(t, err)
	})
}

func TestZipDirectoryToTempFile_ErrorPaths(t *testing.T) {
	t.Run("non-existent directory", func(t *testing.T) {
		_, err := ZipDirectoryToTempFile("/non/existent/path")
		assert.Error(t, err)
	})

	t.Run("empty source path", func(t *testing.T) {
		_, err := ZipDirectoryToTempFile("")
		assert.Error(t, err)
	})
}

func TestZipDirectoryToMemory_NotADirectory(t *testing.T) {
	tempFile, err := os.CreateTemp("", "not_a_dir")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())
	tempFile.Close()

	_, err = ZipDirectoryToMemory(tempFile.Name())
	// filepath.Walk on a file succeeds and visits only that file
	assert.NoError(t, err)
}

func TestZipDirectoryToTempFile_NotADirectory(t *testing.T) {
	tempFile, err := os.CreateTemp("", "not_a_dir_tempfile")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())
	tempFile.Close()

	zf, err := ZipDirectoryToTempFile(tempFile.Name())
	assert.NoError(t, err)
	if err == nil {
		zf.Close()
		os.Remove(zf.Name())
	}
}

func TestZipDirectoryToMemory_OpenError(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "open_err_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	file := filepath.Join(tempDir, "unreadable.txt")
	require.NoError(t, os.WriteFile(file, []byte("test"), 0o000))

	_, err = ZipDirectoryToMemory(tempDir)
	assert.Error(t, err)
}

func TestZipDirectoryToTempFile_InvalidInput(t *testing.T) {
	tests := []struct {
		name      string
		sourceDir string
	}{
		{
			name:      "non-existent directory",
			sourceDir: "/path/that/does/not/exist",
		},
		{
			name:      "empty path",
			sourceDir: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ZipDirectoryToTempFile(tt.sourceDir)
			if err == nil {
				t.Error("Expected error but got none")
			}
		})
	}
}

func TestZipDirectoryToTempFile_InternalErrorPaths(t *testing.T) {
	t.Run("unreadable file in directory", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "unreadable_zip_temp")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		file := filepath.Join(tempDir, "unreadable.txt")
		require.NoError(t, os.WriteFile(file, []byte("test"), 0o000))

		_, err = ZipDirectoryToTempFile(tempDir)
		assert.Error(t, err)
	})
}

func TestUnzipFromMemory_MoreEdgeCases(t *testing.T) {
	t.Run("empty zip data", func(t *testing.T) {
		err := UnzipFromMemory([]byte{}, t.TempDir())
		assert.Error(t, err)
	})

	t.Run("zip with absolute paths", func(t *testing.T) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		_, err := zw.Create("/tmp/test.txt")
		require.NoError(t, err)
		require.NoError(t, zw.Close())

		tempDir := t.TempDir()
		err = UnzipFromMemory(buf.Bytes(), tempDir)
		assert.Error(t, err)
	})

	t.Run("zip with parent traversal", func(t *testing.T) {
		tempDir := t.TempDir()
		escapeName := filepath.Base(tempDir) + "-escape.txt"

		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		_, err := zw.Create("../" + escapeName)
		require.NoError(t, err)
		require.NoError(t, zw.Close())

		err = UnzipFromMemory(buf.Bytes(), tempDir)
		assert.Error(t, err)
		_, statErr := os.Stat(filepath.Join(filepath.Dir(tempDir), escapeName))
		assert.Error(t, statErr)
	})
}

func TestUnzipFromMemory_RejectsPreexistingSymlinks(t *testing.T) {
	makeZip := func(t *testing.T, name string) []byte {
		t.Helper()
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		entry, err := zw.Create(name)
		require.NoError(t, err)
		_, err = entry.Write([]byte("archive content"))
		require.NoError(t, err)
		require.NoError(t, zw.Close())
		return buf.Bytes()
	}

	t.Run("parent symlink", func(t *testing.T) {
		target := t.TempDir()
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(target, "link")); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}

		err := UnzipFromMemory(makeZip(t, "link/escape.txt"), target)
		require.Error(t, err)
		_, statErr := os.Stat(filepath.Join(outside, "escape.txt"))
		assert.ErrorIs(t, statErr, os.ErrNotExist)
	})

	t.Run("final symlink", func(t *testing.T) {
		target := t.TempDir()
		outside := filepath.Join(t.TempDir(), "outside.txt")
		require.NoError(t, os.WriteFile(outside, []byte("original"), 0o600))
		if err := os.Symlink(outside, filepath.Join(target, "escape.txt")); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}

		err := UnzipFromMemory(makeZip(t, "escape.txt"), target)
		require.Error(t, err)
		content, readErr := os.ReadFile(outside)
		require.NoError(t, readErr)
		assert.Equal(t, "original", string(content))
	})

	t.Run("destination symlink", func(t *testing.T) {
		parent := t.TempDir()
		outside := t.TempDir()
		target := filepath.Join(parent, "target")
		if err := os.Symlink(outside, target); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}

		err := UnzipFromMemory(makeZip(t, "escape.txt"), target)
		require.Error(t, err)
		_, statErr := os.Stat(filepath.Join(outside, "escape.txt"))
		assert.ErrorIs(t, statErr, os.ErrNotExist)
	})

	t.Run("hardlink", func(t *testing.T) {
		target := t.TempDir()
		outside := filepath.Join(t.TempDir(), "outside.txt")
		require.NoError(t, os.WriteFile(outside, []byte("original"), 0o600))
		if err := os.Link(outside, filepath.Join(target, "escape.txt")); err != nil {
			t.Skipf("hardlink unavailable: %v", err)
		}

		require.NoError(t, UnzipFromMemory(makeZip(t, "escape.txt"), target))
		outsideContent, err := os.ReadFile(outside)
		require.NoError(t, err)
		assert.Equal(t, "original", string(outsideContent))
		extractedContent, err := os.ReadFile(filepath.Join(target, "escape.txt"))
		require.NoError(t, err)
		assert.Equal(t, "archive content", string(extractedContent))
	})
}

func TestUnzipFromMemory_InvalidReader(t *testing.T) {
	err := UnzipFromMemory([]byte("invalid"), t.TempDir())
	assert.Error(t, err)
}

func TestUnzipFromMemory_FileCreateError(t *testing.T) {
	tempDir := t.TempDir()

	// Create a zip with one file
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	_, err := zw.Create("file.txt")
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	// Create a directory where the file should be
	blockedFile := filepath.Join(tempDir, "file.txt")
	require.NoError(t, os.MkdirAll(blockedFile, 0o755))

	err = UnzipFromMemory(buf.Bytes(), tempDir)
	assert.Error(t, err)
}

func TestUnzipFromMemory_DirCreateError(t *testing.T) {
	tempDir := t.TempDir()

	// Create a zip with one directory entry
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	_, err := zw.Create("subdir/")
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	// Create a file where the directory should be
	blockedDir := filepath.Join(tempDir, "subdir")
	require.NoError(t, os.WriteFile(blockedDir, []byte("blocked"), 0o644))

	err = UnzipFromMemory(buf.Bytes(), tempDir)
	assert.Error(t, err)
}
