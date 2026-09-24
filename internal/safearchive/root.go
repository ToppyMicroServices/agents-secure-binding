// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package safearchive

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// OpenRoot creates and opens an extraction root while rejecting a final-path
// symlink or a directory replacement that races the open.
func OpenRoot(name string, perm os.FileMode) (*os.Root, error) {
	if err := os.MkdirAll(name, perm); err != nil {
		return nil, err
	}
	before, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("unsafe extraction root %q", name)
	}

	root, err := os.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil {
		root.Close()
		return nil, err
	}
	after, err := os.Lstat(name)
	if err != nil {
		root.Close()
		return nil, err
	}
	if !after.IsDir() || after.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(before, opened) || !os.SameFile(after, opened) {
		root.Close()
		return nil, fmt.Errorf("unsafe extraction root %q: path changed while opening", name)
	}
	return root, nil
}

// WriteFile replaces name from a newly created file inside root. It never
// truncates a pre-existing inode, including one referenced by a hard link.
func WriteFile(root *os.Root, name string, perm os.FileMode, source io.Reader) (err error) {
	if err := root.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return err
	}

	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	temporaryName := filepath.Join(filepath.Dir(name), ".asb-extract-"+hex.EncodeToString(random)+".tmp")
	temporary, err := root.OpenFile(temporaryName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	temporaryClosed := false
	defer func() {
		if !temporaryClosed {
			if closeErr := temporary.Close(); err == nil && closeErr != nil {
				err = closeErr
			}
		}
		if removeErr := root.Remove(temporaryName); err == nil && removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = removeErr
		}
	}()

	if err := temporary.Chmod(perm); err != nil {
		return err
	}
	if _, err := io.Copy(temporary, source); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	temporaryClosed = true

	info, statErr := root.Lstat(name)
	if statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to replace symlink %q", name)
		}
		if info.IsDir() {
			return fmt.Errorf("cannot replace directory %q", name)
		}
		if err := root.Remove(name); err != nil {
			return err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	if err := root.Rename(temporaryName, name); err != nil {
		return err
	}
	return nil
}
