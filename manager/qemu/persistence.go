// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package qemu

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const jsonExt = ".json"

type VMState struct {
	ID     string
	VMinfo VMInfo
	PID    int
}

type FilePersistence struct {
	root *os.Root
	lock sync.Mutex
}

// Persistence is an interface for saving and loading VM states.
type Persistence interface {
	SaveVM(state VMState) error
	LoadVMs() ([]VMState, error)
	DeleteVM(id string) error
}

func NewFilePersistence(dir string) (Persistence, error) {
	root, err := openPrivateStateRoot(dir)
	if err != nil {
		return nil, err
	}
	fp := &FilePersistence{root: root}
	if _, err := fp.LoadVMs(); err != nil {
		_ = root.Close()
		return nil, err
	}
	return fp, nil
}

func (fp *FilePersistence) SaveVM(state VMState) error {
	fp.lock.Lock()
	defer fp.lock.Unlock()
	if err := validateState(state); err != nil {
		return err
	}
	if err := fp.checkRoot(); err != nil {
		return err
	}

	data, err := json.Marshal(state)
	if err != nil {
		return err
	}

	name := state.ID + jsonExt
	if err := fp.checkExistingFile(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporaryName := ".vm-state-" + rand.Text() + ".tmp"
	temporary, err := fp.root.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = fp.root.Remove(temporaryName) }()
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := fp.checkExistingFile(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return fp.root.Rename(temporaryName, name)
}

func (fp *FilePersistence) LoadVMs() ([]VMState, error) {
	fp.lock.Lock()
	defer fp.lock.Unlock()

	if err := fp.checkRoot(); err != nil {
		return nil, err
	}
	files, err := fs.ReadDir(fp.root.FS(), ".")
	if err != nil {
		return nil, err
	}

	var states []VMState
	for _, file := range files {
		if filepath.Ext(file.Name()) != jsonExt {
			continue
		}

		if err := validateStateID(strings.TrimSuffix(file.Name(), jsonExt)); err != nil {
			return nil, err
		}
		data, err := fp.readStateFile(file.Name())
		if err != nil {
			return nil, err
		}

		var state VMState
		if err := json.Unmarshal(data, &state); err != nil {
			return nil, err
		}
		if err := validateState(state); err != nil {
			return nil, err
		}
		if file.Name() != state.ID+jsonExt {
			return nil, fmt.Errorf("VM state ID does not match filename %q", file.Name())
		}

		states = append(states, state)
	}

	return states, nil
}

func (fp *FilePersistence) DeleteVM(id string) error {
	fp.lock.Lock()
	defer fp.lock.Unlock()

	if err := validateStateID(id); err != nil {
		return err
	}
	if err := fp.checkRoot(); err != nil {
		return err
	}
	if err := fp.checkExistingFile(id + jsonExt); err != nil {
		return err
	}
	return fp.root.Remove(id + jsonExt)
}

// Close releases the pinned state directory. It must follow the last operation.
func (fp *FilePersistence) Close() error {
	fp.lock.Lock()
	defer fp.lock.Unlock()
	return fp.root.Close()
}

func validateStateID(id string) error {
	if id == "" || id == "." || id == ".." || strings.ContainsAny(id, "/\\\x00") || !filepath.IsLocal(id) {
		return fmt.Errorf("invalid VM state ID %q", id)
	}
	return nil
}

func validateState(state VMState) error {
	if err := validateStateID(state.ID); err != nil {
		return err
	}
	if state.PID <= 0 {
		return fmt.Errorf("invalid persisted VM PID %d", state.PID)
	}
	return nil
}

func (fp *FilePersistence) checkRoot() error {
	info, err := fp.root.Stat(".")
	if err != nil {
		return err
	}
	return checkPrivateStateInfo(info, true)
}

func (fp *FilePersistence) checkExistingFile(name string) error {
	info, err := fp.root.Lstat(name)
	if err != nil {
		return err
	}
	return checkPrivateStateInfo(info, false)
}

func (fp *FilePersistence) readStateFile(name string) ([]byte, error) {
	before, err := fp.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if err := checkPrivateStateInfo(before, false); err != nil {
		return nil, err
	}
	file, err := fp.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	after, err := fp.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if err := checkPrivateStateInfo(opened, false); err != nil {
		return nil, err
	}
	if err := checkPrivateStateInfo(after, false); err != nil {
		return nil, err
	}
	if !os.SameFile(before, opened) || !os.SameFile(after, opened) {
		return nil, fmt.Errorf("VM state file %q changed while opening", name)
	}
	return io.ReadAll(file)
}

func checkPrivateStateInfo(info os.FileInfo, directory bool) error {
	if info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("VM state path %q must be private and have the expected file type", info.Name())
	}
	return checkStateOwnership(info)
}

// Walk from a pinned filesystem root so a symlink in any path component cannot
// redirect state creation. Existing permissions and data are never changed.
func openPrivateStateRoot(dir string) (*os.Root, error) {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.VolumeName(absolute) + string(filepath.Separator))
	if err != nil {
		return nil, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(absolute, filepath.VolumeName(absolute)+string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		if err := root.Mkdir(component, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			_ = root.Close()
			return nil, err
		}
		before, err := root.Lstat(component)
		if err != nil || !before.IsDir() {
			_ = root.Close()
			return nil, fmt.Errorf("unsafe VM state directory component %q", component)
		}
		child, err := root.OpenRoot(component)
		if err != nil {
			_ = root.Close()
			return nil, err
		}
		opened, statErr := child.Stat(".")
		after, pathErr := root.Lstat(component)
		_ = root.Close()
		if statErr != nil || pathErr != nil || !after.IsDir() || !os.SameFile(before, opened) || !os.SameFile(after, opened) {
			_ = child.Close()
			return nil, fmt.Errorf("VM state directory component %q changed while opening", component)
		}
		root = child
	}
	info, err := root.Stat(".")
	if err == nil {
		err = checkPrivateStateInfo(info, true)
	}
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	return root, nil
}
