// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package qemu

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func TestNewFilePersistence(t *testing.T) {
	tempDir := privateStateTestDir(t)

	fp := newTestPersistence(t, tempDir)

	if _, ok := fp.(*FilePersistence); !ok {
		t.Fatalf("NewFilePersistence didn't return a FilePersistence")
	}
}

func TestSaveVM(t *testing.T) {
	tempDir := privateStateTestDir(t)
	fp := newTestPersistence(t, tempDir)

	state := VMState{
		ID:     "test-vm",
		VMinfo: VMInfo{Config: Config{}},
		PID:    1234,
	}

	err := fp.SaveVM(state)
	if err != nil {
		t.Fatalf("SaveVM failed: %v", err)
	}

	// Check if file exists
	if _, err := os.Stat(filepath.Join(tempDir, "test-vm.json")); os.IsNotExist(err) {
		t.Fatalf("SaveVM didn't create a file")
	}
}

func TestLoadVMs(t *testing.T) {
	tempDir := privateStateTestDir(t)
	fp := newTestPersistence(t, tempDir)

	// Save two VMs
	states := []VMState{
		{ID: "vm1", VMinfo: VMInfo{Config: Config{}}, PID: 1234},
		{ID: "vm2", VMinfo: VMInfo{Config: Config{}}, PID: 5678},
	}

	for _, state := range states {
		if err := fp.SaveVM(state); err != nil {
			t.Fatalf("SaveVM failed: %v", err)
		}
	}

	// Load VMs
	loadedStates, err := fp.LoadVMs()
	if err != nil {
		t.Fatalf("LoadVMs failed: %v", err)
	}

	if len(loadedStates) != len(states) {
		t.Fatalf("LoadVMs returned %d states, expected %d", len(loadedStates), len(states))
	}

	// Check if loaded states match saved states
	for i, state := range states {
		if state.ID != loadedStates[i].ID || state.PID != loadedStates[i].PID {
			t.Fatalf("Loaded state %v doesn't match saved state %v", loadedStates[i], state)
		}
	}
}

func TestDeleteVM(t *testing.T) {
	tempDir := privateStateTestDir(t)
	fp := newTestPersistence(t, tempDir)

	state := VMState{ID: "test-vm", VMinfo: VMInfo{Config: Config{}}, PID: 1234}

	// Save VM
	if err := fp.SaveVM(state); err != nil {
		t.Fatalf("SaveVM failed: %v", err)
	}

	// Delete VM
	if err := fp.DeleteVM(state.ID); err != nil {
		t.Fatalf("DeleteVM failed: %v", err)
	}

	// Check if file is deleted
	if _, err := os.Stat(filepath.Join(tempDir, "test-vm.json")); !os.IsNotExist(err) {
		t.Fatalf("DeleteVM didn't remove the file")
	}
}

func TestLoadVMsWithInvalidFile(t *testing.T) {
	tempDir := privateStateTestDir(t)
	fp := newTestPersistence(t, tempDir)

	invalidData := []byte("{invalid json")
	if err := os.WriteFile(filepath.Join(tempDir, "invalid.json"), invalidData, 0o600); err != nil {
		t.Fatalf("Failed to create invalid JSON file: %v", err)
	}

	_, err := fp.LoadVMs()
	if err == nil {
		t.Fatalf("LoadVMs should have failed with invalid JSON")
	}
}

func TestConcurrentAccess(t *testing.T) {
	tempDir := privateStateTestDir(t)
	fp := newTestPersistence(t, tempDir)

	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			state := VMState{ID: fmt.Sprintf("vm-%d", id), VMinfo: VMInfo{Config: Config{}}, PID: id + 1}
			if err := fp.SaveVM(state); err != nil {
				t.Errorf("Concurrent SaveVM failed: %v", err)
			}
		}(i)

		go func() {
			defer wg.Done()
			if _, err := fp.LoadVMs(); err != nil {
				t.Errorf("Concurrent LoadVMs failed: %v", err)
			}
		}()
	}

	wg.Wait()
}

func privateStateTestDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newTestPersistence(t *testing.T, dir string) Persistence {
	t.Helper()
	fp, err := NewFilePersistence(dir)
	if err != nil {
		t.Fatalf("NewFilePersistence failed: %v", err)
	}
	t.Cleanup(func() { _ = fp.(io.Closer).Close() })
	return fp
}

func TestPersistenceRejectsUntrustedDirectories(t *testing.T) {
	for _, mode := range []os.FileMode{0o755, 0o777} {
		t.Run(mode.String(), func(t *testing.T) {
			dir := privateStateTestDir(t)
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			if fp, err := NewFilePersistence(dir); err == nil {
				_ = fp.(io.Closer).Close()
				t.Fatal("accepted a non-private existing state directory")
			}
			info, err := os.Stat(dir)
			if err != nil || info.Mode().Perm() != mode {
				t.Fatal("rejected directory permissions were changed")
			}
		})
	}
	for _, ancestor := range []bool{false, true} {
		t.Run(fmt.Sprintf("symlink_ancestor_%t", ancestor), func(t *testing.T) {
			base, target := privateStateTestDir(t), privateStateTestDir(t)
			link := filepath.Join(base, "link")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			dir := link
			if ancestor {
				dir = filepath.Join(link, "state")
			}
			if fp, err := NewFilePersistence(dir); err == nil {
				_ = fp.(io.Closer).Close()
				t.Fatal("accepted a symlink in the state directory path")
			}
			entries, err := os.ReadDir(target)
			if err != nil || len(entries) != 0 {
				t.Fatal("modified symlink target")
			}
		})
	}
}

func TestPersistenceRejectsUnsafeIDsAndAcceptsBenignIDs(t *testing.T) {
	dir := privateStateTestDir(t)
	fp := newTestPersistence(t, dir)
	outside := filepath.Join(filepath.Dir(dir), "outside.json")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(outside) })
	for _, id := range []string{"", ".", "..", "../outside", "a/../../outside", "/outside", "a\\b", "a\x00b"} {
		t.Run(fmt.Sprintf("invalid_%q", id), func(t *testing.T) {
			if err := fp.SaveVM(VMState{ID: id, PID: 1}); err == nil {
				t.Fatal("saved an unsafe ID")
			}
			if err := fp.DeleteVM(id); err == nil {
				t.Fatal("deleted an unsafe ID")
			}
		})
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "unchanged" {
		t.Fatal("unsafe ID changed a file outside the state directory")
	}
	ids := []string{"test-vm", "vm1", "vm with spaces", "vm_1.2", "計算"}
	for _, id := range ids {
		if err := fp.SaveVM(VMState{ID: id, PID: 1}); err != nil {
			t.Fatalf("rejected benign ID %q: %v", id, err)
		}
	}
	states, err := fp.LoadVMs()
	if err != nil || len(states) != len(ids) {
		t.Fatalf("failed benign ID roundtrip: %v, %v", states, err)
	}
	for _, id := range ids {
		if err := fp.DeleteVM(id); err != nil {
			t.Fatalf("failed benign ID deletion %q: %v", id, err)
		}
	}
}

func TestPersistenceRejectsUnsafeStateFiles(t *testing.T) {
	for _, kind := range []string{"public", "writable", "symlink", "internal_symlink", "hardlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			dir, outsideDir := privateStateTestDir(t), privateStateTestDir(t)
			fp := newTestPersistence(t, dir)
			data, err := json.Marshal(VMState{ID: "vm1", PID: 1})
			if err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(outsideDir, "outside.json")
			if err := os.WriteFile(outside, data, 0o600); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(dir, "vm1.json")
			switch kind {
			case "public", "writable":
				mode := os.FileMode(0o644)
				if kind == "writable" {
					mode = 0o666
				}
				err = os.WriteFile(name, data, mode)
			case "symlink":
				err = os.Symlink(outside, name)
			case "internal_symlink":
				err = os.WriteFile(filepath.Join(dir, "target"), data, 0o600)
				if err == nil {
					err = os.Symlink("target", name)
				}
			case "hardlink":
				err = os.Link(outside, name)
			case "directory":
				err = os.Mkdir(name, 0o700)
			}
			if err != nil {
				t.Fatal(err)
			}
			if reopened, err := NewFilePersistence(dir); err == nil {
				_ = reopened.(io.Closer).Close()
				t.Fatal("constructor accepted an unsafe state file")
			}
			if _, err := fp.LoadVMs(); err == nil {
				t.Fatal("loaded an unsafe state file")
			}
			if err := fp.SaveVM(VMState{ID: "vm1", PID: 1}); err == nil {
				t.Fatal("overwrote an unsafe state file")
			}
			if err := fp.DeleteVM("vm1"); err == nil {
				t.Fatal("deleted an unsafe state file")
			}
			got, err := os.ReadFile(outside)
			if err != nil || !reflect.DeepEqual(got, data) {
				t.Fatal("changed a file outside the state directory")
			}
		})
	}
}

func TestPersistenceRejectsInvalidRecords(t *testing.T) {
	for _, state := range []VMState{{ID: "../outside", PID: 1}, {ID: "other", PID: 1}, {ID: "vm1", PID: 0}, {ID: "vm1", PID: -1}} {
		t.Run(fmt.Sprintf("%q_%d", state.ID, state.PID), func(t *testing.T) {
			dir := privateStateTestDir(t)
			fp := newTestPersistence(t, dir)
			data, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "vm1.json"), data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := fp.LoadVMs(); err == nil {
				t.Fatal("loaded an invalid record")
			}
			if reopened, err := NewFilePersistence(dir); err == nil {
				_ = reopened.(io.Closer).Close()
				t.Fatal("constructor accepted an invalid record")
			}
		})
	}
	fp := newTestPersistence(t, privateStateTestDir(t))
	for _, pid := range []int{0, -1} {
		if err := fp.SaveVM(VMState{ID: "vm1", PID: pid}); err == nil {
			t.Fatalf("saved nonpositive PID %d", pid)
		}
	}
}

func TestPersistencePinsDirectoryAndReplacesAtomically(t *testing.T) {
	base := privateStateTestDir(t)
	dir := filepath.Join(base, "state")
	fp := newTestPersistence(t, dir)
	state := VMState{ID: "vm1", PID: 1}
	if err := fp.SaveVM(state); err != nil {
		t.Fatal(err)
	}
	original, err := os.Stat(filepath.Join(dir, "vm1.json"))
	if err != nil || original.Mode().Perm() != 0o600 {
		t.Fatalf("state was not saved privately: %v", err)
	}
	state.PID = 2
	if err := fp.SaveVM(state); err != nil {
		t.Fatal(err)
	}
	updated, err := os.Stat(filepath.Join(dir, "vm1.json"))
	if err != nil || os.SameFile(original, updated) {
		t.Fatal("state replacement truncated the original inode")
	}
	moved := filepath.Join(base, "original")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	state.PID = 3
	if err := fp.SaveVM(state); err != nil {
		t.Fatal(err)
	}
	states, err := fp.LoadVMs()
	if err != nil || len(states) != 1 || states[0].PID != 3 {
		t.Fatalf("pinned state directory was lost: %v, %v", states, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("adopted a replacement state directory")
	}
	entries, err = os.ReadDir(moved)
	if err != nil || len(entries) != 1 || entries[0].Name() != "vm1.json" {
		t.Fatal("atomic writes left temporary files")
	}
}
