// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanapp

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStoreSnapshotIsExclusiveAndIndependentlyVerifiable(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, filepath.Join(dir, "state.sqlite"))
	executeStore(t, store, testProposal("archive", true, 0), ActorAgent, "archive-proof")

	archiveDir := filepath.Join(dir, "archives")
	archivePath := filepath.Join(archiveDir, "snapshot.sqlite")
	manifest, err := store.ExportSnapshot(context.Background(), archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Archive != "snapshot.sqlite" || manifest.Capacity.Operations != 1 || manifest.Capacity.Commands != 1 || manifest.Capacity.ReplayRecords != 1 {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	loaded, err := ReadStoreArchiveManifest(archivePath + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyStoreArchive(context.Background(), archivePath, loaded); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ExportSnapshot(context.Background(), archivePath); err == nil {
		t.Fatal("export replaced an existing archive")
	}

	file, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("tamper"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := VerifyStoreArchive(context.Background(), archivePath, loaded); err == nil {
		t.Fatal("tampered archive matched its manifest")
	}
}

func TestStoreCapacityReportsLimits(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.sqlite"))
	capacity, err := store.Capacity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if capacity.Operations != 0 || capacity.Pending != 0 || capacity.Commands != 0 || capacity.ReplayRecords != 0 {
		t.Fatalf("new store has records: %+v", capacity)
	}
	if capacity.OperationLimit != maxProposalRecords || capacity.CommandLimit != maxMutationRecords || capacity.ReplayLimit != maxReplayRecords {
		t.Fatalf("wrong limits: %+v", capacity)
	}
}

func TestStoreArchiveInspectionUsesOpenedFile(t *testing.T) {
	dir := t.TempDir()
	archiveDir := filepath.Join(dir, "archives")
	firstStore := openTestStore(t, filepath.Join(dir, "first-source.sqlite"))
	executeStore(t, firstStore, testProposal("first", true, 0), ActorAgent, "first-proof")
	firstPath := filepath.Join(archiveDir, "first.sqlite")
	firstManifest, err := firstStore.ExportSnapshot(context.Background(), firstPath)
	if err != nil {
		t.Fatal(err)
	}

	secondStore := openTestStore(t, filepath.Join(dir, "second-source.sqlite"))
	secondPath := filepath.Join(archiveDir, "second.sqlite")
	if _, err := secondStore.ExportSnapshot(context.Background(), secondPath); err != nil {
		t.Fatal(err)
	}

	snapshot, err := openStoreArchiveSnapshot(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if err := os.Rename(secondPath, firstPath); err != nil {
		if runtime.GOOS == goosWindows {
			return // The non-shareable Windows handle blocks replacement directly.
		}
		t.Fatal(err)
	}

	inspected, err := inspectOpenedStoreArchive(context.Background(), snapshot.file, snapshot.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if inspected.SHA256 != firstManifest.SHA256 || inspected.Bytes != firstManifest.Bytes || inspected.Capacity != firstManifest.Capacity {
		t.Fatalf("inspection followed a replacement path: got %+v, want %+v", inspected, firstManifest)
	}
	if err := ensureArchivePathStable(snapshot.original, firstPath, inspected.SHA256); err == nil {
		t.Fatal("replacement path was not detected")
	}
}

func TestMoveNewFileDoesNotReplaceConcurrentDestination(t *testing.T) {
	dir := t.TempDir()
	temporary := filepath.Join(dir, "temporary")
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(temporary, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := moveNewFile(temporary, target); err == nil {
		t.Fatal("moveNewFile replaced an existing destination")
	}
	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "existing" {
		t.Fatalf("existing destination changed to %q", contents)
	}
}

func TestStoreArchiveSnapshotIsolatedFromInPlaceMutation(t *testing.T) {
	dir := t.TempDir()
	archiveDir := filepath.Join(dir, "archives")
	firstStore := openTestStore(t, filepath.Join(dir, "first-mutable-source.sqlite"))
	executeStore(t, firstStore, testProposal("mutable", true, 0), ActorAgent, "mutable-proof")
	firstPath := filepath.Join(archiveDir, "mutable.sqlite")
	firstManifest, err := firstStore.ExportSnapshot(context.Background(), firstPath)
	if err != nil {
		t.Fatal(err)
	}
	secondStore := openTestStore(t, filepath.Join(dir, "replacement-source.sqlite"))
	secondPath := filepath.Join(archiveDir, "replacement.sqlite")
	if _, err := secondStore.ExportSnapshot(context.Background(), secondPath); err != nil {
		t.Fatal(err)
	}
	replacement, err := os.ReadFile(secondPath)
	if err != nil {
		t.Fatal(err)
	}

	snapshot, err := openStoreArchiveSnapshot(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	file, err := os.OpenFile(firstPath, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		if runtime.GOOS == goosWindows {
			return // The Windows source handle denies write sharing.
		}
		t.Fatal(err)
	}
	if _, err := file.Write(replacement); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	inspected, err := inspectOpenedStoreArchive(context.Background(), snapshot.file, snapshot.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if inspected.SHA256 != firstManifest.SHA256 || inspected.Capacity != firstManifest.Capacity {
		t.Fatalf("snapshot changed with source inode: got %+v, want %+v", inspected, firstManifest)
	}
	if err := ensureArchivePathStable(snapshot.original, firstPath, inspected.SHA256); err == nil {
		t.Fatal("in-place archive mutation was not detected")
	}
}
