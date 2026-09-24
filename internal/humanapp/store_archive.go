// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanapp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const storeArchiveVersion = 1

// StoreCapacity reports the bounded online working set. Limits are part of the
// report so monitoring does not need to duplicate source constants.
type StoreCapacity struct {
	Operations     int `json:"operations"`
	Pending        int `json:"pending"`
	Commands       int `json:"commands"`
	ReplayRecords  int `json:"replay_records"`
	OperationLimit int `json:"operation_limit"`
	CommandLimit   int `json:"command_limit"`
	ReplayLimit    int `json:"replay_limit"`
}

// StoreArchiveManifest binds a consistent SQLite snapshot to its schema,
// content digest, and semantic record counts.
type StoreArchiveManifest struct {
	Version       int           `json:"version"`
	CreatedAt     time.Time     `json:"created_at"`
	Archive       string        `json:"archive"`
	SHA256        string        `json:"sha256"`
	Bytes         int64         `json:"bytes"`
	SchemaVersion int           `json:"schema_version"`
	ApplicationID int           `json:"application_id"`
	Capacity      StoreCapacity `json:"capacity"`
}

type storeArchiveSnapshot struct {
	file         *os.File
	original     *os.File
	databasePath string
	cleanupPath  string
	cleanupDir   string
}

func (s *storeArchiveSnapshot) Close() error {
	if s == nil {
		return nil
	}
	var first error
	if s.file != nil {
		first = s.file.Close()
	}
	if s.original != nil && s.original != s.file {
		if err := s.original.Close(); first == nil {
			first = err
		}
	}
	if s.cleanupPath != "" {
		if err := os.Remove(s.cleanupPath); first == nil && !errors.Is(err, os.ErrNotExist) {
			first = err
		}
	}
	if s.cleanupDir != "" {
		if err := os.Remove(s.cleanupDir); first == nil && !errors.Is(err, os.ErrNotExist) {
			first = err
		}
	}
	return first
}

// Capacity returns the current online record counts after pruning no state.
func (s *Store) Capacity(ctx context.Context) (StoreCapacity, error) {
	if s == nil || s.db == nil || ctx == nil {
		return StoreCapacity{}, ErrUnavailable
	}
	return queryStoreCapacity(ctx, s.db)
}

// ExportSnapshot writes a transactionally consistent SQLite snapshot and a
// sidecar manifest. It never deletes or compacts online records.
func (s *Store) ExportSnapshot(ctx context.Context, destination string) (StoreArchiveManifest, error) {
	if s == nil || s.db == nil || ctx == nil || strings.TrimSpace(destination) == "" {
		return StoreArchiveManifest{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return StoreArchiveManifest{}, err
	}
	destination, err := filepath.Abs(destination)
	if err != nil {
		return StoreArchiveManifest{}, err
	}
	manifestPath := destination + ".manifest.json"
	for _, path := range []string{destination, manifestPath} {
		if _, err := os.Lstat(path); err == nil {
			return StoreArchiveManifest{}, fmt.Errorf("refuse to replace existing archive artifact %q", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return StoreArchiveManifest{}, err
		}
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return StoreArchiveManifest{}, err
	}
	if err := validateArchiveDirectory(parent); err != nil {
		return StoreArchiveManifest{}, err
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return StoreArchiveManifest{}, err
	}
	temporary := filepath.Join(parent, "."+filepath.Base(destination)+"."+hex.EncodeToString(suffix[:])+".tmp")
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", temporary); err != nil {
		return StoreArchiveManifest{}, storeError(err)
	}
	if err := os.Chmod(temporary, 0o600); err != nil {
		return StoreArchiveManifest{}, err
	}
	if err := syncRegularFile(temporary); err != nil {
		return StoreArchiveManifest{}, err
	}
	manifest, err := inspectStoreArchive(ctx, temporary)
	if err != nil {
		return StoreArchiveManifest{}, err
	}
	manifest.CreatedAt = time.Now().UTC()
	manifest.Archive = filepath.Base(destination)
	if err := moveNewFile(temporary, destination); err != nil {
		return StoreArchiveManifest{}, err
	}
	removeTemporary = false
	if err := syncDirectory(parent); err != nil {
		return StoreArchiveManifest{}, err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return StoreArchiveManifest{}, err
	}
	if err := writeNewPrivateFile(manifestPath, append(encoded, '\n')); err != nil {
		return StoreArchiveManifest{}, err
	}
	return manifest, nil
}

// ReadStoreArchiveManifest reads a bounded manifest and rejects extra JSON.
func ReadStoreArchiveManifest(path string) (StoreArchiveManifest, error) {
	var manifest StoreArchiveManifest
	info, err := os.Lstat(path)
	if err != nil {
		return manifest, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 64*1024 {
		return manifest, fmt.Errorf("archive manifest must be a small regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return manifest, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64*1024+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return manifest, fmt.Errorf("archive manifest has trailing data")
	}
	if manifest.Version != storeArchiveVersion || manifest.Archive == "" || filepath.Base(manifest.Archive) != manifest.Archive || !strings.HasPrefix(manifest.SHA256, "sha256:") || manifest.Bytes <= 0 {
		return manifest, fmt.Errorf("invalid archive manifest")
	}
	return manifest, nil
}

// VerifyStoreArchive independently recomputes the snapshot digest, integrity
// result, schema identity, and semantic counts recorded in the manifest.
func VerifyStoreArchive(ctx context.Context, archivePath string, expected StoreArchiveManifest) error {
	if ctx == nil {
		return ErrInvalid
	}
	actual, err := inspectStoreArchive(ctx, archivePath)
	if err != nil {
		return err
	}
	if expected.Version != storeArchiveVersion || actual.SHA256 != expected.SHA256 || actual.Bytes != expected.Bytes || actual.SchemaVersion != expected.SchemaVersion || actual.ApplicationID != expected.ApplicationID || actual.Capacity != expected.Capacity {
		return fmt.Errorf("archive does not match its manifest")
	}
	if expected.Archive != filepath.Base(archivePath) {
		return fmt.Errorf("archive filename does not match its manifest")
	}
	return nil
}

func inspectStoreArchive(ctx context.Context, path string) (StoreArchiveManifest, error) {
	snapshot, err := openStoreArchiveSnapshot(path)
	if err != nil {
		return StoreArchiveManifest{}, err
	}
	defer snapshot.Close()
	manifest, err := inspectOpenedStoreArchive(ctx, snapshot.file, snapshot.databasePath)
	if err != nil {
		return StoreArchiveManifest{}, err
	}
	if err := ensureArchivePathStable(snapshot.original, path, manifest.SHA256); err != nil {
		return StoreArchiveManifest{}, err
	}
	return manifest, nil
}

func ensureArchivePathStable(file *os.File, path, expectedSHA256 string) error {
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, current) {
		return fmt.Errorf("archive path changed during verification")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != expectedSHA256 {
		return fmt.Errorf("archive contents changed during verification")
	}
	return nil
}

func inspectOpenedStoreArchive(ctx context.Context, file *os.File, databasePath string) (StoreArchiveManifest, error) {
	var manifest StoreArchiveManifest
	info, err := file.Stat()
	if err != nil {
		return manifest, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return manifest, fmt.Errorf("archive must be a non-empty regular file")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return manifest, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return manifest, err
	}
	databasePath = filepath.ToSlash(databasePath)
	if filepath.VolumeName(databasePath) != "" && !strings.HasPrefix(databasePath, "/") {
		databasePath = "/" + databasePath
	}
	uri := &url.URL{Scheme: "file", Path: databasePath, RawQuery: "mode=ro&immutable=1"}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return manifest, err
	}
	defer db.Close()
	var check string
	if err := db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check); err != nil {
		return manifest, fmt.Errorf("archive integrity check failed: %w", err)
	}
	if check != "ok" {
		return manifest, fmt.Errorf("archive integrity check failed: %s", check)
	}
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&manifest.SchemaVersion); err != nil {
		return manifest, err
	}
	if err := db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&manifest.ApplicationID); err != nil {
		return manifest, err
	}
	if manifest.SchemaVersion != storeSchemaVersion || manifest.ApplicationID != storeApplicationID {
		return manifest, fmt.Errorf("archive has an unsupported database identity")
	}
	manifest.Capacity, err = queryStoreCapacity(ctx, db)
	if err != nil {
		return manifest, err
	}
	manifest.Version = storeArchiveVersion
	manifest.Bytes = info.Size()
	manifest.SHA256 = "sha256:" + hex.EncodeToString(hash.Sum(nil))
	return manifest, nil
}

func queryStoreCapacity(ctx context.Context, db *sql.DB) (StoreCapacity, error) {
	capacity := StoreCapacity{OperationLimit: maxProposalRecords, CommandLimit: maxMutationRecords, ReplayLimit: maxReplayRecords}
	if err := db.QueryRowContext(ctx, `SELECT count(*), coalesce(sum(json_extract(document, '$.state') = ?), 0) FROM operations`, StatePending).Scan(&capacity.Operations, &capacity.Pending); err != nil {
		return StoreCapacity{}, storeError(err)
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM commands").Scan(&capacity.Commands); err != nil {
		return StoreCapacity{}, storeError(err)
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM replay").Scan(&capacity.ReplayRecords); err != nil {
		return StoreCapacity{}, storeError(err)
	}
	return capacity, nil
}

func validateArchiveDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("archive directory must be a real directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("archive directory must be private (mode 0700)")
	}
	return nil
}

func syncRegularFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	err = file.Sync()
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func writeNewPrivateFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	remove = false
	return syncDirectory(filepath.Dir(path))
}
