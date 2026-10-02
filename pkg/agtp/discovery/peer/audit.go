// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEvent contains metadata only; tokens and Presence payloads are never
// written to the audit log.
type AuditEvent struct {
	Time   time.Time `json:"time"`
	NodeID string    `json:"node_id"`
	PeerID string    `json:"peer_id,omitempty"`
	Action string    `json:"action"`
	Result string    `json:"result"`
	Reason string    `json:"reason,omitempty"`
}

// AuditLog is a synchronous JSONL audit sink.
type AuditLog struct {
	mu       sync.Mutex
	file     *os.File
	path     string
	maxBytes int64
	size     int64
	closed   bool
}

// NewAuditLog opens a mode-0600 append-only audit file.
func NewAuditLog(path string, maxBytes int64) (*AuditLog, error) {
	if path == "" {
		return nil, errors.New("agtp discovery peer: missing audit path")
	}
	if maxBytes < 1024 {
		return nil, errors.New("agtp discovery peer: invalid audit size limit")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	log := &AuditLog{path: path, maxBytes: maxBytes}
	if err := log.openLocked(); err != nil {
		return nil, err
	}
	return log, nil
}

func (l *AuditLog) openLocked() error {
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	l.file = file
	l.size = info.Size()
	return nil
}

// Write appends and syncs one event.
func (l *AuditLog) Write(event AuditEvent) error {
	if l == nil {
		return errors.New("agtp discovery peer: audit log closed")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("agtp discovery peer: audit log closed")
	}
	if l.file == nil {
		if err := l.openLocked(); err != nil {
			return err
		}
	}
	event.Time = time.Now().UTC()
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if int64(len(encoded)) > l.maxBytes {
		return errors.New("agtp discovery peer: audit event exceeds size limit")
	}
	if l.size+int64(len(encoded)) > l.maxBytes {
		if err := l.rotateLocked(); err != nil {
			return err
		}
	}
	written, err := l.file.Write(encoded)
	l.size += int64(written)
	if err != nil {
		return err
	}
	return l.file.Sync()
}

func (l *AuditLog) rotateLocked() error {
	if err := l.file.Sync(); err != nil {
		return err
	}
	rotated := l.path + ".1"
	if err := os.Remove(rotated); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Close before rename for platforms that cannot move an open file. A
	// failed rename reopens the active file; a failed open is retried by Write.
	err := l.file.Close()
	l.file = nil
	if err != nil {
		return err
	}
	if err := os.Rename(l.path, rotated); err != nil {
		return errors.Join(err, l.openLocked())
	}
	return l.openLocked()
}

// Close flushes the audit file.
func (l *AuditLog) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	if l.file == nil {
		return nil
	}
	// A failed flush must still release the descriptor during node shutdown.
	err := errors.Join(l.file.Sync(), l.file.Close())
	l.file = nil
	return err
}
