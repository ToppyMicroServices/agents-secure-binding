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
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &AuditLog{file: file, path: path, maxBytes: maxBytes, size: info.Size()}, nil
}

// Write appends and syncs one event.
func (l *AuditLog) Write(event AuditEvent) error {
	if l == nil {
		return errors.New("agtp discovery peer: audit log closed")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return errors.New("agtp discovery peer: audit log closed")
	}
	event.Time = time.Now().UTC()
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if l.size+int64(len(encoded)) > l.maxBytes {
		if err := l.rotateLocked(); err != nil {
			return err
		}
	}
	if _, err := l.file.Write(encoded); err != nil {
		return err
	}
	l.size += int64(len(encoded))
	return l.file.Sync()
}

func (l *AuditLog) rotateLocked() error {
	if err := l.file.Sync(); err != nil {
		return err
	}
	if err := l.file.Close(); err != nil {
		return err
	}
	rotated := l.path + ".1"
	if err := os.Remove(rotated); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(l.path, rotated); err != nil {
		return err
	}
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	l.file = file
	l.size = 0
	return nil
}

// Close flushes the audit file.
func (l *AuditLog) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	if err := l.file.Sync(); err != nil {
		return err
	}
	err := l.file.Close()
	l.file = nil
	return err
}
