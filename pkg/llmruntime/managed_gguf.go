// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package llmruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	managedModelAlias     = "asb-verified-model"
	managedStartupTimeout = 5 * time.Minute
)

// ErrDigestMismatch means the bytes copied for a model or server executable
// do not match the digest supplied by the caller.
var ErrDigestMismatch = errors.New("llm runtime: digest mismatch")

// ManagedGGUFConfig pins a single local GGUF model and a llama-server binary.
// Both digests must be trusted, canonical sha256:<64 lowercase hex> values.
// ModelPath and ServerPath must name absolute, regular, non-symlink files.
// The server executable is copied before launch, so its runtime libraries
// must remain resolvable from the private copy's location.
type ManagedGGUFConfig struct {
	ModelPath   string
	ModelSHA256 string
	// ModelSize, when positive, is the expected byte length of the GGUF.
	ModelSize    int64
	ServerPath   string
	ServerSHA256 string
}

// ManagedGGUF owns a verified copy of the model and server executable, and
// reaches the server only through a private Unix socket. Close releases both.
// This pins file bytes; it does not attest the operating system, dynamic
// libraries, or another process running with the same user identity.
type ManagedGGUF struct {
	generator *openAICompatible
	server    *exec.Cmd
	wait      chan error
	dir       string
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

var _ Generator = (*ManagedGGUF)(nil)

// NewManagedGGUF verifies both files before starting a single-model
// llama-server. The supplied context controls startup and the server lifetime.
func NewManagedGGUF(ctx context.Context, config ManagedGGUFConfig) (*ManagedGGUF, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, fmt.Errorf("%w: context", ErrInvalidConfig)
	}
	if !validSHA256(config.ModelSHA256) || !validSHA256(config.ServerSHA256) {
		return nil, fmt.Errorf("%w: expected SHA-256", ErrInvalidConfig)
	}
	if config.ModelSize < 0 || config.ModelSize == 1<<63-1 {
		return nil, fmt.Errorf("%w: expected model size", ErrInvalidConfig)
	}
	if !validAbsolutePath(config.ModelPath) || !validAbsolutePath(config.ServerPath) {
		return nil, fmt.Errorf("%w: absolute model and server paths required", ErrInvalidConfig)
	}
	dir, err := os.MkdirTemp("", "asb-llm-")
	if err != nil {
		return nil, fmt.Errorf("%w: create private directory", ErrInvalidConfig)
	}
	keepDir := false
	defer func() {
		if !keepDir {
			_ = os.RemoveAll(dir)
		}
	}()
	modelPath := filepath.Join(dir, "model.gguf")
	serverPath := filepath.Join(dir, "llama-server")
	if err := copyVerifiedFile(config.ModelPath, modelPath, config.ModelSHA256, config.ModelSize, false); err != nil {
		return nil, err
	}
	if err := copyVerifiedFile(config.ServerPath, serverPath, config.ServerSHA256, 0, true); err != nil {
		return nil, err
	}
	socketPath := filepath.Join(dir, "llama.sock")
	if len(socketPath) > 100 {
		return nil, fmt.Errorf("%w: Unix socket path too long", ErrInvalidConfig)
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}
	client := &http.Client{
		Timeout:       requestTimeout,
		Transport:     transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errRedirect },
	}
	endpoint := &url.URL{Scheme: "http", Host: "asb-managed.invalid", Path: "/v1/chat/completions"}
	generator := &openAICompatible{endpoint: endpoint, model: managedModelAlias, client: client}
	command := exec.CommandContext(ctx, serverPath,
		"--model", modelPath,
		"--alias", managedModelAlias,
		"--host", socketPath,
		"--no-webui")
	command.Dir = dir
	// The server needs no inherited environment. In particular, dynamic-loader
	// and llama.cpp variables must not change the code or model it loads.
	command.Env = []string{}
	if err := command.Start(); err != nil {
		transport.CloseIdleConnections()
		return nil, fmt.Errorf("%w: start verified server", ErrProvider)
	}
	wait := make(chan error, 1)
	go func() {
		wait <- command.Wait()
		close(wait)
	}()
	managed := &ManagedGGUF{generator: generator, server: command, wait: wait, dir: dir}
	if err := awaitManagedReady(ctx, client, wait); err != nil {
		_ = managed.Close()
		return nil, err
	}
	keepDir = true
	return managed, nil
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validAbsolutePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsRune(path, 0)
}

func copyVerifiedFile(sourcePath, destinationPath, expected string, expectedSize int64, executable bool) error {
	before, err := os.Lstat(sourcePath)
	if err != nil || !before.Mode().IsRegular() {
		return fmt.Errorf("%w: source must be a regular non-symlink file", ErrInvalidConfig)
	}
	if executable && before.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%w: server file is not executable", ErrInvalidConfig)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("%w: open source file", ErrInvalidConfig)
	}
	defer source.Close()
	after, err := source.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return fmt.Errorf("%w: source file changed", ErrInvalidConfig)
	}
	destination, err := os.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("%w: create private file", ErrInvalidConfig)
	}
	hasher := sha256.New()
	var reader io.Reader = source
	if expectedSize > 0 {
		reader = io.LimitReader(source, expectedSize+1)
	}
	copied, copyErr := io.Copy(io.MultiWriter(destination, hasher), reader)
	closeErr := destination.Close()
	if copyErr != nil || closeErr != nil {
		return fmt.Errorf("%w: copy source file", ErrInvalidConfig)
	}
	if expectedSize > 0 && copied != expectedSize {
		return ErrDigestMismatch
	}
	actual := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if actual != expected {
		return ErrDigestMismatch
	}
	mode := os.FileMode(0o400)
	if executable {
		mode = 0o500
	}
	if err := os.Chmod(destinationPath, mode); err != nil {
		return fmt.Errorf("%w: protect private file", ErrInvalidConfig)
	}
	return nil
}

func awaitManagedReady(ctx context.Context, client *http.Client, wait <-chan error) error {
	startup, cancel := context.WithTimeout(ctx, managedStartupTimeout)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		request, err := http.NewRequestWithContext(startup, http.MethodGet, "http://asb-managed.invalid/health", nil)
		if err != nil {
			return fmt.Errorf("%w: create health request", ErrProvider)
		}
		response, err := client.Do(request)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-startup.Done():
			return fmt.Errorf("%w: verified server did not become ready: %v", ErrProvider, startup.Err())
		case <-wait:
			return fmt.Errorf("%w: verified server exited before ready", ErrProvider)
		case <-ticker.C:
		}
	}
}

// Generate uses only the verified, privately launched model instance.
func (g *ManagedGGUF) Generate(ctx context.Context, request Request) (Response, error) {
	if g == nil || g.closed.Load() {
		return Response{}, fmt.Errorf("%w: managed server is closed", ErrProvider)
	}
	return g.generator.Generate(ctx, request)
}

// Close stops the server and removes its private model and executable copies.
func (g *ManagedGGUF) Close() error {
	if g == nil {
		return nil
	}
	g.closeOnce.Do(func() {
		g.closed.Store(true)
		g.generator.client.Transport.(*http.Transport).CloseIdleConnections()
		_ = g.server.Process.Kill()
		<-g.wait
		g.closeErr = os.RemoveAll(g.dir)
	})
	return g.closeErr
}
