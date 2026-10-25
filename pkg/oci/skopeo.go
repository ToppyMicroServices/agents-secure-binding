// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// OCICryptKeyproviderConfig is the environment variable for ocicrypt config.
	OCICryptKeyproviderConfig = "OCICRYPT_KEYPROVIDER_CONFIG"

	// DefaultOCICryptConfig is the default path to ocicrypt config.
	DefaultOCICryptConfig = "/etc/ocicrypt_keyprovider.conf"

	// DecryptionKeyProvider is the decryption key provider for CoCo.
	DecryptionKeyProvider = "provider:attestation-agent:cc_kbc::null"

	maxSkopeoOutputBytes = 4 << 20
	skopeoWaitDelay      = time.Second
)

var errSkopeoOutputLimit = errors.New("skopeo command output limit exceeded")

// SkopeoClient wraps skopeo command-line operations.
type SkopeoClient struct {
	skopeoPath string
	workDir    string
}

// NewSkopeoClient creates a new Skopeo client.
func NewSkopeoClient(workDir string) (*SkopeoClient, error) {
	skopeoPath, err := exec.LookPath("skopeo")
	if err != nil {
		return nil, fmt.Errorf("skopeo not found in PATH: %w", err)
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create work directory: %w", err)
	}
	if err := os.Chmod(workDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to restrict work directory: %w", err)
	}
	return &SkopeoClient{skopeoPath: skopeoPath, workDir: workDir}, nil
}

// PullAndDecrypt pulls an OCI image and decrypts it if encrypted.
func (s *SkopeoClient) PullAndDecrypt(ctx context.Context, source ResourceSource, destDir string) error {
	if source.URI == "" {
		return fmt.Errorf("oci source URI is empty")
	}
	if destDir == "" {
		return fmt.Errorf("oci destination directory is empty")
	}
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}
	return s.run(ctx, "skopeo copy failed", s.pullAndDecryptArgs(source, destDir))
}

func (s *SkopeoClient) pullAndDecryptArgs(source ResourceSource, destDir string) []string {
	args := []string{"copy"}
	if source.Encrypted {
		args = append(args, "--decryption-key", DecryptionKeyProvider)
	}
	return append(args, source.URI, "oci:"+destDir)
}

// Inspect inspects an OCI image and returns basic manifest information.
func (s *SkopeoClient) Inspect(ctx context.Context, imageRef string) (*ImageManifest, error) {
	if imageRef == "" {
		return nil, fmt.Errorf("oci image reference is empty")
	}

	output, err := s.output(ctx, "skopeo inspect failed", s.inspectArgs(imageRef))
	if err != nil {
		return nil, err
	}

	manifest := &ImageManifest{Reference: imageRef}
	var inspect struct {
		Digest string   `json:"Digest"`
		Layers []string `json:"Layers"`
	}
	if err := json.Unmarshal(output, &inspect); err == nil {
		manifest.Digest = inspect.Digest
		manifest.Layers = append([]string(nil), inspect.Layers...)
	}
	return manifest, nil
}

func (s *SkopeoClient) inspectArgs(imageRef string) []string {
	return []string{"inspect", imageRef}
}

// ToDockerArchive converts an OCI directory to a Docker archive tarball.
func (s *SkopeoClient) ToDockerArchive(ctx context.Context, ociDir, destFile string) error {
	if ociDir == "" {
		return fmt.Errorf("oci directory is empty")
	}
	if destFile == "" {
		return fmt.Errorf("docker archive destination is empty")
	}
	return s.run(ctx, "skopeo copy to docker-archive failed", s.toDockerArchiveArgs(ociDir, destFile))
}

func (s *SkopeoClient) toDockerArchiveArgs(ociDir, destFile string) []string {
	return []string{"copy", "oci:" + ociDir, "docker-archive:" + destFile}
}

// GetLocalImagePath returns the path to a local OCI image directory.
func (s *SkopeoClient) GetLocalImagePath(name string) string {
	return filepath.Join(s.workDir, name)
}

func (s *SkopeoClient) run(ctx context.Context, prefix string, args []string) error {
	_, err := s.output(ctx, prefix, args)
	return err
}

func (s *SkopeoClient) output(ctx context.Context, prefix string, args []string) ([]byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.skopeoPath, args...)
	cmd.Env = skopeoEnv()
	cmd.Dir = s.workDir
	// Bound pipe draining if a descendant retains the command's descriptors.
	// This bounds waiting; it does not terminate those descendants.
	cmd.WaitDelay = skopeoWaitDelay
	output := &skopeoOutput{cancel: cancel}
	cmd.Stdout = output
	cmd.Stderr = output

	err := cmd.Run()
	if output.exceeded {
		err = errSkopeoOutputLimit
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w\nOutput: %s", prefix, err, output.buffer.String())
	}
	return output.buffer.Bytes(), nil
}

// os/exec serializes writes when stdout and stderr share this writer.
type skopeoOutput struct {
	buffer   bytes.Buffer
	cancel   context.CancelFunc
	exceeded bool
}

func (o *skopeoOutput) Write(p []byte) (int, error) {
	remaining := maxSkopeoOutputBytes - o.buffer.Len()
	if len(p) > remaining {
		n, _ := o.buffer.Write(p[:remaining])
		o.exceeded = true
		o.cancel()
		return n, errSkopeoOutputLimit
	}
	return o.buffer.Write(p)
}

func skopeoEnv() []string {
	env := os.Environ()
	for _, value := range env {
		if strings.HasPrefix(value, OCICryptKeyproviderConfig+"=") {
			return env
		}
	}
	return append(env, OCICryptKeyproviderConfig+"="+DefaultOCICryptConfig)
}
