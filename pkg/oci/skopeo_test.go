// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSkopeoClient(t *testing.T) {
	t.Run("valid work directory", func(t *testing.T) {
		workDir := t.TempDir()
		client, err := NewSkopeoClient(workDir)
		if err != nil && err.Error() == "skopeo not found in PATH: exec: \"skopeo\": executable file not found in $PATH" {
			t.Skip("skopeo not installed, skipping test")
		}
		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("new work directory", func(t *testing.T) {
		workDir := filepath.Join(t.TempDir(), "new", "nested", "dir")
		client, err := NewSkopeoClient(workDir)
		if err != nil && err.Error() == "skopeo not found in PATH: exec: \"skopeo\": executable file not found in $PATH" {
			t.Skip("skopeo not installed, skipping test")
		}
		require.NoError(t, err)
		assert.NotNil(t, client)
	})
}

func TestSkopeoClient_GetLocalImagePath(t *testing.T) {
	workDir := t.TempDir()
	client, err := NewSkopeoClient(workDir)
	if err != nil {
		t.Skip("skopeo not installed, skipping test")
	}

	tests := []struct {
		name     string
		imgName  string
		expected string
	}{
		{"simple image name", "myimage", filepath.Join(workDir, "myimage")},
		{"image with tag", "myimage:latest", filepath.Join(workDir, "myimage:latest")},
		{"nested path", "registry/repo/image", filepath.Join(workDir, "registry/repo/image")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := client.GetLocalImagePath(tt.imgName)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestSkopeoClient_PullAndDecrypt(t *testing.T) {
	workDir := t.TempDir()
	client, err := NewSkopeoClient(workDir)
	if err != nil {
		t.Skip("skopeo not installed, skipping test")
	}

	t.Run("invalid source URI", func(t *testing.T) {
		ctx := context.Background()
		destDir := t.TempDir()
		source := ResourceSource{
			Type:      ResourceTypeOCIImage,
			URI:       "invalid://not-a-valid-uri",
			Encrypted: false,
		}
		err := client.PullAndDecrypt(ctx, source, destDir)
		assert.Error(t, err)
	})

	t.Run("destination directory created", func(t *testing.T) {
		ctx := context.Background()
		destDir := filepath.Join(t.TempDir(), "new", "nested", "dest")
		source := ResourceSource{
			Type:      ResourceTypeOCIImage,
			URI:       "invalid://test",
			Encrypted: false,
		}
		_ = client.PullAndDecrypt(ctx, source, destDir)
		_, err := os.Stat(destDir)
		assert.NoError(t, err)
	})
}

func TestSkopeoClient_Inspect(t *testing.T) {
	workDir := t.TempDir()
	client, err := NewSkopeoClient(workDir)
	if err != nil {
		t.Skip("skopeo not installed, skipping test")
	}

	t.Run("invalid image reference", func(t *testing.T) {
		ctx := context.Background()
		manifest, err := client.Inspect(ctx, "invalid://not-a-valid-ref")
		assert.Error(t, err)
		assert.Nil(t, manifest)
	})
}

func TestResourceSource(t *testing.T) {
	t.Run("ResourceType constants", func(t *testing.T) {
		assert.Equal(t, ResourceType("oci-image"), ResourceTypeOCIImage)
	})

	t.Run("ResourceSource structure", func(t *testing.T) {
		source := ResourceSource{
			Type:            ResourceTypeOCIImage,
			URI:             "docker://registry/repo:tag",
			Encrypted:       true,
			KBSResourcePath: "default/key/algo-key",
		}
		assert.Equal(t, ResourceTypeOCIImage, source.Type)
		assert.Equal(t, "docker://registry/repo:tag", source.URI)
		assert.True(t, source.Encrypted)
		assert.Equal(t, "default/key/algo-key", source.KBSResourcePath)
	})
}

func TestImageManifest(t *testing.T) {
	t.Run("ImageManifest structure", func(t *testing.T) {
		manifest := ImageManifest{
			Reference: "docker://registry/repo:tag",
			Digest:    "sha256:abc123",
			Layers:    []string{"sha256:layer1", "sha256:layer2"},
		}
		assert.Equal(t, "docker://registry/repo:tag", manifest.Reference)
		assert.Equal(t, "sha256:abc123", manifest.Digest)
		assert.Len(t, manifest.Layers, 2)
	})
}

func TestSkopeoConstants(t *testing.T) {
	assert.Equal(t, "OCICRYPT_KEYPROVIDER_CONFIG", OCICryptKeyproviderConfig)
	assert.Equal(t, "/etc/ocicrypt_keyprovider.conf", DefaultOCICryptConfig)
	assert.Equal(t, "provider:attestation-agent:cc_kbc::null", DecryptionKeyProvider)
}

func TestNewSkopeoClientUnwritableDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("cannot test unwritable dir as root")
	}

	// Create a file where a directory is expected
	tmpDir := t.TempDir()
	blockingFile := filepath.Join(tmpDir, "blocking")
	require.NoError(t, os.WriteFile(blockingFile, []byte("data"), 0o444))

	// Try to create a client with workDir inside a file (not a dir)
	_, err := NewSkopeoClient(filepath.Join(blockingFile, "subdir"))
	assert.Error(t, err)
}

func TestSkopeoClientPullAndDecryptEncrypted(t *testing.T) {
	workDir := t.TempDir()
	client, err := NewSkopeoClient(workDir)
	if err != nil {
		t.Skip("skopeo not installed, skipping test")
	}

	t.Run("encrypted image uses decryption key flag", func(t *testing.T) {
		ctx := context.Background()
		destDir := t.TempDir()
		// Encrypted source - skopeo call will fail but the --decryption-key arg is built
		source := ResourceSource{
			Type:      ResourceTypeOCIImage,
			URI:       "docker://invalid.registry/nonexistent:latest",
			Encrypted: true,
		}
		err := client.PullAndDecrypt(ctx, source, destDir)
		// We expect an error (no such image) but the encrypted code path was exercised
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "skopeo copy failed")
	})
}

func TestSkopeoClient_ToDockerArchive(t *testing.T) {
	workDir := t.TempDir()
	client, err := NewSkopeoClient(workDir)
	if err != nil {
		t.Skip("skopeo not installed, skipping test")
	}

	t.Run("invalid oci directory", func(t *testing.T) {
		ctx := context.Background()
		destFile := filepath.Join(t.TempDir(), "archive.tar")
		err := client.ToDockerArchive(ctx, "/non/existent/oci/dir", destFile)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "skopeo copy to docker-archive failed")
	})
}

func TestSkopeoClientArgsDoNotDisablePolicyOrTLS(t *testing.T) {
	client := &SkopeoClient{skopeoPath: "skopeo", workDir: t.TempDir()}

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "pull",
			args: client.pullAndDecryptArgs(ResourceSource{
				URI:       "docker://registry.example/repo:tag",
				Encrypted: false,
			}, "/tmp/oci"),
		},
		{
			name: "encrypted pull",
			args: client.pullAndDecryptArgs(ResourceSource{
				URI:       "docker://registry.example/repo:tag",
				Encrypted: true,
			}, "/tmp/oci"),
		},
		{name: "inspect", args: client.inspectArgs("docker://registry.example/repo:tag")},
		{name: "archive", args: client.toDockerArchiveArgs("/tmp/oci", "/tmp/archive.tar")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			joined := strings.Join(tt.args, " ")
			assert.NotContains(t, joined, "--insecure-policy")
			assert.NotContains(t, joined, "--tls-verify=false")
			assert.NotContains(t, joined, "--src-tls-verify=false")
			assert.NotContains(t, joined, "--dest-tls-verify=false")
		})
	}

	encryptedArgs := client.pullAndDecryptArgs(ResourceSource{
		URI:       "docker://registry.example/repo:tag",
		Encrypted: true,
	}, "/tmp/oci")
	assert.Contains(t, encryptedArgs, "--decryption-key")
	assert.Contains(t, encryptedArgs, DecryptionKeyProvider)
}

func skopeoHelperArgs(args ...string) []string {
	return append([]string{"-test.run=^TestSkopeoOutputHelperProcess$", "--"}, args...)
}

func TestSkopeoClientBoundedOutput(t *testing.T) {
	t.Setenv("ASB_SKOPEO_TEST_HELPER", "1")
	client := &SkopeoClient{skopeoPath: os.Args[0], workDir: t.TempDir()}
	t.Run("ordinary stdout and stderr", func(t *testing.T) {
		output, err := client.output(context.Background(), "skopeo copy failed", skopeoHelperArgs("ordinary"))
		require.NoError(t, err)
		require.Equal(t, "stdout\nstderr\n", string(output))
	})
	t.Run("ordinary failure preserves diagnostics", func(t *testing.T) {
		output, err := client.output(context.Background(), "skopeo copy failed", skopeoHelperArgs("failure"))
		require.ErrorContains(t, err, "skopeo copy failed")
		require.ErrorContains(t, err, "Output: stdout\nstderr\n")
		require.Nil(t, output)
	})
	t.Run("exact combined output limit succeeds", func(t *testing.T) {
		output, err := client.output(context.Background(), "skopeo copy failed", skopeoHelperArgs("exact"))
		require.NoError(t, err)
		require.Len(t, output, maxSkopeoOutputBytes)
	})
	t.Run("overflow cancels instead of returning truncated success", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		start := time.Now()
		output, err := client.output(ctx, "skopeo copy failed", skopeoHelperArgs("overflow"))
		require.ErrorIs(t, err, errSkopeoOutputLimit)
		require.ErrorContains(t, err, "skopeo copy failed")
		require.Nil(t, output)
		require.Less(t, len(err.Error()), maxSkopeoOutputBytes+256)
		require.Less(t, time.Since(start), 3*time.Second, "overflow must cancel the blocked helper")
		require.NoError(t, ctx.Err(), "the caller deadline must not be needed to stop output overflow")
	})
}

func TestSkopeoClientCancellationBoundsInheritedPipeDrain(t *testing.T) {
	t.Setenv("ASB_SKOPEO_TEST_HELPER", "1")
	dir := t.TempDir()
	ready := filepath.Join(dir, "child-ready")
	release := filepath.Join(dir, "release-child")
	done := filepath.Join(dir, "child-done")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		// This fixture owns its descendant and releases it independently of
		// the wrapper's pipe-drain timeout.
		require.NoError(t, os.WriteFile(release, nil, 0o600))
		require.Eventually(t, func() bool {
			_, err := os.Stat(done)
			return err == nil
		}, 3*time.Second, 10*time.Millisecond, "fixture descendant did not acknowledge cleanup")
	})
	client := &SkopeoClient{skopeoPath: os.Args[0], workDir: dir}
	finished := make(chan error, 1)
	go func() {
		_, err := client.output(ctx, "skopeo copy failed", skopeoHelperArgs("spawn", ready, release, done))
		finished <- err
	}()
	require.Eventually(t, func() bool {
		_, err := os.Stat(ready)
		return err == nil
	}, 3*time.Second, 10*time.Millisecond)
	cancel()
	select {
	case err := <-finished:
		require.ErrorContains(t, err, "skopeo copy failed")
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation waited for the descendant to close inherited output pipes")
	}
	_, err := os.Stat(done)
	require.True(t, os.IsNotExist(err), "pipe draining must finish while the fixture child still holds its descriptors")
}

func TestSkopeoOutputHelperProcess(t *testing.T) {
	if os.Getenv("ASB_SKOPEO_TEST_HELPER") != "1" {
		return
	}
	separator := slices.Index(os.Args, "--")
	require.GreaterOrEqual(t, separator, 0)
	args := os.Args[separator+1:]
	require.NotEmpty(t, args)
	switch args[0] {
	case "ordinary", "failure":
		_, err := os.Stdout.WriteString("stdout\n")
		require.NoError(t, err)
		_, err = os.Stderr.WriteString("stderr\n")
		require.NoError(t, err)
		if args[0] == "failure" {
			os.Exit(7)
		}
	case "exact", "overflow":
		data := bytes.Repeat([]byte{'x'}, maxSkopeoOutputBytes/2)
		_, err := os.Stdout.Write(data)
		require.NoError(t, err)
		_, err = os.Stderr.Write(data)
		require.NoError(t, err)
		if args[0] == "overflow" {
			_, err = os.Stderr.WriteString("x")
			require.NoError(t, err)
			time.Sleep(30 * time.Second)
		}
	case "spawn":
		require.Len(t, args, 4)
		child := exec.Command(os.Args[0], skopeoHelperArgs("hold", args[1], args[2], args[3])...)
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		require.NoError(t, child.Start())
		time.Sleep(30 * time.Second)
	case "hold":
		require.Len(t, args, 4)
		require.NoError(t, os.WriteFile(args[1], nil, 0o600))
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(args[2]); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		require.NoError(t, os.WriteFile(args[3], nil, 0o600))
	default:
		t.Fatalf("unknown helper mode %q", args[0])
	}
	os.Exit(0)
}
