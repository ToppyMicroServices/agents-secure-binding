// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package llmruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	modelBundleSchema       = "asb.model-bundle/v1"
	formatGGUF              = "gguf"
	formatSafetensors       = "safetensors"
	formatPEFTLoRA          = "peft-lora"
	maxBundleJSONBytes      = 8 * 1024 * 1024
	bundleModelDirectory    = "model"
	bundleAdapterDirectory  = "adapter"
	bundleAdapterConfigName = "adapter_config.json"
	bundleFilesMember       = "files"
	safetensorsExtension    = ".safetensors"
)

// ModelBundleConfig pins the complete model and optional adapter combination.
// RootPath contains model/ and, when declared, adapter/. Exactly one manifest
// source is required. ManifestSHA256 must come from the verifier's policy.
type ModelBundleConfig struct {
	RootPath       string
	ManifestPath   string
	ManifestCID    string
	ManifestSHA256 string
	KuboAPIURL     string
}

type bundleFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type bundleComponent struct {
	Format     string       `json:"format,omitempty"`
	Entrypoint string       `json:"entrypoint,omitempty"`
	Files      []bundleFile `json:"files"`
}

type modelBundleManifest struct {
	Schema  string           `json:"schema"`
	Format  string           `json:"format"`
	Model   bundleComponent  `json:"model"`
	Adapter *bundleComponent `json:"adapter,omitempty"`
}

// PreparedModelBundle owns private, verified file copies. Its paths must only
// be used while the bundle is open. The manifest digest approves the base and
// adapter as one combination; an adapter cannot be selected independently.
// This does not protect against the OS or another process with the same UID.
type PreparedModelBundle struct {
	dir       string
	manifest  modelBundleManifest
	digest    string
	closeOnce sync.Once
	closeErr  error
}

func (b *PreparedModelBundle) Format() string         { return b.manifest.Format }
func (b *PreparedModelBundle) Directory() string      { return b.dir }
func (b *PreparedModelBundle) ManifestSHA256() string { return b.digest }
func (b *PreparedModelBundle) HasAdapter() bool       { return b.manifest.Adapter != nil }
func (b *PreparedModelBundle) ModelPath() string {
	return filepath.Join(b.dir, bundleModelDirectory, filepath.FromSlash(b.manifest.Model.Entrypoint))
}

func (b *PreparedModelBundle) AdapterPath() string {
	if b.manifest.Adapter == nil {
		return ""
	}
	return filepath.Join(b.dir, bundleAdapterDirectory, filepath.FromSlash(b.manifest.Adapter.Entrypoint))
}

func (b *PreparedModelBundle) Close() error {
	if b == nil {
		return nil
	}
	b.closeOnce.Do(func() { b.closeErr = os.RemoveAll(b.dir) })
	return b.closeErr
}

// PrepareModelBundle validates a pinned manifest, copies only its declared
// files while hashing them, and validates the copied load configuration.
// No model runtime starts until this operation succeeds.
func PrepareModelBundle(ctx context.Context, config ModelBundleConfig) (*PreparedModelBundle, error) {
	if ctx == nil || ctx.Err() != nil || !validAbsolutePath(config.RootPath) ||
		!validSHA256(config.ManifestSHA256) || (config.ManifestPath == "") == (config.ManifestCID == "") {
		return nil, fmt.Errorf("%w: model bundle policy", ErrInvalidConfig)
	}
	var raw []byte
	var err error
	if config.ManifestCID != "" {
		raw, err = fetchPinnedManifest(ctx, config.ManifestCID, config.ManifestSHA256, config.KuboAPIURL)
	} else {
		raw, err = readLocalBundleManifest(config.ManifestPath)
	}
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(digest[:]) != config.ManifestSHA256 {
		return nil, ErrDigestMismatch
	}
	manifest, err := parseModelBundle(raw)
	if err != nil {
		return nil, err
	}
	root, err := openBundleRoot(config.RootPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	dir, err := os.MkdirTemp("", "asb-model-bundle-")
	if err != nil {
		return nil, fmt.Errorf("%w: private bundle directory", ErrInvalidConfig)
	}
	bundle := &PreparedModelBundle{dir: dir, manifest: manifest, digest: config.ManifestSHA256}
	keep := false
	defer func() {
		if !keep {
			_ = bundle.Close()
		}
	}()
	if err := copyBundleComponent(ctx, root, dir, bundleModelDirectory, manifest.Model); err != nil {
		return nil, err
	}
	if manifest.Adapter != nil {
		if err := copyBundleComponent(ctx, root, dir, bundleAdapterDirectory, *manifest.Adapter); err != nil {
			return nil, err
		}
	}
	if manifest.Format == formatSafetensors {
		if err := validateSafetensorsBundle(filepath.Join(dir, bundleModelDirectory), manifest.Model.Files); err != nil {
			return nil, err
		}
		if manifest.Adapter != nil {
			if err := validateLoRAConfig(filepath.Join(dir, bundleAdapterDirectory, bundleAdapterConfigName)); err != nil {
				return nil, err
			}
		}
	}
	keep = true
	return bundle, nil
}

func readLocalBundleManifest(filename string) ([]byte, error) {
	if !validAbsolutePath(filename) {
		return nil, fmt.Errorf("%w: absolute manifest path", ErrInvalidConfig)
	}
	root, err := openBundleRoot(filepath.Dir(filename))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := openBundleFile(root, filepath.Base(filename))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxGGUFManifestBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxGGUFManifestBytes {
		return nil, ErrInvalidManifest
	}
	return raw, nil
}

func parseModelBundle(raw []byte) (modelBundleManifest, error) {
	var manifest modelBundleManifest
	if len(raw) == 0 || len(raw) > maxGGUFManifestBytes || !utf8.Valid(raw) {
		return manifest, ErrInvalidManifest
	}
	if err := bundleJSON(raw, &manifest); err != nil {
		return manifest, err
	}
	object, err := bundleObject(raw, "schema", "format", bundleModelDirectory, bundleAdapterDirectory)
	if err != nil || object["schema"] == nil || object["format"] == nil || object[bundleModelDirectory] == nil ||
		manifest.Schema != modelBundleSchema || (manifest.Format != formatGGUF && manifest.Format != formatSafetensors) {
		return manifest, ErrInvalidManifest
	}
	if err := validateBundleComponent(object[bundleModelDirectory], manifest.Model, manifest.Format, false); err != nil {
		return manifest, err
	}
	if adapter, exists := object[bundleAdapterDirectory]; exists {
		if manifest.Adapter == nil {
			return manifest, ErrInvalidManifest
		}
		expected := formatPEFTLoRA
		if manifest.Format == formatGGUF {
			expected = formatGGUF
		}
		if manifest.Adapter.Format != expected {
			return manifest, ErrInvalidManifest
		}
		if err := validateBundleComponent(adapter, *manifest.Adapter, expected, true); err != nil {
			return manifest, err
		}
	}
	return manifest, nil
}

func validateBundleComponent(raw []byte, component bundleComponent, format string, adapter bool) error {
	keys := []string{"entrypoint", bundleFilesMember}
	if adapter {
		keys = append(keys, "format")
	}
	object, err := bundleObject(raw, keys...)
	if err != nil || object[bundleFilesMember] == nil || len(component.Files) == 0 || len(component.Files) > 512 {
		return ErrInvalidManifest
	}
	var files []json.RawMessage
	if json.Unmarshal(object[bundleFilesMember], &files) != nil || len(files) != len(component.Files) {
		return ErrInvalidManifest
	}
	seen := make(map[string]bool)
	spellings := make(map[string]string)
	for i, file := range component.Files {
		members, err := bundleObject(files[i], "path", "sha256", "size")
		if err != nil || len(members) != 3 || !validBundlePath(file.Path) || !validSHA256(file.SHA256) || file.Size < 1 || file.Size == 1<<63-1 {
			return ErrInvalidManifest
		}
		folded := strings.ToLower(file.Path)
		if seen[folded] {
			return ErrInvalidManifest
		}
		segments := strings.Split(file.Path, "/")
		for end := 1; end <= len(segments); end++ {
			prefix := strings.Join(segments[:end], "/")
			key := strings.ToLower(prefix)
			if previous, exists := spellings[key]; exists && previous != prefix {
				return ErrInvalidManifest
			}
			spellings[key] = prefix
		}
		for existing := range seen {
			if strings.HasPrefix(existing, folded+"/") || strings.HasPrefix(folded, existing+"/") {
				return ErrInvalidManifest
			}
		}
		seen[folded] = true
		if format != formatGGUF && !allowedBundleExtension(file.Path) {
			return ErrInvalidManifest
		}
	}
	if format == formatGGUF {
		if !validGGUFPath(component.Entrypoint) || len(component.Files) != 1 || component.Files[0].Path != component.Entrypoint {
			return ErrInvalidManifest
		}
		return nil
	}
	if component.Entrypoint != "" {
		return ErrInvalidManifest
	}
	if format == formatPEFTLoRA {
		if !hasBundleFile(component.Files, bundleAdapterConfigName) || !hasBundleFile(component.Files, "adapter_model.safetensors") {
			return ErrInvalidManifest
		}
		for _, file := range component.Files {
			if strings.HasSuffix(file.Path, safetensorsExtension) && file.Path != "adapter_model.safetensors" {
				return ErrInvalidManifest
			}
		}
	} else if hasBundleFile(component.Files, bundleAdapterConfigName) || !hasBundleFile(component.Files, "config.json") ||
		hasBundleFile(component.Files, "model.safetensors") == hasBundleFile(component.Files, "model.safetensors.index.json") {
		return ErrInvalidManifest
	}
	return nil
}

func validBundlePath(value string) bool {
	if value == "" || len(value) > 1024 || path.Clean(value) != value || strings.HasPrefix(value, "/") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if !validHFSegment(segment) {
			return false
		}
	}
	return true
}

func allowedBundleExtension(filename string) bool {
	switch path.Ext(filename) {
	case safetensorsExtension, ".json", ".model", ".txt", ".tiktoken", ".jinja":
		return true
	default:
		return false
	}
}

func hasBundleFile(files []bundleFile, name string) bool {
	for _, file := range files {
		if file.Path == name {
			return true
		}
	}
	return false
}

func bundleJSON(raw []byte, destination any) error {
	if !utf8.Valid(raw) {
		return ErrInvalidManifest
	}
	checker := json.NewDecoder(bytes.NewReader(raw))
	checker.UseNumber()
	if err := scanJSONValue(checker, false); err != nil {
		return ErrInvalidManifest
	}
	if err := requireJSONEOF(checker); err != nil {
		return ErrInvalidManifest
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidManifest
	}
	return nil
}

func bundleObject(raw []byte, allowed ...string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return nil, ErrInvalidManifest
	}
	for key := range object {
		found := false
		for _, name := range allowed {
			if key == name {
				found = true
				break
			}
		}
		if !found {
			return nil, ErrInvalidManifest
		}
	}
	return object, nil
}

// Open every directory relative to the previous directory descriptor. A
// renamed source directory cannot redirect subsequent traversal. Symlinks are
// rejected, and opened objects must be the same objects observed by Lstat.
func openBundleRoot(filename string) (*os.Root, error) {
	if !validAbsolutePath(filename) {
		return nil, ErrInvalidConfig
	}
	volume := filepath.VolumeName(filename)
	root, err := os.OpenRoot(volume + string(filepath.Separator))
	if err != nil {
		return nil, ErrInvalidConfig
	}
	for _, segment := range strings.Split(strings.TrimPrefix(filename, volume+string(filepath.Separator)), string(filepath.Separator)) {
		if segment == "" {
			continue
		}
		next, err := openBundleDirectory(root, segment)
		_ = root.Close()
		if err != nil {
			return nil, err
		}
		root = next
	}
	return root, nil
}

func openBundleDirectory(root *os.Root, name string) (*os.Root, error) {
	before, err := root.Lstat(name)
	if err != nil || !before.IsDir() {
		return nil, fmt.Errorf("%w: bundle directory must not be a symlink", ErrInvalidConfig)
	}
	child, err := root.OpenRoot(name)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	after, err := child.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		_ = child.Close()
		return nil, ErrInvalidConfig
	}
	return child, nil
}

func openBundleFile(root *os.Root, filename string) (*os.File, error) {
	parts := strings.Split(filename, "/")
	parent := root
	var owned *os.Root
	defer func() {
		if owned != nil {
			_ = owned.Close()
		}
	}()
	for _, segment := range parts[:len(parts)-1] {
		next, err := openBundleDirectory(parent, segment)
		if err != nil {
			return nil, err
		}
		if owned != nil {
			_ = owned.Close()
		}
		parent, owned = next, next
	}
	name := parts[len(parts)-1]
	before, err := parent.Lstat(name)
	if err != nil || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: bundle file must be regular and not a symlink", ErrInvalidConfig)
	}
	file, err := parent.Open(name)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, ErrInvalidConfig
	}
	return file, nil
}

func copyBundleComponent(ctx context.Context, root *os.Root, destination, prefix string, component bundleComponent) error {
	for _, entry := range component.Files {
		if err := ctx.Err(); err != nil {
			return err
		}
		source, err := openBundleFile(root, prefix+"/"+entry.Path)
		if err != nil {
			return err
		}
		err = copyBundleFile(ctx, source, filepath.Join(destination, prefix, filepath.FromSlash(entry.Path)), entry)
		_ = source.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

type bundleContextReader struct {
	context context.Context
	reader  io.Reader
}

func (r bundleContextReader) Read(buffer []byte) (int, error) {
	if err := r.context.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

func copyBundleFile(ctx context.Context, source *os.File, filename string, entry bundleFile) error {
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		return ErrInvalidConfig
	}
	destination, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrInvalidConfig
	}
	hasher := sha256.New()
	copied, copyErr := io.Copy(io.MultiWriter(destination, hasher), io.LimitReader(bundleContextReader{ctx, source}, entry.Size+1))
	closeErr := destination.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if copied != entry.Size || "sha256:"+hex.EncodeToString(hasher.Sum(nil)) != entry.SHA256 {
		return ErrDigestMismatch
	}
	if err := os.Chmod(filename, 0o400); err != nil {
		return ErrInvalidConfig
	}
	return nil
}

func readBundleJSON(filename string, destination any) error {
	file, err := os.Open(filename)
	if err != nil {
		return ErrInvalidManifest
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxBundleJSONBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxBundleJSONBytes {
		return ErrInvalidManifest
	}
	return bundleJSON(raw, destination)
}

func validateSafetensorsBundle(directory string, files []bundleFile) error {
	var config map[string]json.RawMessage
	if err := readBundleJSON(filepath.Join(directory, "config.json"), &config); err != nil || config == nil {
		return ErrInvalidManifest
	}
	shards := make(map[string]bool)
	for _, file := range files {
		if strings.HasSuffix(file.Path, safetensorsExtension) {
			shards[file.Path] = true
		}
	}
	if hasBundleFile(files, "model.safetensors") {
		if len(shards) != 1 {
			return ErrInvalidManifest
		}
		return nil
	}
	var index map[string]json.RawMessage
	if err := readBundleJSON(filepath.Join(directory, "model.safetensors.index.json"), &index); err != nil {
		return ErrInvalidManifest
	}
	var weightMap map[string]string
	if json.Unmarshal(index["weight_map"], &weightMap) != nil || len(weightMap) == 0 {
		return ErrInvalidManifest
	}
	referenced := make(map[string]bool)
	for tensor, shard := range weightMap {
		if tensor == "" || !validBundlePath(shard) || !shards[shard] {
			return ErrInvalidManifest
		}
		referenced[shard] = true
	}
	if len(referenced) != len(shards) {
		return ErrInvalidManifest
	}
	return nil
}

func validateLoRAConfig(filename string) error {
	var config map[string]json.RawMessage
	if err := readBundleJSON(filename, &config); err != nil || config == nil {
		return ErrInvalidManifest
	}
	var peftType string
	if json.Unmarshal(config["peft_type"], &peftType) != nil || peftType != "LORA" {
		return ErrInvalidManifest
	}
	return nil
}
