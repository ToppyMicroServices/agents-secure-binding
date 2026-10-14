// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package llmruntime

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	ggufManifestSchema   = "asb.huggingface-gguf/v1"
	maxGGUFManifestBytes = 64 * 1024
	manifestFetchTimeout = 30 * time.Second
)

// ErrInvalidManifest means the fetched manifest does not satisfy the pinned
// single-GGUF contract or the verifier's expected source identity.
var ErrInvalidManifest = errors.New("llm runtime: invalid pinned GGUF manifest")

// PinnedGGUFManifestConfig contains verifier-local expected values. The
// manifest SHA-256 is the trust anchor. The CID and Kubo node only locate bytes;
// neither establishes that the claimed Hugging Face source published them.
type PinnedGGUFManifestConfig struct {
	CID              string
	ManifestSHA256   string
	KuboAPIURL       string
	ExpectedRepo     string
	ExpectedRevision string
	ExpectedPath     string
}

// GGUFManifest identifies one exact GGUF artifact. ModelSHA256 can be passed
// to NewManagedGGUF, which independently hashes the copied model bytes.
type GGUFManifest struct {
	Repo        string
	Revision    string
	Path        string
	ModelSHA256 string
	Size        int64
}

// ResolvePinnedGGUFManifest fetches one small raw IPFS block from a local
// Kubo RPC endpoint, then verifies its bytes against a locally pinned digest.
// The CID is restricted to a raw CIDv1 with a full sha2-256 multihash, so its
// digest must also agree with the independently pinned manifest SHA-256.
func ResolvePinnedGGUFManifest(ctx context.Context, config PinnedGGUFManifestConfig) (GGUFManifest, error) {
	if ctx == nil || ctx.Err() != nil {
		return GGUFManifest{}, fmt.Errorf("%w: context", ErrInvalidConfig)
	}
	if !validSHA256(config.ManifestSHA256) || !validHFRepo(config.ExpectedRepo) ||
		!validHFRevision(config.ExpectedRevision) || !validGGUFPath(config.ExpectedPath) {
		return GGUFManifest{}, fmt.Errorf("%w: pinned manifest policy", ErrInvalidConfig)
	}
	cidDigest, err := rawSHA256CID(config.CID)
	if err != nil || "sha256:"+hex.EncodeToString(cidDigest[:]) != config.ManifestSHA256 {
		return GGUFManifest{}, fmt.Errorf("%w: manifest CID and digest", ErrInvalidConfig)
	}
	address, err := localKuboAddress(config.KuboAPIURL)
	if err != nil {
		return GGUFManifest{}, err
	}
	fetchCtx, cancel := context.WithTimeout(ctx, manifestFetchTimeout)
	defer cancel()
	transport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   manifestFetchTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errRedirect
		},
	}
	endpoint := "http://" + address + "/api/v0/block/get?arg=" + url.QueryEscape(config.CID)
	request, err := http.NewRequestWithContext(fetchCtx, http.MethodPost, endpoint, nil)
	if err != nil {
		return GGUFManifest{}, fmt.Errorf("%w: Kubo request", ErrInvalidConfig)
	}
	response, err := client.Do(request)
	if err != nil {
		return GGUFManifest{}, fmt.Errorf("%w: Kubo block fetch", ErrProvider)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return GGUFManifest{}, fmt.Errorf("%w: Kubo block status %d", ErrProvider, response.StatusCode)
	}
	block, err := io.ReadAll(io.LimitReader(response.Body, maxGGUFManifestBytes+1))
	if err != nil || len(block) == 0 || len(block) > maxGGUFManifestBytes {
		return GGUFManifest{}, fmt.Errorf("%w: Kubo block exceeds bounds", ErrInvalidManifest)
	}
	digest := sha256.Sum256(block)
	if "sha256:"+hex.EncodeToString(digest[:]) != config.ManifestSHA256 {
		return GGUFManifest{}, ErrDigestMismatch
	}
	manifest, err := parseGGUFManifest(block)
	if err != nil {
		return GGUFManifest{}, err
	}
	if manifest.Repo != config.ExpectedRepo || manifest.Revision != config.ExpectedRevision || manifest.Path != config.ExpectedPath {
		return GGUFManifest{}, fmt.Errorf("%w: source identity differs from policy", ErrInvalidManifest)
	}
	return manifest, nil
}

func rawSHA256CID(value string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	// CIDv1 = version 1, raw codec 0x55, sha2-256 code 0x12, length 32,
	// followed by the digest. This narrow form is 36 bytes or 59 base32 chars.
	if len(value) != 59 || value[0] != 'b' {
		return digest, ErrInvalidConfig
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '2' || character > '7') {
			return digest, ErrInvalidConfig
		}
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(value[1:]))
	if err != nil || len(decoded) != 36 || decoded[0] != 1 || decoded[1] != 0x55 || decoded[2] != 0x12 || decoded[3] != sha256.Size {
		return digest, ErrInvalidConfig
	}
	if "b"+strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(decoded)) != value {
		return digest, ErrInvalidConfig
	}
	copy(digest[:], decoded[4:])
	return digest, nil
}

func localKuboAddress(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != httpScheme || parsed.Host == "" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || strings.Contains(raw, "#") || parsed.Opaque != "" {
		return "", fmt.Errorf("%w: Kubo RPC must be a loopback HTTP origin", ErrInvalidConfig)
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	if err != nil || host != "127.0.0.1" && host != "::1" {
		return "", fmt.Errorf("%w: Kubo RPC must use a literal loopback address", ErrInvalidConfig)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 || strconv.Itoa(portNumber) != port {
		return "", fmt.Errorf("%w: Kubo RPC port", ErrInvalidConfig)
	}
	return net.JoinHostPort(host, port), nil
}

func parseGGUFManifest(block []byte) (GGUFManifest, error) {
	var manifest GGUFManifest
	decoder := json.NewDecoder(strings.NewReader(string(block)))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return manifest, ErrInvalidManifest
	}
	seen := make(map[string]bool, 6)
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return GGUFManifest{}, ErrInvalidManifest
		}
		name, ok := nameToken.(string)
		if !ok || seen[name] {
			return GGUFManifest{}, ErrInvalidManifest
		}
		seen[name] = true
		switch name {
		case "schema":
			var schema string
			if decoder.Decode(&schema) != nil || schema != ggufManifestSchema {
				return GGUFManifest{}, ErrInvalidManifest
			}
		case "repo":
			if decoder.Decode(&manifest.Repo) != nil {
				return GGUFManifest{}, ErrInvalidManifest
			}
		case "revision":
			if decoder.Decode(&manifest.Revision) != nil {
				return GGUFManifest{}, ErrInvalidManifest
			}
		case "path":
			if decoder.Decode(&manifest.Path) != nil {
				return GGUFManifest{}, ErrInvalidManifest
			}
		case "sha256":
			if decoder.Decode(&manifest.ModelSHA256) != nil {
				return GGUFManifest{}, ErrInvalidManifest
			}
		case "size":
			if decoder.Decode(&manifest.Size) != nil {
				return GGUFManifest{}, ErrInvalidManifest
			}
		default:
			return GGUFManifest{}, ErrInvalidManifest
		}
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') || len(seen) != 6 {
		return GGUFManifest{}, ErrInvalidManifest
	}
	if _, err := decoder.Token(); err != io.EOF {
		return GGUFManifest{}, ErrInvalidManifest
	}
	if !validHFRepo(manifest.Repo) || !validHFRevision(manifest.Revision) ||
		!validGGUFPath(manifest.Path) || !validSHA256(manifest.ModelSHA256) || manifest.Size < 1 {
		return GGUFManifest{}, ErrInvalidManifest
	}
	return manifest, nil
}

func validHFRepo(value string) bool {
	if value == "" || len(value) > 256 || strings.Count(value, "/") != 1 {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if !validHFSegment(segment) {
			return false
		}
	}
	return true
}

func validHFRevision(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validGGUFPath(value string) bool {
	if value == "" || len(value) > 1024 || path.Clean(value) != value || strings.HasPrefix(value, "/") || !strings.HasSuffix(value, ".gguf") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if !validHFSegment(segment) {
			return false
		}
	}
	return true
}

func validHFSegment(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '_' && character != '-' && character != '.' {
			return false
		}
	}
	return true
}
