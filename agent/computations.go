// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc/metadata"
)

var _ fmt.Stringer = (*Datasets)(nil)

type AgentConfig struct {
	CertFile     string `json:"cert_file,omitempty"`
	KeyFile      string `json:"server_key,omitempty"`
	ServerCAFile string `json:"server_ca_file,omitempty"`
	ClientCAFile string `json:"client_ca_file,omitempty"`
	AttestedTls  bool   `json:"attested_tls,omitempty"`
}

// ResourceSource specifies the location of a remote encrypted resource.
type ResourceSource struct {
	// Type is the type of resource source (currently only "oci-image" is supported)
	Type string `json:"type,omitempty"`
	// URL is the location of the resource (e.g., docker://registry/repo:tag)
	URL string `json:"url,omitempty"`
	// KBSResourcePath is the path to the decryption key in KBS (e.g., "default/key/my-key")
	KBSResourcePath string `json:"kbs_resource_path,omitempty"`
	// Encrypted indicates whether the resource is encrypted and requires KBS
	Encrypted bool `json:"encrypted,omitempty"`
}

// KBSConfig holds configuration for Key Broker Service.
type KBSConfig struct {
	// URL is the KBS endpoint (e.g., "https://kbs.example.com")
	URL string `json:"url,omitempty"`
	// Enabled indicates whether to use KBS for key retrieval
	Enabled bool `json:"enabled,omitempty"`
}

type Computation struct {
	ID              string           `json:"id,omitempty"`
	Name            string           `json:"name,omitempty"`
	Description     string           `json:"description,omitempty"`
	Datasets        Datasets         `json:"datasets,omitempty"`
	Algorithm       Algorithm        `json:"algorithm,omitempty"`
	ResultConsumers []ResultConsumer `json:"result_consumers,omitempty"`
	KBS             KBSConfig        `json:"kbs,omitempty"`
}

type ResultConsumer struct {
	UserKey []byte `json:"user_key,omitempty"`
}

func (d *Datasets) String() string {
	dat, err := json.Marshal(d)
	if err != nil {
		return ""
	}
	return string(dat)
}

type Dataset struct {
	Dataset    []byte          `json:"-"`
	Hash       [32]byte        `json:"hash,omitempty"`
	UserKey    []byte          `json:"user_key,omitempty"`
	Filename   string          `json:"filename,omitempty"`
	Source     *ResourceSource `json:"source,omitempty"` // Optional remote source
	Decompress bool            `json:"decompress,omitempty"`
}

type Datasets []Dataset

type Algorithm struct {
	Algorithm    []byte          `json:"-"`
	Hash         [32]byte        `json:"hash,omitempty"`
	UserKey      []byte          `json:"user_key,omitempty"`
	Requirements []byte          `json:"-"`
	Source       *ResourceSource `json:"source,omitempty"` // Optional remote source
	AlgoType     string          `json:"algo_type,omitempty"`
	AlgoArgs     []string        `json:"algo_args,omitempty"`
}

// AlgorithmCommitment returns the manifest commitment accepted for an
// algorithm. The original program-only digest remains valid only for a binary
// with no arguments or requirements.
func AlgorithmCommitment(algoType string, args []string, program, requirements []byte) [32]byte {
	if algoType == "" {
		algoType = "bin"
	}
	if algoType == "bin" && len(args) == 0 && len(requirements) == 0 {
		return sha3.Sum256(program)
	}
	return ExecutionBundleHash(algoType, args, program, requirements)
}

// ExecutionBundleHash returns the v1 commitment for every input that changes
// algorithm execution. Producers must use it whenever the execution is not a
// legacy binary with no arguments or requirements.
func ExecutionBundleHash(algoType string, args []string, program, requirements []byte) [32]byte {
	h := sha3.New256()
	writeHashPart := func(value []byte) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = h.Write(size[:])
		_, _ = h.Write(value)
	}
	writeHashPart([]byte("asb.execution-bundle.v1"))
	writeHashPart([]byte(algoType))
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(args)))
	_, _ = h.Write(count[:])
	for _, arg := range args {
		writeHashPart([]byte(arg))
	}
	writeHashPart(program)
	writeHashPart(requirements)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

type ManifestIndexKey struct{}

func IndexToContext(ctx context.Context, index int) context.Context {
	return context.WithValue(ctx, ManifestIndexKey{}, index)
}

func IndexFromContext(ctx context.Context) (int, bool) {
	index, ok := ctx.Value(ManifestIndexKey{}).(int)
	return index, ok
}

const DecompressKey = "decompress"

func DecompressFromContext(ctx context.Context) bool {
	vals := metadata.ValueFromIncomingContext(ctx, DecompressKey)
	if len(vals) == 0 {
		return false
	}

	return vals[0] == "true"
}

func DecompressToContext(ctx context.Context, decompress bool) context.Context {
	return metadata.AppendToOutgoingContext(ctx, DecompressKey, fmt.Sprintf("%t", decompress))
}
