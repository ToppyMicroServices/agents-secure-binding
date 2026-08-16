// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/production"
)

const (
	stateVersion = "asb.redis-failover-evidence/v1"
	phaseSeed    = "seed"
	phaseVerify  = "verify"
)

var (
	errReplayAcceptedAfterFailover = errors.New("replay key was accepted after failover")
	errEvidenceExpired             = errors.New("failover evidence TTL expired before verification")
)

type options struct {
	Phase              string
	StateFile          string
	Address            string
	ServerName         string
	CAFile             string
	ClientCertificate  string
	ClientKey          string
	KeyPrefix          string
	RequiredReplicas   int
	ReplicationTimeout time.Duration
	OperationTimeout   time.Duration
	TTL                time.Duration
}

type evidenceState struct {
	Version         string    `json:"version"`
	ReplayKey       string    `json:"replay_key"`
	ReplayKeySHA256 string    `json:"replay_key_sha256"`
	SeededAt        time.Time `json:"seeded_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type setNXStore interface {
	SetNX(context.Context, string, time.Duration) (bool, error)
}

func main() {
	opts := options{}
	flag.StringVar(&opts.Phase, "phase", "", "test phase: seed or verify")
	flag.StringVar(&opts.StateFile, "state-file", "", "private state file shared across failover")
	flag.StringVar(&opts.Address, "address", "", "stable private Redis/Valkey endpoint")
	flag.StringVar(&opts.ServerName, "server-name", "", "TLS server name")
	flag.StringVar(&opts.CAFile, "ca-file", "", "PEM CA bundle for the replay service")
	flag.StringVar(&opts.ClientCertificate, "client-certificate", "", "optional PEM client certificate")
	flag.StringVar(&opts.ClientKey, "client-key", "", "optional PEM client private key")
	flag.StringVar(&opts.KeyPrefix, "key-prefix", "asb:redis-failover:v1:", "isolated Redis key prefix")
	flag.IntVar(&opts.RequiredReplicas, "required-replicas", 1, "replica acknowledgements required by WAIT")
	flag.DurationVar(&opts.ReplicationTimeout, "replication-timeout", time.Second, "WAIT timeout")
	flag.DurationVar(&opts.OperationTimeout, "operation-timeout", 5*time.Second, "total replay operation timeout")
	flag.DurationVar(&opts.TTL, "ttl", 30*time.Minute, "failover evidence TTL")
	flag.Parse()

	if err := execute(context.Background(), opts, time.Now(), rand.Reader); err != nil {
		fmt.Fprintf(os.Stderr, "redis failover red-team failed: %v\n", err)
		os.Exit(1)
	}
}

func execute(ctx context.Context, opts options, now time.Time, randomness io.Reader) error {
	if strings.TrimSpace(opts.StateFile) == "" || strings.TrimSpace(opts.Address) == "" ||
		strings.TrimSpace(opts.ServerName) == "" || strings.TrimSpace(opts.CAFile) == "" {
		return errors.New("state-file, address, server-name, and ca-file are required")
	}
	tlsConfig, err := loadTLSConfig(opts)
	if err != nil {
		return err
	}
	store := production.RedisSetNXStore{
		Address:                         opts.Address,
		Username:                        os.Getenv("ASB_REDIS_USERNAME"),
		Password:                        os.Getenv("ASB_REDIS_PASSWORD"),
		KeyPrefix:                       opts.KeyPrefix,
		TLSConfig:                       tlsConfig,
		OperationTimeout:                opts.OperationTimeout,
		RequiredReplicaAcknowledgements: opts.RequiredReplicas,
		ReplicationTimeout:              opts.ReplicationTimeout,
	}
	return runPhase(ctx, opts, store, now, randomness)
}

func runPhase(ctx context.Context, opts options, store setNXStore, now time.Time, randomness io.Reader) error {
	if ctx == nil || store == nil || randomness == nil || opts.TTL <= 0 {
		return errors.New("invalid failover test configuration")
	}
	switch opts.Phase {
	case phaseSeed:
		rawKey := make([]byte, 32)
		if _, err := io.ReadFull(randomness, rawKey); err != nil {
			return fmt.Errorf("generate replay key: %w", err)
		}
		replayKey := base64.RawURLEncoding.EncodeToString(rawKey)
		accepted, err := store.SetNX(ctx, replayKey, opts.TTL)
		if err != nil {
			return fmt.Errorf("seed replicated replay state: %w", err)
		}
		if !accepted {
			return errors.New("fresh replay key was already present")
		}
		digest := sha256.Sum256([]byte(replayKey))
		state := evidenceState{
			Version:         stateVersion,
			ReplayKey:       replayKey,
			ReplayKeySHA256: hex.EncodeToString(digest[:]),
			SeededAt:        now.UTC(),
			ExpiresAt:       now.Add(opts.TTL).UTC(),
		}
		if err := writeState(opts.StateFile, state); err != nil {
			return err
		}
		fmt.Printf("seed passed: replay_key_sha256=%s expires_at=%s\n", state.ReplayKeySHA256, state.ExpiresAt.Format(time.RFC3339))
		return nil

	case phaseVerify:
		state, err := readState(opts.StateFile)
		if err != nil {
			return err
		}
		if !now.Before(state.ExpiresAt) {
			return errEvidenceExpired
		}
		remainingTTL := state.ExpiresAt.Sub(now)
		accepted, err := store.SetNX(ctx, state.ReplayKey, remainingTTL)
		if err != nil {
			return fmt.Errorf("verify replay state after failover: %w", err)
		}
		if accepted {
			return errReplayAcceptedAfterFailover
		}
		fmt.Printf("verify passed: replay_key_sha256=%s remained rejected after failover\n", state.ReplayKeySHA256)
		return nil

	default:
		return errors.New("phase must be seed or verify")
	}
}

func loadTLSConfig(opts options) (*tls.Config, error) {
	rootPEM, err := os.ReadFile(opts.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, errors.New("CA file contains no usable certificates")
	}
	config := &tls.Config{
		RootCAs:    roots,
		ServerName: opts.ServerName,
		MinVersion: tls.VersionTLS13,
	}
	if (opts.ClientCertificate == "") != (opts.ClientKey == "") {
		return nil, errors.New("client-certificate and client-key must be provided together")
	}
	if opts.ClientCertificate != "" {
		certificate, err := tls.LoadX509KeyPair(opts.ClientCertificate, opts.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("load Redis client certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	return config, nil
}

func writeState(path string, state evidenceState) error {
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal failover state: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write failover state: %w", err)
	}
	if _, err := file.Write(append(payload, '\n')); err != nil {
		_ = file.Close()
		return fmt.Errorf("write failover state: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close failover state: %w", err)
	}
	return nil
}

func readState(path string) (evidenceState, error) {
	info, err := os.Stat(path)
	if err != nil {
		return evidenceState{}, fmt.Errorf("stat failover state: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return evidenceState{}, errors.New("failover state permissions must be 0600 or stricter")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return evidenceState{}, fmt.Errorf("read failover state: %w", err)
	}
	var state evidenceState
	if err := json.Unmarshal(payload, &state); err != nil {
		return evidenceState{}, fmt.Errorf("decode failover state: %w", err)
	}
	digest := sha256.Sum256([]byte(state.ReplayKey))
	if state.Version != stateVersion || state.ReplayKey == "" ||
		state.ReplayKeySHA256 != hex.EncodeToString(digest[:]) ||
		state.SeededAt.IsZero() || state.ExpiresAt.IsZero() || !state.ExpiresAt.After(state.SeededAt) {
		return evidenceState{}, errors.New("invalid failover state")
	}
	return state, nil
}
