// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package s3product assembles the Linux, single-authority S3 reader. It exposes
// only the existing authenticated ASB protocol and explicit local operations.
package s3product

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/strictjson"
	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege/awsiam"
)

const ConfigSchema = "asb.s3-product/v1"

var ErrConfiguration = errors.New("invalid or unavailable S3 product configuration")

// Config is trusted, owner-only operator input. Agents cannot install this file.
// Public keys use JSON base64. SigningKeyFile contains a PKCS#8 Ed25519 key.
type Config struct {
	Schema               string                       `json:"schema"`
	Namespace            string                       `json:"namespace"`
	Listen               string                       `json:"listen"`
	StoreDirectory       string                       `json:"store_directory"`
	ProfileFile          string                       `json:"profile_file"`
	MandatesFile         string                       `json:"mandates_file"`
	SigningKeyFile       string                       `json:"signing_key_file"`
	CertificateFile      string                       `json:"certificate_file"`
	TLSKeyFile           string                       `json:"tls_key_file"`
	ClientCAFile         string                       `json:"client_ca_file"`
	AWSCLI               string                       `json:"aws_cli"`
	WebIdentityTokenFile string                       `json:"web_identity_token_file"`
	Issuer               string                       `json:"issuer"`
	Audience             string                       `json:"audience"`
	GrantKeys            map[string]ed25519.PublicKey `json:"grant_keys"`
	ActorKeys            map[string]ed25519.PublicKey `json:"actor_keys"`
}

func privateFile(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrConfiguration
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrConfiguration
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, ErrConfiguration
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		clear(data)
		return nil, ErrConfiguration
	}
	return data, nil
}

func decode(data []byte, target any) error {
	if err := strictjson.ValidateDocument(data, 4<<20); err != nil {
		return ErrConfiguration
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrConfiguration
	}
	return nil
}

type loadedConfig struct {
	config   Config
	profile  *awsiam.Profile
	mandates []lp.Mandate
	signer   ed25519.PrivateKey
	tls      *tls.Config
	executor *awsiam.Executor
}

func loadConfig(path string) (loadedConfig, error) {
	var loaded loadedConfig
	raw, err := privateFile(path, 4<<20)
	if err != nil {
		return loaded, err
	}
	if err = decode(raw, &loaded.config); err != nil {
		return loaded, err
	}
	c := loaded.config
	address, err := netip.ParseAddrPort(c.Listen)
	if err != nil || address.Port() == 0 || (!address.Addr().IsLoopback() && !address.Addr().IsPrivate()) || c.Schema != ConfigSchema || !filepath.IsAbs(c.StoreDirectory) {
		return loaded, ErrConfiguration
	}
	raw, err = privateFile(c.ProfileFile, awsiam.MaxInputBytes)
	if err != nil {
		return loaded, err
	}
	loaded.profile, err = awsiam.Compile(raw)
	if err != nil {
		return loaded, ErrConfiguration
	}
	raw, err = privateFile(c.MandatesFile, 4<<20)
	if err != nil {
		return loaded, err
	}
	if err = decode(raw, &loaded.mandates); err != nil || len(loaded.mandates) > 4096 {
		return loaded, ErrConfiguration
	}
	raw, err = privateFile(c.SigningKeyFile, 16<<10)
	if err != nil {
		return loaded, err
	}
	defer clear(raw)
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return loaded, ErrConfiguration
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return loaded, ErrConfiguration
	}
	signer, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return loaded, ErrConfiguration
	}
	loaded.signer = signer
	certificate, err := privateFile(c.CertificateFile, 64<<10)
	if err != nil {
		return loaded, err
	}
	key, err := privateFile(c.TLSKeyFile, 64<<10)
	if err != nil {
		return loaded, err
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		return loaded, ErrConfiguration
	}
	ca, err := privateFile(c.ClientCAFile, 64<<10)
	if err != nil {
		return loaded, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return loaded, ErrConfiguration
	}
	loaded.tls = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{pair}}
	loaded.executor, err = awsiam.NewExecutor(loaded.profile, awsiam.CLIConfig{Path: c.AWSCLI, WebIdentityTokenFile: c.WebIdentityTokenFile, MaxEvaluations: 1 << lp.MaxGrants})
	if err != nil {
		return loaded, ErrConfiguration
	}
	return loaded, nil
}
