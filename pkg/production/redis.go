// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package production

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidRedisConfig = errors.New("production: invalid redis replay configuration")
	ErrRedisProtocol      = errors.New("production: redis replay protocol error")
	ErrRedisReplication   = errors.New("production: redis replay replication acknowledgement failed")
)

// RedisSetNXStore implements identitypolicy.SetNXStore with Redis or Valkey
// SET key value NX PX ttl over TLS. It opens one bounded connection per replay
// commit so no failed connection or authentication state is reused.
type RedisSetNXStore struct {
	Address          string
	Username         string
	Password         string
	KeyPrefix        string
	TLSConfig        *tls.Config
	Dialer           *net.Dialer
	OperationTimeout time.Duration

	// RequiredReplicaAcknowledgements enables a same-connection WAIT after a
	// successful SET. Zero preserves SET NX PX-only behavior. WAIT reduces the
	// acknowledged-write loss window, but Redis replication is not strongly
	// consistent and this is not a zero-loss failover guarantee.
	RequiredReplicaAcknowledgements int
	ReplicationTimeout              time.Duration
}

// SetNX atomically records a SHA-256-derived replay key until its TTL expires.
func (s RedisSetNXStore) SetNX(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	if ctx == nil {
		return false, ErrMissingContext
	}
	if err := s.validate(); err != nil {
		return false, err
	}
	if key == "" || ttl <= 0 {
		return false, ErrInvalidRedisConfig
	}
	operationCtx, cancel := context.WithTimeout(ctx, s.OperationTimeout)
	defer cancel()
	ctx = operationCtx

	dialer := s.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	}
	raw, err := dialer.DialContext(ctx, "tcp", s.Address)
	if err != nil {
		return false, fmt.Errorf("redis replay dial: %w", err)
	}
	defer raw.Close()

	tlsConfig := s.TLSConfig.Clone()
	conn := tls.Client(raw, tlsConfig)
	if err := conn.HandshakeContext(ctx); err != nil {
		return false, fmt.Errorf("redis replay TLS: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return false, fmt.Errorf("redis replay deadline: %w", err)
		}
	}
	reader := bufio.NewReader(conn)

	if s.Password != "" {
		auth := []string{"AUTH", s.Password}
		if s.Username != "" {
			auth = []string{"AUTH", s.Username, s.Password}
		}
		if err := writeRESPArray(conn, auth); err != nil {
			return false, fmt.Errorf("redis replay AUTH: %w", err)
		}
		kind, value, err := readRESP(reader)
		if err != nil {
			return false, fmt.Errorf("redis replay AUTH: %w", err)
		}
		if kind != '+' || value != "OK" {
			return false, fmt.Errorf("%w: AUTH rejected", ErrRedisProtocol)
		}
	}

	digest := sha256.Sum256([]byte(key))
	redisKey := s.KeyPrefix + hex.EncodeToString(digest[:])
	millis := ttl.Milliseconds()
	if millis < 1 {
		millis = 1
	}
	command := []string{"SET", redisKey, "1", "NX", "PX", strconv.FormatInt(millis, 10)}
	if err := writeRESPArray(conn, command); err != nil {
		return false, fmt.Errorf("redis replay SET: %w", err)
	}
	kind, value, err := readRESP(reader)
	if err != nil {
		return false, fmt.Errorf("redis replay SET: %w", err)
	}
	switch {
	case kind == '+' && value == "OK":
		if s.RequiredReplicaAcknowledgements == 0 {
			return true, nil
		}
		waitMillis := s.ReplicationTimeout.Milliseconds()
		if waitMillis < 1 {
			waitMillis = 1
		}
		wait := []string{
			"WAIT",
			strconv.Itoa(s.RequiredReplicaAcknowledgements),
			strconv.FormatInt(waitMillis, 10),
		}
		if err := writeRESPArray(conn, wait); err != nil {
			return false, fmt.Errorf("redis replay WAIT: %w", err)
		}
		kind, value, err = readRESP(reader)
		if err != nil {
			return false, fmt.Errorf("redis replay WAIT: %w", err)
		}
		if kind != ':' {
			return false, fmt.Errorf("%w: unexpected WAIT response", ErrRedisProtocol)
		}
		acknowledged, err := strconv.Atoi(value)
		if err != nil || acknowledged < 0 {
			return false, fmt.Errorf("%w: invalid WAIT acknowledgement", ErrRedisProtocol)
		}
		if acknowledged < s.RequiredReplicaAcknowledgements {
			return false, fmt.Errorf(
				"%w: got %d, require %d",
				ErrRedisReplication,
				acknowledged,
				s.RequiredReplicaAcknowledgements,
			)
		}
		return true, nil
	case kind == '$' && value == "":
		return false, nil
	default:
		return false, fmt.Errorf("%w: unexpected SET response", ErrRedisProtocol)
	}
}

func (s RedisSetNXStore) validate() error {
	if strings.TrimSpace(s.Address) == "" || strings.TrimSpace(s.KeyPrefix) == "" || s.OperationTimeout <= 0 {
		return ErrInvalidRedisConfig
	}
	if s.Username != "" && s.Password == "" {
		return ErrInvalidRedisConfig
	}
	if s.TLSConfig == nil || s.TLSConfig.InsecureSkipVerify || s.TLSConfig.ServerName == "" {
		return ErrInvalidRedisConfig
	}
	if s.TLSConfig.MinVersion < tls.VersionTLS13 {
		return ErrInvalidRedisConfig
	}
	if s.RequiredReplicaAcknowledgements < 0 || s.ReplicationTimeout < 0 {
		return ErrInvalidRedisConfig
	}
	if s.RequiredReplicaAcknowledgements == 0 && s.ReplicationTimeout != 0 {
		return ErrInvalidRedisConfig
	}
	if s.RequiredReplicaAcknowledgements > 0 &&
		(s.ReplicationTimeout <= 0 || s.ReplicationTimeout >= s.OperationTimeout) {
		return ErrInvalidRedisConfig
	}
	return nil
}

func writeRESPArray(w io.Writer, values []string) error {
	if len(values) == 0 {
		return ErrRedisProtocol
	}
	var builder strings.Builder
	builder.WriteByte('*')
	builder.WriteString(strconv.Itoa(len(values)))
	builder.WriteString("\r\n")
	for _, value := range values {
		builder.WriteByte('$')
		builder.WriteString(strconv.Itoa(len(value)))
		builder.WriteString("\r\n")
		builder.WriteString(value)
		builder.WriteString("\r\n")
	}
	_, err := io.WriteString(w, builder.String())
	return err
}

func readRESP(r *bufio.Reader) (byte, string, error) {
	prefix, err := r.ReadByte()
	if err != nil {
		return 0, "", err
	}
	line, err := readRESPLine(r)
	if err != nil {
		return 0, "", err
	}
	switch prefix {
	case '+':
		return prefix, line, nil
	case ':':
		if _, err := strconv.ParseInt(line, 10, 64); err != nil {
			return 0, "", ErrRedisProtocol
		}
		return prefix, line, nil
	case '-':
		return 0, "", fmt.Errorf("%w: server error", ErrRedisProtocol)
	case '$':
		length, err := strconv.Atoi(line)
		if err != nil || length < -1 || length > 4096 {
			return 0, "", ErrRedisProtocol
		}
		if length == -1 {
			return '$', "", nil
		}
		payload := make([]byte, length+2)
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, "", err
		}
		if payload[length] != '\r' || payload[length+1] != '\n' {
			return 0, "", ErrRedisProtocol
		}
		return '$', string(payload[:length]), nil
	default:
		return 0, "", ErrRedisProtocol
	}
}

func readRESPLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) < 2 || !strings.HasSuffix(line, "\r\n") || len(line) > 4096 {
		return "", ErrRedisProtocol
	}
	return strings.TrimSuffix(line, "\r\n"), nil
}
