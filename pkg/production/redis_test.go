// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package production

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRedisSetNXStoreCommitsOneWinnerOverTLS(t *testing.T) {
	t.Parallel()
	address, clientTLS, stop := startTestRedisTLS(t)
	t.Cleanup(stop)

	store := RedisSetNXStore{
		Address:                         address,
		KeyPrefix:                       "asb:replay:v1:",
		TLSConfig:                       clientTLS,
		OperationTimeout:                5 * time.Second,
		RequiredReplicaAcknowledgements: 1,
		ReplicationTimeout:              time.Second,
	}

	const workers = 20
	var winners atomic.Int32
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := store.SetNX(context.Background(), "sensitive\x00replay\x00material", time.Minute)
			if err != nil {
				errCh <- err
				return
			}
			if ok {
				winners.Add(1)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("SetNX() error = %v", err)
	}
	if got := winners.Load(); got != 1 {
		t.Fatalf("SetNX() winners = %d, want 1", got)
	}
}

func TestRedisSetNXStoreRejectsInsufficientReplication(t *testing.T) {
	t.Parallel()
	address, clientTLS, stop := startTestRedisTLSWithAcknowledgements(t, 0)
	t.Cleanup(stop)

	store := RedisSetNXStore{
		Address:                         address,
		KeyPrefix:                       "asb:replay:v1:",
		TLSConfig:                       clientTLS,
		OperationTimeout:                5 * time.Second,
		RequiredReplicaAcknowledgements: 1,
		ReplicationTimeout:              time.Second,
	}
	ok, err := store.SetNX(context.Background(), "replication-required", time.Minute)
	if ok || !errors.Is(err, ErrRedisReplication) {
		t.Fatalf("SetNX() = (%v, %v), want (false, %v)", ok, err, ErrRedisReplication)
	}
}

func TestRedisSetNXStoreRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	if _, err := (RedisSetNXStore{}).SetNX(nil, "key", time.Minute); !errors.Is(err, ErrMissingContext) {
		t.Fatalf("SetNX(nil) error = %v, want %v", err, ErrMissingContext)
	}
	tests := []RedisSetNXStore{
		{},
		{Address: "redis.test:6379", KeyPrefix: "asb:", OperationTimeout: time.Second, TLSConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}}, //nolint:gosec // verifies rejection
		{Address: "redis.test:6379", KeyPrefix: "asb:", OperationTimeout: time.Second, TLSConfig: &tls.Config{ServerName: "redis.test", MinVersion: tls.VersionTLS12}},
		{Address: "redis.test:6379", KeyPrefix: "asb:", OperationTimeout: time.Second, Username: "user", TLSConfig: &tls.Config{ServerName: "redis.test", MinVersion: tls.VersionTLS13}},
		{Address: "redis.test:6379", KeyPrefix: "asb:", OperationTimeout: time.Second, TLSConfig: &tls.Config{ServerName: "redis.test", MinVersion: tls.VersionTLS13}, RequiredReplicaAcknowledgements: -1},
		{Address: "redis.test:6379", KeyPrefix: "asb:", OperationTimeout: time.Second, TLSConfig: &tls.Config{ServerName: "redis.test", MinVersion: tls.VersionTLS13}, ReplicationTimeout: time.Millisecond},
		{Address: "redis.test:6379", KeyPrefix: "asb:", OperationTimeout: time.Second, TLSConfig: &tls.Config{ServerName: "redis.test", MinVersion: tls.VersionTLS13}, RequiredReplicaAcknowledgements: 1},
		{Address: "redis.test:6379", KeyPrefix: "asb:", OperationTimeout: time.Second, TLSConfig: &tls.Config{ServerName: "redis.test", MinVersion: tls.VersionTLS13}, RequiredReplicaAcknowledgements: 1, ReplicationTimeout: time.Second},
	}
	for i, store := range tests {
		if _, err := store.SetNX(context.Background(), "key", time.Minute); !errors.Is(err, ErrInvalidRedisConfig) {
			t.Fatalf("case %d: SetNX() error = %v, want %v", i, err, ErrInvalidRedisConfig)
		}
	}
}

func startTestRedisTLS(t *testing.T) (string, *tls.Config, func()) {
	t.Helper()
	return startTestRedisTLSWithAcknowledgements(t, 1)
}

func startTestRedisTLSWithAcknowledgements(t *testing.T, acknowledgements int) (string, *tls.Config, func()) {
	t.Helper()
	certificate, roots := testRedisCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := &testRedisServer{
		listener:         listener,
		seen:             make(map[string]struct{}),
		done:             make(chan struct{}),
		acknowledgements: acknowledgements,
	}
	go server.serve()
	stop := func() {
		_ = listener.Close()
		<-server.done
		server.mu.Lock()
		defer server.mu.Unlock()
		if server.err != nil {
			t.Errorf("test Redis server: %v", server.err)
		}
	}
	return listener.Addr().String(), &tls.Config{
		RootCAs:    roots,
		ServerName: "redis.test",
		MinVersion: tls.VersionTLS13,
	}, stop
}

type testRedisServer struct {
	listener         net.Listener
	done             chan struct{}
	mu               sync.Mutex
	seen             map[string]struct{}
	err              error
	wg               sync.WaitGroup
	acknowledgements int
}

func (s *testRedisServer) serve() {
	defer close(s.done)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			s.recordError(err)
			break
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			if err := s.handle(conn); err != nil {
				s.recordError(err)
			}
		}()
	}
	s.wg.Wait()
}

func (s *testRedisServer) handle(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	command, err := readTestRESPArray(reader)
	if err != nil {
		return err
	}
	if len(command) != 6 || command[0] != "SET" || command[2] != "1" || command[3] != "NX" || command[4] != "PX" {
		return fmt.Errorf("unexpected command: %q", command)
	}
	if !strings.HasPrefix(command[1], "asb:replay:v1:") || strings.Contains(command[1], "sensitive") {
		return fmt.Errorf("unsafe Redis key: %q", command[1])
	}
	if _, err := strconv.ParseInt(command[5], 10, 64); err != nil {
		return fmt.Errorf("invalid TTL: %w", err)
	}

	s.mu.Lock()
	_, exists := s.seen[command[1]]
	if !exists {
		s.seen[command[1]] = struct{}{}
	}
	s.mu.Unlock()
	if exists {
		_, err = io.WriteString(conn, "$-1\r\n")
		return err
	}
	if _, err = io.WriteString(conn, "+OK\r\n"); err != nil {
		return err
	}

	wait, err := readTestRESPArray(reader)
	if err != nil {
		return err
	}
	if len(wait) != 3 || wait[0] != "WAIT" || wait[1] != "1" {
		return fmt.Errorf("unexpected replication command: %q", wait)
	}
	if _, err := strconv.ParseInt(wait[2], 10, 64); err != nil {
		return fmt.Errorf("invalid WAIT timeout: %w", err)
	}
	_, err = fmt.Fprintf(conn, ":%d\r\n", s.acknowledgements)
	return err
}

func (s *testRedisServer) recordError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err == nil {
		s.err = err
	}
}

func readTestRESPArray(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 4 || line[0] != '*' || !strings.HasSuffix(line, "\r\n") {
		return nil, errors.New("invalid array")
	}
	count, err := strconv.Atoi(strings.TrimSuffix(line[1:], "\r\n"))
	if err != nil || count < 1 || count > 16 {
		return nil, errors.New("invalid array count")
	}
	out := make([]string, count)
	for i := range count {
		lengthLine, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if len(lengthLine) < 4 || lengthLine[0] != '$' || !strings.HasSuffix(lengthLine, "\r\n") {
			return nil, errors.New("invalid bulk string")
		}
		length, err := strconv.Atoi(strings.TrimSuffix(lengthLine[1:], "\r\n"))
		if err != nil || length < 0 || length > maxRedisResultReplyBytes {
			return nil, errors.New("invalid bulk string length")
		}
		value := make([]byte, length+2)
		if _, err := io.ReadFull(r, value); err != nil {
			return nil, err
		}
		if value[length] != '\r' || value[length+1] != '\n' {
			return nil, errors.New("invalid bulk string terminator")
		}
		out[i] = string(value[:length])
	}
	return out, nil
}

func testRedisCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ASB test Redis CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "redis.test"},
		DNSNames:     []string{"redis.test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, serverPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}

	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER})
	certificate, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return certificate, roots
}
