// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package internaltransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/ea"
)

func TestListenerIgnoresMalformedPeer(t *testing.T) {
	listener, err := Listen("tcp", "127.0.0.1:0", &ServerConfig{
		TLSConfig:        &tls.Config{MinVersion: tls.VersionTLS13},
		HandshakeTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()

	peer, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = peer.Write([]byte("not a TLS record"))
	_ = peer.Close()

	select {
	case err := <-result:
		t.Fatalf("malformed peer stopped server: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	_ = server.Close()
	_ = listener.Close()
}

func TestListenerSlowPeerDoesNotBlockValidClient(t *testing.T) {
	cert := selfSignedCert(t)
	roots := x509.NewCertPool()
	root, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(root)
	listener, err := Listen("tcp", "127.0.0.1:0", &ServerConfig{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
		},
		Identity:             cert,
		HandshakeTimeout:     300 * time.Millisecond,
		MaxPendingHandshakes: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		accepted <- err
	}()
	idle, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := DialContext(ctx, "tcp", listener.Addr().String(), &ClientConfig{
		TLSConfig: &tls.Config{
			RootCAs:    roots,
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
		},
		VerifyOptions: &x509.VerifyOptions{Roots: roots},
	})
	if err != nil {
		t.Fatalf("valid client blocked behind idle peer: %v", err)
	}
	_ = client.Close()
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("listener did not deliver valid authenticated connection")
	}
}

func TestListenerCancelsExtensionBuilderAndRecovers(t *testing.T) {
	cert := selfSignedCert(t)
	roots := x509.NewCertPool()
	root, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(root)
	var calls atomic.Int32
	entered := make(chan struct{})
	listener, err := Listen("tcp", "127.0.0.1:0", &ServerConfig{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
		Identity:  cert,
		BuildLeafExtensionsContext: func(ctx context.Context, _ *tls.ConnectionState, _ *ea.AuthenticatorRequest, _ *x509.Certificate) ([]ea.Extension, error) {
			if calls.Add(1) == 1 {
				close(entered)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return nil, nil
		},
		HandshakeTimeout:     100 * time.Millisecond,
		MaxPendingHandshakes: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		accepted <- err
	}()
	first := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn, err := DialContext(ctx, "tcp", listener.Addr().String(), &ClientConfig{
			TLSConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
			VerifyOptions: &x509.VerifyOptions{Roots: roots},
		})
		if conn != nil {
			_ = conn.Close()
		}
		first <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("extension builder did not start")
	}
	if err := <-first; err == nil {
		t.Fatal("timed-out extension builder was accepted")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := DialContext(ctx, "tcp", listener.Addr().String(), &ClientConfig{
		TLSConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		VerifyOptions: &x509.VerifyOptions{Roots: roots},
	})
	if err != nil {
		t.Fatalf("listener did not recover after canceled evidence work: %v", err)
	}
	_ = client.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

type temporaryAcceptError struct{}

func (temporaryAcceptError) Error() string   { return "temporary accept error" }
func (temporaryAcceptError) Timeout() bool   { return false }
func (temporaryAcceptError) Temporary() bool { return true }

type temporaryOnceListener struct {
	net.Listener
	injected atomic.Bool
}

func (l *temporaryOnceListener) Accept() (net.Conn, error) {
	if l.injected.CompareAndSwap(false, true) {
		return nil, temporaryAcceptError{}
	}
	return l.Listener.Accept()
}

func TestListenerRetriesTemporaryAcceptError(t *testing.T) {
	cert := selfSignedCert(t)
	roots := x509.NewCertPool()
	root, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(root)
	listener, err := Listen("tcp", "127.0.0.1:0", &ServerConfig{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
		Identity:  cert,
	})
	if err != nil {
		t.Fatal(err)
	}
	listener.raw = &temporaryOnceListener{Listener: listener.raw}
	defer listener.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		accepted <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := DialContext(ctx, "tcp", listener.Addr().String(), &ClientConfig{
		TLSConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		VerifyOptions: &x509.VerifyOptions{Roots: roots},
	})
	if err != nil {
		t.Fatalf("temporary Accept error stopped listener: %v", err)
	}
	_ = client.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}
