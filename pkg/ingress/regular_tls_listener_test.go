// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testRegularTLSListener(t *testing.T, timeout time.Duration, limit int) *regularTLSListener {
	t.Helper()
	certFile, keyFile := createTempCert(t)
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	listener := newRegularTLSListener(raw, &tls.Config{Certificates: []tls.Certificate{certificate}}, timeout, limit)
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func TestRegularTLSListenerBoundsIncompleteHandshakes(t *testing.T) {
	listener := testRegularTLSListener(t, 250*time.Millisecond, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		acceptErr <- err
	}()

	first, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = first.Close() }()
	require.Eventually(t, func() bool { return len(listener.sem) == 1 }, time.Second, time.Millisecond)

	second, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = second.Close() }()
	require.NoError(t, second.SetReadDeadline(time.Now().Add(150*time.Millisecond)))
	var buf [1]byte
	_, err = second.Read(buf[:])
	require.ErrorIs(t, err, io.EOF, "excess pending TLS connection should be refused")

	require.NoError(t, first.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = first.Read(buf[:])
	require.ErrorIs(t, err, io.EOF, "incomplete TLS handshake should expire")

	require.NoError(t, listener.Close())
	select {
	case err := <-acceptErr:
		require.True(t, errors.Is(err, net.ErrClosed))
	case <-time.After(time.Second):
		t.Fatal("Accept remained blocked after listener closure")
	}
}

func TestRegularTLSListenerClearsDeadlineAfterHandshake(t *testing.T) {
	listener := testRegularTLSListener(t, 80*time.Millisecond, 1)
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, err := listener.Accept()
		accepted <- acceptResult{conn: conn, err: err}
	}()

	raw, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	client := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) // Test certificate only.
	defer func() { _ = client.Close() }()
	require.NoError(t, client.Handshake())

	var server net.Conn
	select {
	case result := <-accepted:
		require.NoError(t, result.err)
		server = result.conn
	case <-time.After(time.Second):
		t.Fatal("completed TLS handshake was not accepted")
	}
	defer func() { _ = server.Close() }()

	time.Sleep(120 * time.Millisecond)
	read := make(chan error, 1)
	go func() {
		var buf [2]byte
		_, err := io.ReadFull(server, buf[:])
		if err == nil && string(buf[:]) != "ok" {
			err = errors.New("unexpected payload")
		}
		read <- err
	}()
	time.Sleep(20 * time.Millisecond)
	_, err = client.Write([]byte("ok"))
	require.NoError(t, err)
	select {
	case err := <-read:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("established TLS connection did not remain usable")
	}
}
