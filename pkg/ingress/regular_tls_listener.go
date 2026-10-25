// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"crypto/tls"
	"net"
	"sync"
	"time"
)

const (
	regularTLSHandshakeTimeout = 10 * time.Second
	regularTLSMaxPending       = 128
)

type regularTLSAcceptResult struct {
	conn net.Conn
	err  error
}

// regularTLSListener limits work held by peers that have not completed TLS.
// Connections are handed to HTTP only after the handshake, so long-lived
// requests do not consume a pending-handshake slot.
type regularTLSListener struct {
	raw       net.Listener
	config    *tls.Config
	timeout   time.Duration
	ready     chan regularTLSAcceptResult
	done      chan struct{}
	sem       chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
	closeErr  error
	mu        sync.Mutex
	pending   map[net.Conn]struct{}
}

func newRegularTLSListener(raw net.Listener, config *tls.Config, timeout time.Duration, maxPending int) *regularTLSListener {
	if timeout <= 0 {
		timeout = regularTLSHandshakeTimeout
	}
	if maxPending <= 0 {
		maxPending = regularTLSMaxPending
	}
	return &regularTLSListener{
		raw:     raw,
		config:  config,
		timeout: timeout,
		ready:   make(chan regularTLSAcceptResult),
		done:    make(chan struct{}),
		sem:     make(chan struct{}, maxPending),
		pending: make(map[net.Conn]struct{}),
	}
}

func (l *regularTLSListener) Accept() (net.Conn, error) {
	l.startOnce.Do(func() { go l.acceptLoop() })
	select {
	case result := <-l.ready:
		return result.conn, result.err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *regularTLSListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		l.closeErr = l.raw.Close()
		l.mu.Lock()
		for conn := range l.pending {
			_ = conn.Close()
		}
		l.mu.Unlock()
	})
	return l.closeErr
}

func (l *regularTLSListener) Addr() net.Addr { return l.raw.Addr() }

func (l *regularTLSListener) acceptLoop() {
	var retryDelay time.Duration
	for {
		rawConn, err := l.raw.Accept()
		if err != nil {
			if temporary, ok := err.(interface{ Temporary() bool }); ok && temporary.Temporary() {
				if retryDelay == 0 {
					retryDelay = 5 * time.Millisecond
				} else if retryDelay < time.Second {
					retryDelay *= 2
					if retryDelay > time.Second {
						retryDelay = time.Second
					}
				}
				select {
				case <-time.After(retryDelay):
					continue
				case <-l.done:
					return
				}
			}
			select {
			case l.ready <- regularTLSAcceptResult{err: err}:
			case <-l.done:
			}
			return
		}
		retryDelay = 0
		select {
		case l.sem <- struct{}{}:
			if !l.track(rawConn) {
				<-l.sem
				_ = rawConn.Close()
				return
			}
			go l.handshake(rawConn)
		default:
			_ = rawConn.Close()
		}
	}
}

func (l *regularTLSListener) track(conn net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.done:
		return false
	default:
		l.pending[conn] = struct{}{}
		return true
	}
}

func (l *regularTLSListener) handshake(rawConn net.Conn) {
	defer func() {
		l.mu.Lock()
		delete(l.pending, rawConn)
		l.mu.Unlock()
		<-l.sem
	}()
	if err := rawConn.SetDeadline(time.Now().Add(l.timeout)); err != nil {
		_ = rawConn.Close()
		return
	}
	conn := tls.Server(rawConn, l.config)
	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return
	}
	select {
	case l.ready <- regularTLSAcceptResult{conn: conn}:
	case <-l.done:
		_ = conn.Close()
	}
}
