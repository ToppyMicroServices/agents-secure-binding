// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package internaltransport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	defaultHandshakeTimeout     = 10 * time.Second
	defaultMaxPendingHandshakes = 128
)

type acceptResult struct {
	conn net.Conn
	err  error
}

type Listener struct {
	raw       net.Listener
	cfg       *ServerConfig
	ready     chan acceptResult
	done      chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
	closeErr  error
	pendingMu sync.Mutex
	pending   map[net.Conn]struct{}
	sem       chan struct{}
}

func Listen(network, address string, cfg *ServerConfig) (*Listener, error) {
	if cfg == nil || cfg.TLSConfig == nil {
		return nil, fmt.Errorf("atls: missing server TLS config")
	}
	if cfg.BuildLeafExtensions != nil && cfg.BuildLeafExtensionsContext == nil {
		return nil, fmt.Errorf("atls: listener requires a context-aware extension builder")
	}
	raw, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	limit := cfg.MaxPendingHandshakes
	if limit <= 0 {
		limit = defaultMaxPendingHandshakes
	}
	return &Listener{
		raw:     raw,
		cfg:     cfg,
		ready:   make(chan acceptResult),
		done:    make(chan struct{}),
		pending: make(map[net.Conn]struct{}),
		sem:     make(chan struct{}, limit),
	}, nil
}

func (l *Listener) Accept() (net.Conn, error) {
	l.startOnce.Do(func() { go l.acceptLoop() })
	select {
	case result := <-l.ready:
		return result.conn, result.err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		l.closeErr = l.raw.Close()
		l.pendingMu.Lock()
		for conn := range l.pending {
			_ = conn.Close()
		}
		l.pendingMu.Unlock()
	})
	return l.closeErr
}

func (l *Listener) Addr() net.Addr {
	return l.raw.Addr()
}

func (l *Listener) acceptLoop() {
	var retryDelay time.Duration
	for {
		rawConn, err := l.raw.Accept()
		if err != nil {
			if temporary, ok := err.(interface{ Temporary() bool }); ok && temporary.Temporary() {
				if retryDelay == 0 {
					retryDelay = 5 * time.Millisecond
				} else {
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
			case l.ready <- acceptResult{err: err}:
			case <-l.done:
			}
			return
		}
		retryDelay = 0
		select {
		case l.sem <- struct{}{}:
			if !l.track(rawConn) {
				<-l.sem
				return
			}
			go l.authenticate(rawConn)
		default:
			// Refuse excess unauthenticated peers rather than allowing an
			// unbounded goroutine and descriptor queue.
			_ = rawConn.Close()
		}
	}
}

func (l *Listener) authenticate(rawConn net.Conn) {
	defer func() {
		l.untrack(rawConn)
		<-l.sem
	}()
	timeout := l.cfg.HandshakeTimeout
	if timeout <= 0 {
		timeout = defaultHandshakeTimeout
	}
	if err := rawConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = rawConn.Close()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	tlsConn := tls.Server(rawConn, l.cfg.TLSConfig.Clone())
	conn, err := ServerContext(ctx, tlsConn, l.cfg)
	if err != nil {
		_ = tlsConn.Close()
		return
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return
	}
	select {
	case l.ready <- acceptResult{conn: conn}:
	case <-l.done:
		_ = conn.Close()
	}
}

func (l *Listener) track(conn net.Conn) bool {
	l.pendingMu.Lock()
	defer l.pendingMu.Unlock()
	select {
	case <-l.done:
		_ = conn.Close()
		return false
	default:
	}
	l.pending[conn] = struct{}{}
	return true
}

func (l *Listener) untrack(conn net.Conn) {
	l.pendingMu.Lock()
	delete(l.pending, conn)
	l.pendingMu.Unlock()
}
