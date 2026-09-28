// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package s3product

import (
	"net"
	"sync"
)

// Limit before TLS: only one Accept loop and at most capacity accepted sockets.
// Once full, connections wait in the kernel's bounded listen queue. No goroutine
// or TLS state is allocated for them; clients must use a bounded connect timeout.
type connectionLimit struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
}

func newConnectionLimit(listener net.Listener, capacity int) *connectionLimit {
	return &connectionLimit{Listener: listener, slots: make(chan struct{}, capacity), done: make(chan struct{})}
}

func (l *connectionLimit) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitedConnection{Conn: c, release: func() { <-l.slots }}, nil
}

func (l *connectionLimit) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitedConnection struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
