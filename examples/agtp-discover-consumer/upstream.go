// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package agtpdiscover

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxUpstreamResponseBytes = 4 << 20

// TCPUpstream sends DISCOVER /population using the AGTP/1.0 wire format.
// Address and TLSConfig are verifier-local configuration, never query inputs.
type TCPUpstream struct {
	Address   string
	TLSConfig *tls.Config
	Timeout   time.Duration
}

// Discover sends one exact capability query to the configured coordinator.
func (u TCPUpstream) Discover(ctx context.Context, query Query) (Result, error) {
	if err := validateQuery(query); err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(u.Address) == "" {
		return Result{}, ErrUpstream
	}
	timeout := u.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	if u.TLSConfig != nil {
		conn, err = tls.DialWithDialer(dialer, "tcp", u.Address, u.TLSConfig.Clone())
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", u.Address)
	}
	if err != nil {
		return Result{}, fmt.Errorf("%w: connect: %v", ErrUpstream, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	values := url.Values{}
	values.Set("capability", query.Capability)
	values.Set("limit", strconv.Itoa(query.Limit))
	values.Set("scope_negotiate", "true")
	request := fmt.Sprintf(
		"AGTP/1.0 DISCOVER %s?%s\r\nAccept: application/json\r\nHost: %s\r\n\r\n",
		PopulationPath,
		values.Encode(),
		u.Address,
	)
	if _, err := io.WriteString(conn, request); err != nil {
		return Result{}, fmt.Errorf("%w: write: %v", ErrUpstream, err)
	}
	return readAGTPResponse(bufio.NewReader(conn))
}

func readAGTPResponse(reader *bufio.Reader) (Result, error) {
	textReader := textproto.NewReader(reader)
	statusLine, err := textReader.ReadLine()
	if err != nil {
		return Result{}, fmt.Errorf("%w: status: %v", ErrUpstream, err)
	}
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 || parts[0] != "AGTP/1.0" {
		return Result{}, fmt.Errorf("%w: malformed status", ErrUpstream)
	}
	statusCode, err := strconv.Atoi(parts[1])
	if err != nil || statusCode < 100 || statusCode > 599 {
		return Result{}, fmt.Errorf("%w: malformed status code", ErrUpstream)
	}
	statusText := ""
	if len(parts) == 3 {
		statusText = parts[2]
	}
	headers, err := textReader.ReadMIMEHeader()
	if err != nil {
		return Result{}, fmt.Errorf("%w: headers: %v", ErrUpstream, err)
	}
	lengthText := headers.Get("Content-Length")
	if lengthText == "" {
		return Result{}, fmt.Errorf("%w: missing content length", ErrUpstream)
	}
	length, err := strconv.ParseInt(lengthText, 10, 64)
	if err != nil || length < 0 || length > maxUpstreamResponseBytes {
		return Result{}, fmt.Errorf("%w: invalid content length", ErrUpstream)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return Result{}, fmt.Errorf("%w: body: %v", ErrUpstream, err)
	}
	if !json.Valid(body) {
		return Result{}, fmt.Errorf("%w: non-json response", ErrUpstream)
	}
	return Result{StatusCode: statusCode, StatusText: statusText, Body: body}, nil
}
