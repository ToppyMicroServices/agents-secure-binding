// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls"
	"golang.org/x/net/http2"
)

const (
	unix        = "unix"
	httpScheme  = "http"
	httpsScheme = "https"
)

var ErrPlaintextIngressDisabled = errors.New("plaintext ingress proxy is disabled")

// ProxyConfig contains configuration for starting a proxy instance.
type ProxyConfig struct {
	Port           string
	CertFile       string
	KeyFile        string
	ServerCAFile   string
	ClientCAFile   string
	AttestedTLS    bool
	AllowPlaintext bool
}

// ProxyContext provides context information for logging and tracking.
type ProxyContext struct {
	ID   string
	Name string
}

// ProxyServer manages ingress proxy instances.
type ProxyServer interface {
	Start(cfg ProxyConfig, ctx ProxyContext) error
	Stop() error
}

type proxyServer struct {
	mu           sync.RWMutex
	logger       *slog.Logger
	backendURL   *url.URL
	certProvider atls.CertificateProvider
	httpServer   *http.Server
	started      bool
	stopped      bool
}

// NewProxyServer creates a new ingress proxy server manager.
func NewProxyServer(logger *slog.Logger, backendURL *url.URL, certProvider atls.CertificateProvider) ProxyServer {
	return &proxyServer{
		logger:       logger,
		backendURL:   backendURL,
		certProvider: certProvider,
	}
}

// Start starts the proxy server with the given configuration.
func (p *proxyServer) Start(cfg ProxyConfig, ctx ProxyContext) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.started {
		return fmt.Errorf("proxy server already started")
	}
	if p.stopped {
		return fmt.Errorf("proxy server already stopped")
	}

	if cfg.Port == "" {
		cfg.Port = "7002"
	}

	addr := net.JoinHostPort("0.0.0.0", cfg.Port)
	transport, err := backendTransport(p.backendURL)
	if err != nil {
		return err
	}

	// Configure Reverse Proxy
	var rp *httputil.ReverseProxy

	// Check if backend is Unix socket or TCP
	if p.backendURL.Scheme == unix {
		// For Unix socket backend, we need to manually configure the reverse proxy
		// because NewSingleHostReverseProxy doesn't support unix:// scheme
		targetURL := &url.URL{
			Scheme: httpScheme,
			Host:   unix,
		}
		rp = httputil.NewSingleHostReverseProxy(targetURL)

		// Override the Director to not modify the request
		originalDirector := rp.Director
		rp.Director = func(req *http.Request) {
			originalDirector(req)
			// Set the URL to point to the backend service
			req.URL.Scheme = httpScheme
			req.URL.Host = unix
		}
	} else {
		// TCP backend
		rp = httputil.NewSingleHostReverseProxy(p.backendURL)
	}
	rp.Transport = transport

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(true)
	p.httpServer = &http.Server{
		Addr:              addr,
		Handler:           rp,
		Protocols:         protocols,
		ReadHeaderTimeout: regularTLSHandshakeTimeout,
		IdleTimeout:       time.Minute,
	}

	// Configure TLS
	var tlsConfig *tls.Config
	var listener net.Listener
	contextDesc := fmt.Sprintf("context %s", ctx.ID)
	if ctx.Name != "" {
		contextDesc = fmt.Sprintf("%s (%s)", ctx.Name, ctx.ID)
	}

	if cfg.AttestedTLS {
		if p.certProvider == nil {
			return fmt.Errorf("attested TLS requested for ingress proxy but no certificate provider available. Please ensure a CC platform is detected (not NoCC), aTLS is enabled, and the attestation service is running")
		}
		tlsConfig, identity, mtls, err := atls.BuildServerTLSConfig(cfg.CertFile, cfg.KeyFile, cfg.ServerCAFile, cfg.ClientCAFile)
		if err != nil {
			return fmt.Errorf("failed to setup attested TLS: %w", err)
		}
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}

		listener, err = p.attestedListener(addr, tlsConfig, identity)
		if err != nil {
			return fmt.Errorf("failed to listen: %w", err)
		}

		p.started = true
		go func() {
			serveErr := p.httpServer.Serve(listener)
			if serveErr != nil && serveErr != http.ErrServerClosed {
				p.logger.Error(fmt.Sprintf("ingress-proxy server error: %s", serveErr))
			}
		}()

		if mtls {
			p.logger.Info(fmt.Sprintf("ingress-proxy listening at %s with Attested mTLS for %s", addr, contextDesc))
		} else {
			p.logger.Info(fmt.Sprintf("ingress-proxy listening at %s with Attested TLS for %s", addr, contextDesc))
		}
		return nil
	} else if cfg.CertFile != "" && cfg.KeyFile != "" {
		// Regular TLS
		tlsSetup, err := SetupRegularTLS(cfg.CertFile, cfg.KeyFile, cfg.ServerCAFile, cfg.ClientCAFile)
		if err != nil {
			return fmt.Errorf("failed to setup TLS: %w", err)
		}
		tlsConfig = tlsSetup.Config
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}

		if tlsSetup.MTLS {
			p.logger.Info(fmt.Sprintf("ingress-proxy listening at %s with mTLS for %s", addr, contextDesc))
		} else {
			p.logger.Info(fmt.Sprintf("ingress-proxy listening at %s with TLS for %s", addr, contextDesc))
		}
	} else {
		if !cfg.AllowPlaintext {
			return ErrPlaintextIngressDisabled
		}
		addr = net.JoinHostPort("127.0.0.1", cfg.Port)
		p.httpServer.Addr = addr
		p.logger.Info(fmt.Sprintf("ingress-proxy listening at %s without TLS for %s", addr, contextDesc))
	}

	if tlsConfig != nil {
		tcpListener, listenErr := net.Listen("tcp", addr)
		if listenErr != nil {
			return fmt.Errorf("failed to listen: %w", listenErr)
		}
		listener = newRegularTLSListener(tcpListener, tlsConfig, regularTLSHandshakeTimeout, regularTLSMaxPending)
	} else {
		listener, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to listen: %w", err)
		}
	}

	p.started = true

	// Start server in goroutine
	go func() {
		serveErr := p.httpServer.Serve(listener)
		if serveErr != nil && serveErr != http.ErrServerClosed {
			p.logger.Error(fmt.Sprintf("ingress-proxy server error: %s", serveErr))
		}
	}()

	return nil
}

func backendTransport(backend *url.URL) (*http2.Transport, error) {
	if backend == nil {
		return nil, fmt.Errorf("missing ingress backend URL")
	}
	transport := &http2.Transport{}
	switch backend.Scheme {
	case httpsScheme:
		// The default dialer performs TLS and verifies the backend certificate.
	case httpScheme, unix:
		transport.AllowHTTP = true
		transport.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			if backend.Scheme == unix {
				network, addr = unix, backend.Path
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
	default:
		return nil, fmt.Errorf("unsupported ingress backend scheme %q", backend.Scheme)
	}
	return transport, nil
}

func (p *proxyServer) attestedListener(addr string, tlsConfig *tls.Config, identity tls.Certificate) (net.Listener, error) {
	network := "tcp"
	address := addr
	if len(addr) > 0 && addr[0] == '/' {
		network = unix
		address = addr
		_ = os.Remove(address)
	}

	serverConfig := &atls.ServerConfig{
		TLSConfig:           tlsConfig,
		Identity:            identity,
		BuildLeafExtensions: p.certProvider.BuildLeafExtensions,
	}
	if provider, ok := p.certProvider.(atls.ContextCertificateProvider); ok {
		serverConfig.BuildLeafExtensionsContext = provider.BuildLeafExtensionsContext
	}
	listener, err := atls.Listen(network, address, serverConfig)
	if err != nil {
		return nil, err
	}
	return &attestedHTTPListener{Listener: listener}, nil
}

// Expose the authenticated TLS connection so net/http can apply its native
// ALPN and HTTP/2 preface deadlines. Accept completes aTLS authentication first.
type attestedHTTPListener struct {
	*atls.Listener
}

func (l *attestedHTTPListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return connection.(*atls.Conn).Conn, nil
}

// Stop stops the proxy server.
func (p *proxyServer) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.stopped {
		return nil
	}
	p.stopped = true

	if p.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*1000000000) // 5 seconds
		defer cancel()
		if err := p.httpServer.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown server: %w", err)
		}
		p.logger.Info("ingress-proxy stopped")
	}

	return nil
}
