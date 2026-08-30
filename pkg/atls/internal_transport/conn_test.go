// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package internaltransport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/ea"
	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
)

const testIdentityBindingNonce = "identity-binding-nonce"

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "internal-transport"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

func TestDialContextDerivesServerNameAndValidatesCA(t *testing.T) {
	cert := selfSignedCert(t)
	roots := x509.NewCertPool()
	root, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(root)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverResult := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		serverTLS := tls.Server(raw, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
		})
		conn, err := Server(serverTLS, &ServerConfig{Identity: cert})
		if conn != nil {
			_ = conn.Close()
		}
		serverResult <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialContext(ctx, "tcp", listener.Addr().String(), &ClientConfig{
		TLSConfig: &tls.Config{
			RootCAs:    roots,
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
		},
		VerifyOptions: &x509.VerifyOptions{Roots: roots},
	})
	if err != nil {
		t.Fatalf("DialContext() failed CA-validated handshake: %v", err)
	}
	_ = conn.Close()
	if err := <-serverResult; err != nil {
		t.Fatalf("server failed: %v", err)
	}
}

func TestClientTLSConfigForTargetRequiresNameForUnix(t *testing.T) {
	_, err := clientTLSConfigForTarget("unix", "/tmp/asb.sock", &tls.Config{MinVersion: tls.VersionTLS13})
	if !errors.Is(err, ErrMissingTLSServerName) {
		t.Fatalf("clientTLSConfigForTarget() error = %v, want ErrMissingTLSServerName", err)
	}

	config, err := clientTLSConfigForTarget("unix", "/tmp/asb.sock", &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: "agent.internal",
	})
	if err != nil || config.ServerName != "agent.internal" {
		t.Fatalf("explicit unix server name = (%q, %v)", config.ServerName, err)
	}
}

func TestServerAllowsIdentityWithoutTLSConfig(t *testing.T) {
	cert := selfSignedCert(t)
	a, b := net.Pipe()

	serverTLS := tls.Server(a, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	clientTLS := tls.Client(b, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})

	type result struct {
		conn *Conn
		err  error
	}
	serverCh := make(chan result, 1)
	clientCh := make(chan result, 1)

	go func() {
		conn, err := Server(serverTLS, &ServerConfig{
			Identity: cert,
		})
		serverCh <- result{conn: conn, err: err}
	}()

	go func() {
		conn, err := Client(clientTLS, &ClientConfig{
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
				MaxVersion:         tls.VersionTLS13,
			},
		})
		clientCh <- result{conn: conn, err: err}
	}()

	srvRes := <-serverCh
	cliRes := <-clientCh

	if srvRes.err != nil {
		t.Fatalf("server failed: %v", srvRes.err)
	}
	if cliRes.err != nil {
		t.Fatalf("client failed: %v", cliRes.err)
	}

	defer srvRes.conn.Close()
	defer cliRes.conn.Close()
}

func TestClientRejectsIdentityPolicyBeforeReturningConnOrAppData(t *testing.T) {
	cert := selfSignedCert(t)
	a, b := net.Pipe()

	serverTLS := tls.Server(a, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	clientTLS := tls.Client(b, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})

	type result struct {
		conn *Conn
		err  error
	}
	serverCh := make(chan error, 1)
	clientCh := make(chan result, 1)

	go func() {
		conn, err := Server(serverTLS, &ServerConfig{Identity: cert})
		if err != nil {
			serverCh <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, 1)
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := conn.Read(buf)
		if n > 0 {
			serverCh <- errors.New("server received app data after failed identity policy")
			return
		}
		if err == nil {
			serverCh <- errors.New("server read returned without data or error")
			return
		}
		serverCh <- nil
	}()

	go func() {
		conn, err := Client(clientTLS, &ClientConfig{
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
				MaxVersion:         tls.VersionTLS13,
			},
			IdentityPolicy: identitypolicy.Policy{
				Require:  identitypolicy.Requirements{L3: true},
				Expected: identitypolicy.Values{Service: "payments"},
			},
			ObservedIdentity: func(_ *tls.ConnectionState, validation *ea.ValidationResult) (identitypolicy.Assertion, error) {
				binding, err := ExpectedIdentityBinding(validation)
				if err != nil {
					return identitypolicy.Assertion{}, err
				}
				binding.ExpiresAt = time.Now().Add(time.Hour)
				return identitypolicy.Assertion{
					Values:  identitypolicy.Values{Service: "analytics"},
					Binding: binding,
				}, nil
			},
		})
		if conn != nil {
			_, _ = conn.Write([]byte("x"))
			_ = conn.Close()
		} else {
			_ = clientTLS.Close()
		}
		clientCh <- result{conn: conn, err: err}
	}()

	cliRes := <-clientCh
	if cliRes.conn != nil {
		t.Fatal("client returned a connection after identity policy failure")
	}
	if !errors.Is(cliRes.err, identitypolicy.ErrMismatch) {
		t.Fatalf("client error = %v, want %v", cliRes.err, identitypolicy.ErrMismatch)
	}

	if err := <-serverCh; err != nil {
		t.Fatalf("server app-data observation error = %v", err)
	}
}

func TestValidateIdentityPolicySkipsDisabledPolicy(t *testing.T) {
	cfg := &ClientConfig{}

	if err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, nil); err != nil {
		t.Fatalf("validateIdentityPolicy() error = %v", err)
	}
}

func TestValidateIdentityPolicyRequiresObservedIdentitySource(t *testing.T) {
	cfg := &ClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L3: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
	}

	err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, nil)
	if !errors.Is(err, ErrMissingObservedIdentity) {
		t.Fatalf("validateIdentityPolicy() error = %v, want %v", err, ErrMissingObservedIdentity)
	}
}

func TestValidateIdentityPolicyRejectsObservedIdentityError(t *testing.T) {
	validation := validationResultForIdentityPolicy(t)
	sourceErr := errors.New("identity source unavailable")
	cfg := &ClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L3: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
		ObservedIdentity: func(*tls.ConnectionState, *ea.ValidationResult) (identitypolicy.Assertion, error) {
			return identitypolicy.Assertion{}, sourceErr
		},
	}

	err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation)
	if !errors.Is(err, sourceErr) {
		t.Fatalf("validateIdentityPolicy() error = %v, want %v", err, sourceErr)
	}
}

func TestValidateIdentityPolicyRejectsPartialDirectIdentitySource(t *testing.T) {
	validation := validationResultForIdentityPolicy(t)
	binding := bindingForAssertion(t, validation)
	grant := &identitypolicy.VerifiedGrant{
		Issuer:          "manager-key-1",
		Audience:        "client-a",
		GrantHash:       "sha256:grant",
		ConfirmationKey: "agent-confirmation-key",
		Values:          identitypolicy.Values{Service: "payments"},
		IssuedAt:        time.Now().Add(-time.Minute),
		ExpiresAt:       time.Now().Add(time.Hour),
	}
	statement := &identitypolicy.VerifiedSessionBindingStatement{
		GrantHash: "sha256:grant",
		Audience:  "client-a",
		SignerKey: "agent-confirmation-key",
		Binding:   binding,
	}

	tests := []struct {
		name      string
		grant     *identitypolicy.VerifiedGrant
		statement *identitypolicy.VerifiedSessionBindingStatement
	}{
		{name: "grant only", grant: grant},
		{name: "statement only", statement: statement},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ClientConfig{
				IdentityPolicy: identitypolicy.Policy{
					Require:  identitypolicy.Requirements{L3: true},
					Expected: identitypolicy.Values{Service: "payments"},
				},
				IdentityGrant:   tt.grant,
				IdentityBinding: tt.statement,
			}

			err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation)
			if !errors.Is(err, ErrMissingObservedIdentity) {
				t.Fatalf("validateIdentityPolicy() error = %v, want %v", err, ErrMissingObservedIdentity)
			}
		})
	}
}

func TestValidateIdentityPolicyAcceptsObservedIdentity(t *testing.T) {
	validation := validationResultForIdentityPolicy(t)
	binding := bindingForAssertion(t, validation)
	cfg := &ClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L3: true, L4: true},
			Expected: identitypolicy.Values{Service: "payments", Agent: "agent-a"},
		},
		ObservedIdentity: func(*tls.ConnectionState, *ea.ValidationResult) (identitypolicy.Assertion, error) {
			return identitypolicy.Assertion{
				Values:  identitypolicy.Values{Service: "payments", Agent: "agent-a"},
				Binding: binding,
			}, nil
		},
	}

	if err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation); err != nil {
		t.Fatalf("validateIdentityPolicy() error = %v", err)
	}
}

func TestValidateIdentityPolicyAcceptsVerifiedGrantAndBinding(t *testing.T) {
	validation := validationResultForIdentityPolicy(t)
	binding := bindingForAssertion(t, validation)
	binding.Nonce = testIdentityBindingNonce
	cfg := &ClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L3: true, L4: true},
			Expected: identitypolicy.Values{Service: "payments", Agent: "agent-a"},
		},
		IdentityGrant: &identitypolicy.VerifiedGrant{
			Issuer:          "manager-key-1",
			Audience:        "client-a",
			GrantHash:       "sha256:grant",
			ConfirmationKey: "agent-confirmation-key",
			Values:          identitypolicy.Values{Service: "payments", Agent: "agent-a"},
			IssuedAt:        time.Now().Add(-time.Minute),
			ExpiresAt:       time.Now().Add(time.Hour),
		},
		IdentityBinding: &identitypolicy.VerifiedSessionBindingStatement{
			GrantHash: "sha256:grant",
			Audience:  "client-a",
			SignerKey: "agent-confirmation-key",
			Binding:   binding,
		},
	}

	if err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation); err != nil {
		t.Fatalf("validateIdentityPolicy() error = %v", err)
	}
}

func TestValidateIdentityPolicyRejectsVerifiedGrantReplay(t *testing.T) {
	validation := validationResultForIdentityPolicy(t)
	binding := bindingForAssertion(t, validation)
	binding.Nonce = testIdentityBindingNonce
	replayCache := newTransportReplayCache()
	cfg := &ClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L3: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
		IdentityGrant: &identitypolicy.VerifiedGrant{
			Issuer:          "manager-key-1",
			Audience:        "client-a",
			GrantHash:       "sha256:grant",
			ConfirmationKey: "agent-confirmation-key",
			Values:          identitypolicy.Values{Service: "payments"},
			IssuedAt:        time.Now().Add(-time.Minute),
			ExpiresAt:       time.Now().Add(time.Hour),
		},
		IdentityBinding: &identitypolicy.VerifiedSessionBindingStatement{
			GrantHash: "sha256:grant",
			Audience:  "client-a",
			SignerKey: "agent-confirmation-key",
			Binding:   binding,
		},
		IdentityReplay: replayCache,
	}

	if err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation); err != nil {
		t.Fatalf("validateIdentityPolicy() first error = %v", err)
	}
	err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation)
	if !errors.Is(err, identitypolicy.ErrReplayDetected) {
		t.Fatalf("validateIdentityPolicy() replay error = %v, want %v", err, identitypolicy.ErrReplayDetected)
	}
}

func TestValidateIdentityPolicyDoesNotConsumeReplayOnPolicyMismatch(t *testing.T) {
	validation := validationResultForIdentityPolicy(t)
	binding := bindingForAssertion(t, validation)
	binding.Nonce = testIdentityBindingNonce
	replayCache := newTransportReplayCache()
	cfg := &ClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L3: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
		IdentityGrant: &identitypolicy.VerifiedGrant{
			Issuer:          "manager-key-1",
			Audience:        "client-a",
			GrantHash:       "sha256:grant",
			ConfirmationKey: "agent-confirmation-key",
			Values:          identitypolicy.Values{Service: "analytics"},
			IssuedAt:        time.Now().Add(-time.Minute),
			ExpiresAt:       time.Now().Add(time.Hour),
		},
		IdentityBinding: &identitypolicy.VerifiedSessionBindingStatement{
			GrantHash: "sha256:grant",
			Audience:  "client-a",
			SignerKey: "agent-confirmation-key",
			Binding:   binding,
		},
		IdentityReplay: replayCache,
	}

	err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation)
	if !errors.Is(err, identitypolicy.ErrMismatch) {
		t.Fatalf("validateIdentityPolicy() mismatch error = %v, want %v", err, identitypolicy.ErrMismatch)
	}
	cfg.IdentityGrant.Values.Service = "payments"
	if err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation); err != nil {
		t.Fatalf("validateIdentityPolicy() second error = %v", err)
	}
}

func TestValidateIdentityPolicyRejectsObservedIdentityMismatch(t *testing.T) {
	validation := validationResultForIdentityPolicy(t)
	binding := bindingForAssertion(t, validation)
	cfg := &ClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L3: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
		ObservedIdentity: func(*tls.ConnectionState, *ea.ValidationResult) (identitypolicy.Assertion, error) {
			return identitypolicy.Assertion{
				Values:  identitypolicy.Values{Service: "analytics"},
				Binding: binding,
			}, nil
		},
	}

	err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation)
	if !errors.Is(err, identitypolicy.ErrMismatch) {
		t.Fatalf("validateIdentityPolicy() error = %v, want %v", err, identitypolicy.ErrMismatch)
	}
}

func TestValidateIdentityPolicyDebugLogsFailureWithoutValues(t *testing.T) {
	validation := validationResultForIdentityPolicy(t)
	binding := bindingForAssertion(t, validation)
	var logs bytes.Buffer
	cfg := &ClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L3: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
		IdentityLogger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		ObservedIdentity: func(*tls.ConnectionState, *ea.ValidationResult) (identitypolicy.Assertion, error) {
			return identitypolicy.Assertion{
				Values:  identitypolicy.Values{Service: "analytics"},
				Binding: binding,
			}, nil
		},
	}

	err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation)
	if !errors.Is(err, identitypolicy.ErrMismatch) {
		t.Fatalf("validateIdentityPolicy() error = %v, want %v", err, identitypolicy.ErrMismatch)
	}
	logText := logs.String()
	for _, want := range []string{
		"aTLS identity policy check",
		"reason=validation_failed",
		"L3 service",
	} {
		if !strings.Contains(logText, want) {
			t.Fatalf("log output = %q, want %q", logText, want)
		}
	}
	for _, leakedValue := range []string{"payments", "analytics"} {
		if strings.Contains(logText, leakedValue) {
			t.Fatalf("log output leaked identity value %q: %q", leakedValue, logText)
		}
	}
}

func TestValidateIdentityPolicyDebugLogsSuccess(t *testing.T) {
	validation := validationResultForIdentityPolicy(t)
	binding := bindingForAssertion(t, validation)
	var logs bytes.Buffer
	cfg := &ClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L3: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
		IdentityLogger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		ObservedIdentity: func(*tls.ConnectionState, *ea.ValidationResult) (identitypolicy.Assertion, error) {
			return identitypolicy.Assertion{
				Values:  identitypolicy.Values{Service: "payments"},
				Binding: binding,
			}, nil
		},
	}

	if err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation); err != nil {
		t.Fatalf("validateIdentityPolicy() error = %v", err)
	}
	if !strings.Contains(logs.String(), "reason=accepted") {
		t.Fatalf("log output = %q, want accepted reason", logs.String())
	}
}

func TestValidateIdentityPolicyRejectsUnboundAssertion(t *testing.T) {
	validation := validationResultForIdentityPolicy(t)
	cfg := &ClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L3: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
		ObservedIdentity: func(*tls.ConnectionState, *ea.ValidationResult) (identitypolicy.Assertion, error) {
			return identitypolicy.Assertion{
				Values: identitypolicy.Values{Service: "payments"},
				Binding: identitypolicy.Binding{
					LeafPublicKeySHA256:  "wrong-leaf",
					RequestContextSHA256: "wrong-context",
					ExpiresAt:            time.Now().Add(time.Hour),
				},
			}, nil
		},
	}

	err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation)
	if !errors.Is(err, identitypolicy.ErrMismatch) {
		t.Fatalf("validateIdentityPolicy() error = %v, want %v", err, identitypolicy.ErrMismatch)
	}
}

func TestValidateIdentityPolicyRejectsMissingRequestContext(t *testing.T) {
	validation := validationResultForIdentityPolicy(t)
	validation.Context = nil
	cfg := &ClientConfig{
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L3: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
		ObservedIdentity: func(*tls.ConnectionState, *ea.ValidationResult) (identitypolicy.Assertion, error) {
			return identitypolicy.Assertion{
				Values:  identitypolicy.Values{Service: "payments"},
				Binding: bindingForAssertion(t, validationResultForIdentityPolicy(t)),
			}, nil
		},
	}

	err := validateIdentityPolicy(cfg, &tls.ConnectionState{}, validation)
	if err == nil {
		t.Fatal("validateIdentityPolicy() error = nil, want missing context error")
	}
}

func validationResultForIdentityPolicy(t *testing.T) *ea.ValidationResult {
	t.Helper()

	cert := selfSignedCert(t)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return &ea.ValidationResult{
		Context: []byte("identity-policy-request-context"),
		Chain:   []*x509.Certificate{leaf},
		Attestation: &eaattestation.VerifiedPayload{
			Payload: &eaattestation.Payload{Binder: eaattestation.AttestationBinder{
				Binding: []byte("identity-policy-attestation-binding"),
			}},
			BindingVerified: true,
			Binding: eaattestation.EvidenceBinding{
				ExportedValue: []byte("identity-policy-tls-exporter"),
			},
		},
	}
}

func bindingForAssertion(t *testing.T, validation *ea.ValidationResult) identitypolicy.Binding {
	t.Helper()

	binding, err := ExpectedIdentityBinding(validation)
	if err != nil {
		t.Fatal(err)
	}
	binding.ExpiresAt = time.Now().Add(time.Hour)
	return binding
}

type transportReplayCache struct {
	seen map[string]time.Time
}

func newTransportReplayCache() *transportReplayCache {
	return &transportReplayCache{seen: make(map[string]time.Time)}
}

func (c *transportReplayCache) MarkUsed(key string, expiresAt time.Time) error {
	if _, ok := c.seen[key]; ok {
		return identitypolicy.ErrReplayDetected
	}
	c.seen[key] = expiresAt
	return nil
}
