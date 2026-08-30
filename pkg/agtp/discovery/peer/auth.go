// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/production"
)

const nonceLifetime = 30 * time.Second

// PeerIdentity binds a configured DHT Node-ID and endpoint to one mTLS client
// certificate and one ASB verification profile.
type PeerIdentity struct {
	Node    discovery.NodeInfo
	Profile production.SoftwareOnlyProfile
}

// PeerDirectory is verifier-local policy. Network input cannot add entries.
type PeerDirectory struct {
	mu     sync.RWMutex
	byCert map[string]PeerIdentity
	byNode map[string]PeerIdentity
}

// NewPeerDirectory creates an empty trust directory.
func NewPeerDirectory() *PeerDirectory {
	return &PeerDirectory{byCert: make(map[string]PeerIdentity), byNode: make(map[string]PeerIdentity)}
}

// Add binds a peer certificate to its expected Node-ID.
func (d *PeerDirectory) Add(certificate *x509.Certificate, identity PeerIdentity) error {
	if d == nil || certificate == nil {
		return ErrUnauthorized
	}
	if _, err := discovery.NewRoutingTable(identity.Node, 1); err != nil {
		return err
	}
	fingerprint := certificateKey(certificate)
	d.mu.Lock()
	defer d.mu.Unlock()
	if current, exists := d.byCert[fingerprint]; exists && current.Node.ID != identity.Node.ID {
		return ErrUnauthorized
	}
	if current, exists := d.byNode[identity.Node.ID]; exists {
		// Key or endpoint rotation is an explicit local policy replacement.
		for key, candidate := range d.byCert {
			if candidate.Node.ID == current.Node.ID {
				delete(d.byCert, key)
			}
		}
	}
	d.byCert[fingerprint] = identity
	d.byNode[identity.Node.ID] = identity
	return nil
}

// LookupCertificate returns local policy for an authenticated TLS leaf.
func (d *PeerDirectory) LookupCertificate(certificate *x509.Certificate) (PeerIdentity, bool) {
	if d == nil || certificate == nil {
		return PeerIdentity{}, false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	identity, ok := d.byCert[certificateKey(certificate)]
	return identity, ok
}

// LookupNode returns local policy for one configured Node-ID.
func (d *PeerDirectory) LookupNode(nodeID string) (PeerIdentity, bool) {
	if d == nil {
		return PeerIdentity{}, false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	identity, ok := d.byNode[nodeID]
	return identity, ok
}

func certificateKey(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(digest[:])
}

type nonceEntry struct {
	value     string
	expiresAt time.Time
}

type nonceStore struct {
	mu      sync.Mutex
	entries map[string]nonceEntry
	now     func() time.Time
}

func newNonceStore(now func() time.Time) *nonceStore {
	if now == nil {
		now = time.Now
	}
	return &nonceStore{entries: make(map[string]nonceEntry), now: now}
}

func (s *nonceStore) issue(state *tls.ConnectionState, receiver string) (string, error) {
	key, err := sessionKey(state, receiver)
	if err != nil {
		return "", err
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString(random)
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for existing, entry := range s.entries {
		if !entry.expiresAt.After(now) {
			delete(s.entries, existing)
		}
	}
	s.entries[key] = nonceEntry{value: value, expiresAt: now.Add(nonceLifetime)}
	return value, nil
}

func (s *nonceStore) consume(state *tls.ConnectionState, receiver, value string) error {
	key, err := sessionKey(state, receiver)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[key]
	delete(s.entries, key)
	if !ok || value == "" || entry.value != value || !entry.expiresAt.After(s.now().UTC()) {
		return ErrUnauthorized
	}
	return nil
}

func sessionKey(state *tls.ConnectionState, receiver string) (string, error) {
	if state == nil {
		return "", ErrUnauthorized
	}
	exported, err := state.ExportKeyingMaterial("EXPORTER-ASB-Discovery-Peer-Nonce", []byte(receiver), 32)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(exported)
	return hex.EncodeToString(digest[:]), nil
}

type rateBucket struct {
	tokens float64
	last   time.Time
}

type peerRateLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]rateBucket
	now     func() time.Time
}

func newPeerRateLimiter(rate float64, burst int, now func() time.Time) *peerRateLimiter {
	if now == nil {
		now = time.Now
	}
	return &peerRateLimiter{rate: rate, burst: float64(burst), buckets: make(map[string]rateBucket), now: now}
}

func (l *peerRateLimiter) allow(peerID string) bool {
	if l.rate <= 0 || l.burst <= 0 {
		return false
	}
	now := l.now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	bucket, ok := l.buckets[peerID]
	if !ok {
		bucket = rateBucket{tokens: l.burst, last: now}
	}
	elapsed := now.Sub(bucket.last).Seconds()
	bucket.tokens += elapsed * l.rate
	if bucket.tokens > l.burst {
		bucket.tokens = l.burst
	}
	bucket.last = now
	if bucket.tokens < 1 {
		l.buckets[peerID] = bucket
		return false
	}
	bucket.tokens--
	l.buckets[peerID] = bucket
	return true
}

func expectedPeerPolicy(action Action, peerID, receiverID string) identitypolicy.Policy {
	return identitypolicy.Policy{
		Mode:    identitypolicy.ModeRequired,
		SetMode: identitypolicy.SetModeExact,
		Require: identitypolicy.Requirements{L3: true, L4: true, L6: true},
		Expected: identitypolicy.Values{
			Service:       "agtp-discovery-peer",
			Agent:         peerID,
			CapabilityRef: capabilityReference(action),
			OntologyID:    "agtp:peer-action:v1",
			Scopes:        []string{actionScope(action)},
			Resources:     []string{nodeResource(receiverID)},
		},
	}
}

func verifyPeerAction(ctx context.Context, identity PeerIdentity, receiverID string, state *tls.ConnectionState, leaf *x509.Certificate, action Action, body []byte, nonce, grant, binding string) error {
	if ctx == nil || state == nil || leaf == nil {
		return ErrUnauthorized
	}
	actionContext, err := canonicalActionContext(action, identity.Node.ID, receiverID, body)
	if err != nil {
		return err
	}
	expected, err := production.SoftwareBindingFromTLS(state, leaf, actionContext, nonce)
	if err != nil {
		return err
	}
	profile := identity.Profile
	profile.IdentityPolicy = expectedPeerPolicy(action, identity.Node.ID, receiverID)
	accepted, err := profile.Verify(ctx, production.SoftwareOnlyVerifyRequest{
		GrantJWT: grant, SessionBindingJWT: binding, ExpectedBinding: expected,
	})
	if err != nil {
		return err
	}
	if accepted.Agent != identity.Node.ID {
		return ErrUnauthorized
	}
	return nil
}

func requireTLSIdentity(state *tls.ConnectionState, directory *PeerDirectory) (PeerIdentity, *x509.Certificate, error) {
	if state == nil || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return PeerIdentity{}, nil, ErrUnauthorized
	}
	leaf := state.PeerCertificates[0]
	identity, ok := directory.LookupCertificate(leaf)
	if !ok {
		return PeerIdentity{}, nil, ErrUnauthorized
	}
	return identity, leaf, nil
}
