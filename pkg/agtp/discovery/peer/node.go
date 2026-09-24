// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery"
)

const (
	DefaultMaxRecords        = 100
	DefaultMaxTombstones     = 200
	DefaultMaxPeers          = 2
	DefaultMaxRequestBytes   = 1 << 20
	DefaultAuditMaxBytes     = 10 << 20
	DefaultRequestsPerSecond = 20
	DefaultRequestBurst      = 40
)

// Config fixes the bounded discovery profile. NetworkPolicy opts in to
// explicitly configured LAN/VPC peers; nil keeps loopback networking.
type Config struct {
	Info               discovery.NodeInfo
	ListenAddress      string
	NetworkPolicy      *NetworkPolicy
	TLSConfig          *tls.Config
	Directory          *PeerDirectory
	Client             *Client
	StatePath          string
	AuditPath          string
	AuditMaxBytes      int64
	GossipInterval     time.Duration
	RequestTimeout     time.Duration
	TombstoneRetention time.Duration
	MaxRecords         int
	MaxTombstones      int
	MaxPeers           int
	MaxRequestBytes    int64
	RequestsPerSecond  float64
	RequestBurst       int
	Now                func() time.Time
	ErrorLog           *log.Logger
}

// Node is one persistent Presence, DHT, ANS, and gossip peer.
type Node struct {
	config   Config
	infoMu   sync.RWMutex
	info     discovery.NodeInfo
	presence *discovery.PresenceStore
	names    *discovery.NameService
	routing  *discovery.RoutingTable
	state    *StateStore
	audit    *AuditLog
	metrics  Metrics
	nonces   *nonceStore
	limiter  *peerRateLimiter

	stateMu      sync.Mutex
	dirty        bool // a failed snapshot must be retried before acknowledging replication
	remoteMu     sync.Mutex
	remoteDigest map[string]discovery.Digest
	remoteNames  map[string]map[string]uint64
	blocked      map[string]bool

	server      *http.Server
	lifecycleMu sync.Mutex
	listener    net.Listener
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	serveErrors chan error
	started     atomic.Bool
	ready       atomic.Bool
	closed      atomic.Bool
}

// NewNode loads durable state and constructs one peer. It does not open a port
// until Start succeeds.
func NewNode(config Config) (*Node, error) {
	config = withDefaults(config)
	config.NetworkPolicy = config.NetworkPolicy.clone()
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	// Give the node its own transport policy without changing a caller's client.
	client := *config.Client
	client.NetworkPolicy = config.NetworkPolicy.clone()
	config.Client = &client
	routing, err := discovery.NewRoutingTable(config.Info, min(config.MaxPeers, 20))
	if err != nil {
		return nil, err
	}
	presence := discovery.NewPresenceStoreWithOptions(discovery.PresenceOptions{
		TombstoneRetention: config.TombstoneRetention,
		MaxRecords:         config.MaxRecords,
		MaxTombstones:      config.MaxTombstones,
		Now:                config.Now,
	})
	names := discovery.NewNameService(presence, config.Now)
	state, err := NewStateStore(config.StatePath)
	if err != nil {
		return nil, err
	}
	audit, err := NewAuditLog(config.AuditPath, config.AuditMaxBytes)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	node := &Node{
		config:       config,
		info:         config.Info,
		presence:     presence,
		names:        names,
		routing:      routing,
		state:        state,
		audit:        audit,
		nonces:       newNonceStore(config.Now),
		limiter:      newPeerRateLimiter(config.RequestsPerSecond, config.RequestBurst, config.Now),
		remoteDigest: make(map[string]discovery.Digest),
		remoteNames:  make(map[string]map[string]uint64),
		blocked:      make(map[string]bool),
		ctx:          ctx,
		cancel:       cancel,
		serveErrors:  make(chan error, 1),
	}
	if err := node.load(); err != nil {
		_ = audit.Close()
		cancel()
		return nil, err
	}
	node.server = &http.Server{
		Handler:           node.routes(),
		ReadTimeout:       config.RequestTimeout,
		WriteTimeout:      config.RequestTimeout,
		ReadHeaderTimeout: config.RequestTimeout,
		IdleTimeout:       2 * config.RequestTimeout,
		MaxHeaderBytes:    int(config.MaxRequestBytes),
		TLSConfig:         hardenedServerTLS(config.TLSConfig),
		ErrorLog:          config.ErrorLog,
	}
	return node, nil
}

// Start opens the configured real TCP port and starts periodic gossip.
func (n *Node) Start() error {
	n.lifecycleMu.Lock()
	defer n.lifecycleMu.Unlock()
	if n.closed.Load() || !n.started.CompareAndSwap(false, true) {
		return errors.New("agtp discovery peer: node already started or closed")
	}
	listener, err := net.Listen("tcp", n.config.ListenAddress)
	if err != nil {
		n.started.Store(false)
		return err
	}
	if err := n.recordAudit(AuditEvent{NodeID: n.Info().ID, Action: "start", Result: "ok"}); err != nil {
		_ = listener.Close()
		n.started.Store(false)
		return fmt.Errorf("agtp discovery peer: write startup audit: %w", err)
	}
	n.listener = listener
	if n.config.NetworkPolicy == nil {
		n.infoMu.Lock()
		n.info.Endpoint = listener.Addr().String()
		n.infoMu.Unlock()
	}
	n.ready.Store(true)
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		err := n.server.ServeTLS(listener, "", "")
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			n.ready.Store(false)
			select {
			case n.serveErrors <- err:
			default:
			}
		}
	}()
	n.wg.Add(1)
	go n.gossipLoop()
	return nil
}

// Stop stops gossip, drains HTTP requests, and commits a final snapshot.
func (n *Node) Stop(ctx context.Context) error {
	if n == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("agtp discovery peer: missing shutdown context")
	}
	n.lifecycleMu.Lock()
	defer n.lifecycleMu.Unlock()
	if n.closed.Swap(true) {
		return nil
	}
	n.ready.Store(false)
	n.cancel()
	var result error
	if n.started.Load() {
		if err := n.server.Shutdown(ctx); err != nil {
			result = errors.Join(result, err)
			result = errors.Join(result, n.server.Close())
		}
	}
	n.wg.Wait()
	if err := n.persist(); err != nil {
		result = errors.Join(result, err)
	}
	if err := n.recordAudit(AuditEvent{NodeID: n.Info().ID, Action: "stop", Result: "ok"}); err != nil {
		result = errors.Join(result, err)
	}
	if err := n.audit.Close(); err != nil {
		result = errors.Join(result, err)
	}
	return result
}

// Errors reports asynchronous serving failures.
func (n *Node) Errors() <-chan error { return n.serveErrors }

// Info returns the current Node-ID and bound endpoint.
func (n *Node) Info() discovery.NodeInfo {
	n.infoMu.RLock()
	defer n.infoMu.RUnlock()
	return n.info
}

// Announce applies and durably commits one Presence update.
func (n *Node) Announce(record discovery.Record) (bool, error) {
	n.stateMu.Lock()
	defer n.stateMu.Unlock()
	if err := n.ensureOpen(); err != nil {
		return false, err
	}
	changed, err := n.presence.Announce(record)
	if err != nil {
		return false, err
	}
	return changed, n.persistLocked()
}

// Withdraw applies and durably commits a retained deletion marker.
func (n *Node) Withdraw(agentID string, version uint64) (bool, error) {
	n.stateMu.Lock()
	defer n.stateMu.Unlock()
	if err := n.ensureOpen(); err != nil {
		return false, err
	}
	changed, err := n.presence.Withdraw(agentID, version)
	if err != nil {
		return false, err
	}
	return changed, n.persistLocked()
}

// Register applies and durably commits one ANS binding.
func (n *Node) Register(binding discovery.NameBinding) (bool, error) {
	n.stateMu.Lock()
	defer n.stateMu.Unlock()
	if err := n.ensureOpen(); err != nil {
		return false, err
	}
	changed, err := n.names.Register(binding)
	if err != nil {
		return false, err
	}
	return changed, n.persistLocked()
}

// Deregister removes an ANS binding and commits its Presence withdrawal.
func (n *Node) Deregister(name string, version uint64) (bool, error) {
	n.stateMu.Lock()
	defer n.stateMu.Unlock()
	if err := n.ensureOpen(); err != nil {
		return false, err
	}
	changed, err := n.names.Deregister(name, version)
	if err != nil {
		return false, err
	}
	return changed, n.persistLocked()
}

// Discover queries local live Presence state.
func (n *Node) Discover(ctx context.Context, query discovery.Query, requester discovery.Requester) (discovery.Response, error) {
	n.stateMu.Lock()
	defer n.stateMu.Unlock()
	if err := n.ensureOpen(); err != nil {
		return discovery.Response{}, err
	}
	if n.dirty {
		return discovery.Response{}, errors.New("agtp discovery peer: persistence unavailable")
	}
	return n.presence.Discover(ctx, query, requester)
}

// Resolve resolves one live ANS name.
func (n *Node) Resolve(name string) (discovery.NameBinding, bool) {
	n.stateMu.Lock()
	defer n.stateMu.Unlock()
	if n.ensureOpen() != nil || n.dirty {
		return discovery.NameBinding{}, false
	}
	return n.names.Resolve(name)
}

// AddPeer adds a verifier-configured peer and commits routing state.
func (n *Node) AddPeer(peer discovery.NodeInfo) error {
	if !n.trustedPeer(peer) {
		return ErrUnauthorized
	}
	n.stateMu.Lock()
	defer n.stateMu.Unlock()
	if err := n.ensureOpen(); err != nil {
		return err
	}
	peers := n.routing.Peers()
	found := false
	for _, current := range peers {
		if current.ID == peer.ID {
			found = true
			break
		}
	}
	if !found && len(peers) >= n.config.MaxPeers {
		return discovery.ErrLimitExceeded
	}
	if _, err := n.routing.Observe(peer); err != nil {
		return err
	}
	return n.persistLocked()
}

// SetPeerBlocked is an operator/test partition control. It does not alter
// durable routing state.
func (n *Node) SetPeerBlocked(peerID string, blocked bool) {
	n.remoteMu.Lock()
	defer n.remoteMu.Unlock()
	n.blocked[peerID] = blocked
}

// GossipOnce exchanges bounded Presence and ANS deltas with all reachable
// configured peers.
func (n *Node) GossipOnce(ctx context.Context) error {
	if n == nil || n.closed.Load() {
		return errors.New("agtp discovery peer: node closed")
	}
	peers := n.routing.Peers()
	var result error
	for _, target := range peers {
		if n.peerBlocked(target.ID) {
			continue
		}
		if err := n.gossipPeer(ctx, target); err != nil {
			if n.closed.Load() {
				return errors.Join(result, err)
			}
			n.metrics.GossipFailure.Add(1)
			if auditErr := n.recordAudit(AuditEvent{NodeID: n.Info().ID, PeerID: target.ID, Action: string(ActionReplicate), Result: "error", Reason: "exchange-failed"}); auditErr != nil {
				result = errors.Join(result, auditErr)
			}
			result = errors.Join(result, err)
			continue
		}
		if n.closed.Load() {
			return n.ensureOpen()
		}
		n.metrics.GossipSuccess.Add(1)
		if err := n.recordAudit(AuditEvent{NodeID: n.Info().ID, PeerID: target.ID, Action: string(ActionReplicate), Result: "ok"}); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

// Locate performs a real multi-peer authenticated DHT lookup.
func (n *Node) Locate(ctx context.Context, target string, count int) ([]discovery.NodeInfo, error) {
	if err := n.ensureOpen(); err != nil {
		return nil, err
	}
	// Lookup learns into a private table. Only commit after rechecking lifecycle
	// and capacity, so shutdown and concurrent AddPeer cannot invalidate them.
	routing, err := discovery.NewRoutingTable(n.Info(), min(n.config.MaxPeers, 20))
	if err != nil {
		return nil, err
	}
	for _, known := range n.routing.Peers() {
		if n.trustedPeer(known) {
			_, _ = routing.Observe(known)
		}
	}
	peers, err := routing.IterativeLocate(ctx, target, min(count, n.config.MaxPeers), 3,
		func(ctx context.Context, peerInfo discovery.NodeInfo, target string) ([]discovery.NodeInfo, error) {
			if !n.trustedPeer(peerInfo) {
				return nil, ErrUnauthorized
			}
			if n.peerBlocked(peerInfo.ID) {
				return nil, errors.New("agtp discovery peer: peer partitioned")
			}
			response, err := n.config.Client.FindNode(ctx, peerInfo, FindNodeRequest{
				Protocol: ProtocolVersion, Sender: n.Info(), Target: target, Count: min(count, n.config.MaxPeers),
			})
			if err != nil {
				return nil, err
			}
			trusted := make([]discovery.NodeInfo, 0, len(response.Peers))
			known := make(map[string]bool)
			for _, current := range routing.Peers() {
				known[current.ID] = true
			}
			remaining := n.config.MaxPeers - len(known)
			for _, candidate := range response.Peers {
				if candidate.ID == n.Info().ID || known[candidate.ID] {
					continue
				}
				if !n.trustedPeer(candidate) {
					continue
				}
				if remaining <= 0 {
					break
				}
				trusted = append(trusted, candidate)
				known[candidate.ID] = true
				remaining--
			}
			return trusted, nil
		})
	if err != nil {
		return nil, err
	}
	n.stateMu.Lock()
	defer n.stateMu.Unlock()
	if err := n.ensureOpen(); err != nil {
		return nil, err
	}
	known := make(map[string]bool)
	for _, current := range n.routing.Peers() {
		known[current.ID] = true
	}
	for _, candidate := range routing.Peers() {
		if known[candidate.ID] || len(known) >= n.config.MaxPeers || !n.trustedPeer(candidate) {
			continue
		}
		_, _ = n.routing.Observe(candidate)
		known[candidate.ID] = true
	}
	if err := n.persistLocked(); err != nil {
		return nil, err
	}
	return peers, nil
}

// Counts reports bounded live state.
func (n *Node) Counts() (records, tombstones, peers int) {
	records, tombstones = n.presence.Counts()
	peers = len(n.routing.Peers())
	return
}

func (n *Node) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(NoncePath, n.handleNonce)
	mux.HandleFunc(ReplicatePath, n.authenticated(ActionReplicate, n.handleReplicate))
	mux.HandleFunc(FindNodePath, n.authenticated(ActionFindNode, n.handleFindNode))
	mux.HandleFunc(HealthPath, n.handleHealth)
	mux.HandleFunc(MetricsPath, n.handleMetrics)
	if n.config.NetworkPolicy == nil {
		return mux
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// RemoteAddr is the accepted socket's address; forwarding headers do
		// not establish membership in this administrative network.
		if !n.config.NetworkPolicy.allowsRemoteAddress(request.RemoteAddr) {
			n.reject(writer, "outside-network")
			return
		}
		identity, _, err := requireTLSIdentity(request.TLS, n.config.Directory)
		if err != nil || !n.trustedPeer(identity.Node) {
			n.reject(writer, "unknown-peer")
			return
		}
		mux.ServeHTTP(writer, request)
	})
}

func (n *Node) trustedPeer(peer discovery.NodeInfo) bool {
	identity, ok := n.config.Directory.LookupNode(peer.ID)
	return ok && identity.Node == peer && n.config.NetworkPolicy.validateEndpoint(peer.Endpoint, false) == nil
}

func (n *Node) handleNonce(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if request.Method != http.MethodPost || request.TLS == nil {
		http.Error(writer, "authentication failed", http.StatusUnauthorized)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 0)
	if _, err := io.Copy(io.Discard, request.Body); err != nil {
		http.Error(writer, "request body not allowed", http.StatusRequestEntityTooLarge)
		return
	}
	identity, _, err := requireTLSIdentity(request.TLS, n.config.Directory)
	if err != nil {
		n.metrics.AuthRejected.Add(1)
		http.Error(writer, "authentication failed", http.StatusUnauthorized)
		return
	}
	if !n.limiter.allow(identity.Node.ID) {
		n.metrics.RateLimited.Add(1)
		http.Error(writer, "rate limited", http.StatusTooManyRequests)
		return
	}
	nonce, err := n.nonces.issue(request.TLS, n.Info().ID)
	if err != nil {
		http.Error(writer, "authentication failed", http.StatusUnauthorized)
		return
	}
	if err := writeJSON(writer, nonceResponse{Nonce: nonce}); err != nil {
		return
	}
}

type actionHandler func(http.ResponseWriter, *http.Request, PeerIdentity, []byte)

func (n *Node) authenticated(action Action, next actionHandler) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		n.metrics.PeerRequests.Add(1)
		if request.Method != http.MethodPost || request.TLS == nil {
			n.reject(writer, "invalid-request")
			return
		}
		mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			n.reject(writer, "invalid-content-type")
			return
		}
		identity, leaf, err := requireTLSIdentity(request.TLS, n.config.Directory)
		if err != nil {
			n.reject(writer, "unknown-peer")
			return
		}
		if n.peerBlocked(identity.Node.ID) {
			http.Error(writer, "peer unavailable", http.StatusServiceUnavailable)
			return
		}
		if !n.limiter.allow(identity.Node.ID) {
			n.metrics.RateLimited.Add(1)
			http.Error(writer, "rate limited", http.StatusTooManyRequests)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, n.config.MaxRequestBytes+1))
		if int64(len(body)) > n.config.MaxRequestBytes {
			http.Error(writer, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		if err != nil || len(body) == 0 {
			n.reject(writer, "invalid-body")
			return
		}
		nonce := request.Header.Get(VerifierNonceHeader)
		if err := n.nonces.consume(request.TLS, n.Info().ID, nonce); err != nil {
			n.reject(writer, "invalid-nonce")
			return
		}
		if err := verifyPeerAction(request.Context(), identity, n.Info().ID, request.TLS, leaf, action, body, nonce,
			request.Header.Get(IdentityGrantHeader), request.Header.Get(SessionBindingHeader)); err != nil {
			n.reject(writer, "asb-verification-failed")
			_ = n.recordAudit(AuditEvent{NodeID: n.Info().ID, PeerID: identity.Node.ID, Action: string(action), Result: "rejected", Reason: "asb-verification-failed"})
			return
		}
		if err := n.recordAudit(AuditEvent{NodeID: n.Info().ID, PeerID: identity.Node.ID, Action: string(action), Result: "authorized"}); err != nil {
			http.Error(writer, "audit unavailable", http.StatusInternalServerError)
			return
		}
		next(writer, request, identity, body)
	}
}

func (n *Node) handleReplicate(writer http.ResponseWriter, _ *http.Request, identity PeerIdentity, body []byte) {
	var request ReplicateRequest
	if err := decodeStrict(body, &request); err != nil || request.Protocol != ProtocolVersion || request.Sender != identity.Node {
		http.Error(writer, "invalid request", http.StatusBadRequest)
		return
	}
	if len(request.Delta.Records)+len(request.Delta.Tombstones) > n.config.MaxRecords+n.config.MaxTombstones || len(request.Names) > n.config.MaxRecords {
		http.Error(writer, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	n.stateMu.Lock()
	defer n.stateMu.Unlock()
	if err := n.ensureOpen(); err != nil {
		http.Error(writer, "node closed", http.StatusServiceUnavailable)
		return
	}
	if err := n.mergeLocked(request.Delta, request.Names); err != nil {
		if n.dirty {
			http.Error(writer, "persistence failed", http.StatusInternalServerError)
			return
		}
		http.Error(writer, "merge failed", http.StatusConflict)
		return
	}
	response := ReplicateResponse{
		Protocol:   ProtocolVersion,
		Digest:     n.presence.Digest(),
		Delta:      n.presence.Delta(request.Digest),
		NameDigest: n.names.Digest(),
		Names:      n.names.Delta(request.NameDigest),
	}
	if err := writeJSON(writer, response); err != nil {
		return
	}
}

func (n *Node) handleFindNode(writer http.ResponseWriter, _ *http.Request, identity PeerIdentity, body []byte) {
	var request FindNodeRequest
	if err := decodeStrict(body, &request); err != nil || request.Protocol != ProtocolVersion || request.Sender != identity.Node || request.Count < 1 || request.Count > n.config.MaxPeers {
		http.Error(writer, "invalid request", http.StatusBadRequest)
		return
	}
	peers, err := n.routing.HandleLocate(request.Target, request.Count)
	if err != nil {
		http.Error(writer, "invalid request", http.StatusBadRequest)
		return
	}
	if err := writeJSON(writer, FindNodeResponse{Protocol: ProtocolVersion, Peers: peers}); err != nil {
		return
	}
}

func (n *Node) handleHealth(writer http.ResponseWriter, request *http.Request) {
	n.stateMu.Lock()
	ready := n.ready.Load() && !n.dirty
	n.stateMu.Unlock()
	if request.Method != http.MethodGet || !ready {
		http.Error(writer, "not ready", http.StatusServiceUnavailable)
		return
	}
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write([]byte("ok\n"))
}

func (n *Node) handleMetrics(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.NotFound(writer, request)
		return
	}
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4")
	records, tombstones, peers := n.Counts()
	n.metrics.writePrometheus(writer, records, tombstones, peers)
}

func (n *Node) reject(writer http.ResponseWriter, reason string) {
	n.metrics.AuthRejected.Add(1)
	_ = n.recordAudit(AuditEvent{NodeID: n.Info().ID, Action: "peer-request", Result: "rejected", Reason: reason})
	http.Error(writer, "authentication failed", http.StatusUnauthorized)
}

func (n *Node) recordAudit(event AuditEvent) error {
	if err := n.audit.Write(event); err != nil {
		n.metrics.AuditErrors.Add(1)
		return err
	}
	return nil
}

func (n *Node) ensureOpen() error {
	if n == nil || n.closed.Load() {
		return errors.New("agtp discovery peer: node closed")
	}
	return nil
}

func (n *Node) gossipLoop() {
	defer n.wg.Done()
	ticker := time.NewTicker(n.config.GossipInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(n.ctx, n.config.RequestTimeout)
			_ = n.GossipOnce(ctx)
			cancel()
		}
	}
}

func (n *Node) gossipPeer(ctx context.Context, target discovery.NodeInfo) error {
	if !n.trustedPeer(target) {
		return ErrUnauthorized
	}
	n.remoteMu.Lock()
	remoteDigest := n.remoteDigest[target.ID]
	remoteNames := n.remoteNames[target.ID]
	n.remoteMu.Unlock()
	n.stateMu.Lock()
	if err := n.ensureOpen(); err != nil {
		n.stateMu.Unlock()
		return err
	}
	if n.dirty {
		if err := n.persistLocked(); err != nil {
			n.stateMu.Unlock()
			return err
		}
	}
	request := ReplicateRequest{
		Protocol:   ProtocolVersion,
		Sender:     n.Info(),
		Digest:     n.presence.Digest(),
		Delta:      n.presence.Delta(remoteDigest),
		NameDigest: n.names.Digest(),
		Names:      n.names.Delta(remoteNames),
	}
	n.stateMu.Unlock()
	response, err := n.config.Client.Replicate(ctx, target, request)
	if err != nil {
		return err
	}
	n.stateMu.Lock()
	defer n.stateMu.Unlock()
	if err := n.ensureOpen(); err != nil {
		return err
	}
	if err := n.mergeLocked(response.Delta, response.Names); err != nil {
		return err
	}
	n.remoteMu.Lock()
	n.remoteDigest[target.ID] = response.Digest
	n.remoteNames[target.ID] = response.NameDigest
	n.remoteMu.Unlock()
	return nil
}

func (n *Node) peerBlocked(peerID string) bool {
	n.remoteMu.Lock()
	defer n.remoteMu.Unlock()
	return n.blocked[peerID]
}

func (n *Node) load() error {
	state, found, err := n.state.Load()
	if err != nil || !found {
		return err
	}
	if err := n.presence.Merge(discovery.Delta{Tombstones: state.Presence.Tombstones}); err != nil {
		return err
	}
	if err := n.names.Merge(state.Names); err != nil {
		return err
	}
	if err := n.presence.Merge(discovery.Delta{Records: state.Presence.Records}); err != nil {
		return err
	}
	for _, peerInfo := range state.Peers {
		if !n.trustedPeer(peerInfo) || len(n.routing.Peers()) >= n.config.MaxPeers {
			continue
		}
		if _, err := n.routing.Observe(peerInfo); err != nil {
			return err
		}
	}
	return nil
}

func (n *Node) persist() error {
	n.stateMu.Lock()
	defer n.stateMu.Unlock()
	return n.persistLocked()
}

func (n *Node) persistLocked() error {
	err := n.state.Save(n.snapshotLocked())
	n.dirty = err != nil
	if err != nil {
		n.metrics.PersistenceErrors.Add(1)
	}
	return err
}

func (n *Node) snapshotLocked() PersistentState {
	return PersistentState{
		Presence: n.presence.Snapshot(),
		Names:    n.names.Bindings(),
		Peers:    n.routing.Peers(),
	}
}

// mergeLocked preserves withdrawals before admitting replacement names. Full
// snapshots include retention metadata that the version-only wire digest omits.
func (n *Node) mergeLocked(delta discovery.Delta, names []discovery.NameBinding) error {
	before := n.snapshotLocked()
	err := n.presence.Merge(discovery.Delta{Tombstones: delta.Tombstones})
	if err == nil {
		err = n.names.Merge(names)
	}
	if err == nil {
		err = n.presence.Merge(discovery.Delta{Records: delta.Records})
	}
	if n.dirty || !reflect.DeepEqual(before, n.snapshotLocked()) {
		err = errors.Join(err, n.persistLocked())
	}
	return err
}

func withDefaults(config Config) Config {
	if config.ListenAddress == "" {
		config.ListenAddress = config.Info.Endpoint
	}
	if config.GossipInterval == 0 {
		config.GossipInterval = time.Second
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 5 * time.Second
	}
	if config.TombstoneRetention == 0 {
		config.TombstoneRetention = discovery.DefaultTombstoneRetention
	}
	if config.MaxRecords == 0 {
		config.MaxRecords = DefaultMaxRecords
	}
	if config.MaxTombstones == 0 {
		config.MaxTombstones = DefaultMaxTombstones
	}
	if config.MaxPeers == 0 {
		config.MaxPeers = DefaultMaxPeers
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = DefaultMaxRequestBytes
	}
	if config.AuditMaxBytes == 0 {
		config.AuditMaxBytes = DefaultAuditMaxBytes
	}
	if config.RequestsPerSecond == 0 {
		config.RequestsPerSecond = DefaultRequestsPerSecond
	}
	if config.RequestBurst == 0 {
		config.RequestBurst = DefaultRequestBurst
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return config
}

func validateConfig(config Config) error {
	if config.Directory == nil || config.Client == nil || config.Client.TLSConfig == nil || config.TLSConfig == nil || config.StatePath == "" || config.AuditPath == "" {
		return errors.New("agtp discovery peer: incomplete node config")
	}
	if config.Client.AgentID != config.Info.ID {
		return errors.New("agtp discovery peer: client Agent-ID must equal Node-ID")
	}
	if config.MaxRecords != DefaultMaxRecords {
		return fmt.Errorf("agtp discovery peer: product scope requires max_records=%d", DefaultMaxRecords)
	}
	if config.GossipInterval < 0 || config.RequestTimeout < 0 || config.TombstoneRetention < 0 || config.MaxTombstones < 0 || config.MaxPeers < 0 || config.MaxRequestBytes < 0 || config.AuditMaxBytes < 0 || config.RequestsPerSecond < 0 || config.RequestBurst < 0 {
		return errors.New("agtp discovery peer: negative limits are invalid")
	}
	if config.MaxPeers < 2 || config.MaxPeers > DefaultMaxPeers || config.MaxTombstones < config.MaxRecords {
		return errors.New("agtp discovery peer: invalid state limits")
	}
	if err := config.NetworkPolicy.validate(); err != nil {
		return err
	}
	if err := config.NetworkPolicy.validateEndpoint(config.ListenAddress, true); err != nil {
		return err
	}
	if err := config.NetworkPolicy.validateEndpoint(config.Info.Endpoint, true); err != nil {
		return err
	}
	if config.NetworkPolicy != nil {
		if config.ListenAddress != config.Info.Endpoint {
			return errors.New("agtp discovery peer: LAN listener must match its advertised IP endpoint")
		}
		if config.Client.TLSConfig.InsecureSkipVerify || config.TLSConfig.GetConfigForClient != nil {
			return errors.New("agtp discovery peer: LAN profile requires standard TLS verification")
		}
	}
	if _, err := discovery.NewRoutingTable(config.Info, 1); err != nil {
		return err
	}
	if len(config.TLSConfig.Certificates) == 0 || config.TLSConfig.ClientCAs == nil {
		return errors.New("agtp discovery peer: mTLS certificate and client CA required")
	}
	return nil
}

func hardenedServerTLS(config *tls.Config) *tls.Config {
	clone := config.Clone()
	clone.MinVersion = tls.VersionTLS13
	clone.ClientAuth = tls.RequireAndVerifyClientCert
	return clone
}

func decodeStrict(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrInvalidProtocol
	}
	return nil
}

func writeJSON(writer http.ResponseWriter, value any) error {
	writer.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(writer).Encode(value)
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}
