// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"fmt"
	"io"
	"sync/atomic"
)

// Metrics contains dependency-free counters for the bounded local product.
type Metrics struct {
	PeerRequests      atomic.Uint64
	AuthRejected      atomic.Uint64
	RateLimited       atomic.Uint64
	GossipSuccess     atomic.Uint64
	GossipFailure     atomic.Uint64
	PersistenceErrors atomic.Uint64
	AuditErrors       atomic.Uint64
}

func (m *Metrics) writePrometheus(writer io.Writer, records, tombstones, peers int) {
	_, _ = fmt.Fprintf(writer, "agtp_peer_requests_total %d\n", m.PeerRequests.Load())
	_, _ = fmt.Fprintf(writer, "agtp_peer_auth_rejected_total %d\n", m.AuthRejected.Load())
	_, _ = fmt.Fprintf(writer, "agtp_peer_rate_limited_total %d\n", m.RateLimited.Load())
	_, _ = fmt.Fprintf(writer, "agtp_gossip_success_total %d\n", m.GossipSuccess.Load())
	_, _ = fmt.Fprintf(writer, "agtp_gossip_failure_total %d\n", m.GossipFailure.Load())
	_, _ = fmt.Fprintf(writer, "agtp_persistence_errors_total %d\n", m.PersistenceErrors.Load())
	_, _ = fmt.Fprintf(writer, "agtp_audit_errors_total %d\n", m.AuditErrors.Load())
	_, _ = fmt.Fprintf(writer, "agtp_presence_records %d\n", records)
	_, _ = fmt.Fprintf(writer, "agtp_presence_tombstones %d\n", tombstones)
	_, _ = fmt.Fprintf(writer, "agtp_dht_peers %d\n", peers)
}
