#!/usr/bin/env bash
set -Eeuo pipefail

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required command not found: $1" >&2
    exit 2
  fi
}

require_command docker
require_command go
require_command openssl
require_command timeout

redis_image="${ASB_REDIS_IMAGE:-redis:7.4.10-alpine3.21}"
artifact_dir="${ASB_FAILOVER_ARTIFACT_DIR:-${TMPDIR:-/tmp}/asb-redis-failover-evidence}"
mkdir -p "$artifact_dir"
cat >"$artifact_dir/report.md" <<'EOF'
# Redis Sentinel failover evidence

- Result: INCOMPLETE

The failover gate did not reach its final evidence write. Inspect the workflow
log and any attached container logs before retrying.
EOF

run_token="${GITHUB_RUN_ID:-$$}-${GITHUB_RUN_ATTEMPT:-1}"
run_token="${run_token//[^a-zA-Z0-9-]/-}"
prefix="asb-rf-${run_token}"
network="${prefix}-network"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/asb-redis-failover.XXXXXX")"
runtime_dir="$work_dir/runtime"
private_dir="$work_dir/private"
mkdir -p "$runtime_dir" "$private_dir"
state_file="$private_dir/replay-state.json"
post_failover_state_file="$private_dir/post-failover-state.json"

primary="${prefix}-primary"
replica_one="${prefix}-replica-1"
replica_two="${prefix}-replica-2"
sentinel_one="${prefix}-sentinel-1"
sentinel_two="${prefix}-sentinel-2"
sentinel_three="${prefix}-sentinel-3"
containers=(
  "$primary"
  "$replica_one"
  "$replica_two"
  "$sentinel_one"
  "$sentinel_two"
  "$sentinel_three"
)

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if ((status != 0)); then
    for container in "${containers[@]}"; do
      docker logs "$container" >"$artifact_dir/${container}.log" 2>&1 || true
    done
  fi
  for container in "${containers[@]}"; do
    docker rm -f "$container" >/dev/null 2>&1 || true
  done
  docker network rm "$network" >/dev/null 2>&1 || true
  case "$work_dir" in
    "${TMPDIR:-/tmp}"/asb-redis-failover.*) rm -rf -- "$work_dir" ;;
    *) echo "refusing to remove unexpected temporary path: $work_dir" >&2 ;;
  esac
  exit "$status"
}
trap cleanup EXIT INT TERM

wait_until() {
  local description deadline
  description="$1"
  shift
  deadline=$((SECONDS + 90))
  while ((SECONDS < deadline)); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for $description" >&2
  return 1
}

redis_cli() {
  local container
  container="$1"
  shift
  timeout --signal=KILL 5s docker exec "$container" redis-cli \
    --tls \
    --cacert /asb/ca.crt \
    --sni redis.local \
    --raw \
    -h 127.0.0.1 \
    -p 6379 \
    "$@"
}

sentinel_cli() {
  local container
  container="$1"
  shift
  timeout --signal=KILL 5s docker exec "$container" redis-cli \
    --tls \
    --cacert /tls/ca.crt \
    --sni redis.local \
    --raw \
    -h 127.0.0.1 \
    -p 26379 \
    "$@"
}

redis_ready() {
  [[ "$(redis_cli "$1" PING)" == "PONG" ]]
}

replicas_connected() {
  local expected
  expected="$2"
  redis_cli "$1" INFO replication | tr -d '\r' | grep -q "^connected_slaves:${expected}$"
}

sentinel_quorum_ready() {
  sentinel_cli "$1" SENTINEL CKQUORUM asb-primary | grep -q '^OK '
}

sentinel_topology_ready() {
  sentinel_cli "$1" SENTINEL MASTER asb-primary | awk '
    previous == "num-slaves" { slaves = $0 + 0 }
    previous == "num-other-sentinels" { sentinels = $0 + 0 }
    { previous = $0 }
    END { exit !(slaves >= 2 && sentinels >= 2) }
  '
}

is_master() {
  [[ "$(redis_cli "$1" ROLE | sed -n '1p')" == "master" ]]
}

echo "Pulling pinned Redis test image: $redis_image"
timeout --signal=KILL 120s docker pull "$redis_image"
resolved_image="$(timeout --signal=KILL 5s docker image inspect --format '{{index .RepoDigests 0}}' "$redis_image")"

cat >"$private_dir/openssl.cnf" <<'EOF'
[req]
distinguished_name = subject
req_extensions = extensions
prompt = no

[subject]
CN = redis.local

[extensions]
subjectAltName = @alt_names
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = redis.local
DNS.2 = redis-primary
DNS.3 = redis-replica-1
DNS.4 = redis-replica-2
IP.1 = 127.0.0.1
EOF

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$private_dir/ca.key" \
  -out "$runtime_dir/ca.crt" \
  -subj '/CN=ASB Redis failover test CA' \
  -days 1 >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -keyout "$runtime_dir/server.key" \
  -out "$private_dir/server.csr" \
  -config "$private_dir/openssl.cnf" >/dev/null 2>&1
openssl x509 -req \
  -in "$private_dir/server.csr" \
  -CA "$runtime_dir/ca.crt" \
  -CAkey "$private_dir/ca.key" \
  -CAcreateserial \
  -out "$runtime_dir/server.crt" \
  -days 1 \
  -extfile "$private_dir/openssl.cnf" \
  -extensions extensions >/dev/null 2>&1

cat >"$runtime_dir/primary.conf" <<'EOF'
bind 0.0.0.0
protected-mode no
port 0
tls-port 6379
tls-cert-file /asb/server.crt
tls-key-file /asb/server.key
tls-ca-cert-file /asb/ca.crt
tls-auth-clients no
tls-protocols "TLSv1.3"
tls-prefer-server-ciphers yes
save ""
appendonly yes
appendfsync always
EOF

chmod 0600 "$private_dir/ca.key"
chmod 0644 "$runtime_dir"/*.crt "$runtime_dir"/*.key "$runtime_dir"/primary.conf

docker network create "$network" >/dev/null
docker run -d \
  --name "$primary" \
  --network "$network" \
  --network-alias redis-primary \
  -p 127.0.0.1::6379 \
  -v "$runtime_dir:/asb" \
  "$redis_image" redis-server /asb/primary.conf >/dev/null

wait_until "Redis primary" redis_ready "$primary"
primary_ip="$(timeout --signal=KILL 5s docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$primary")"
if [[ ! "$primary_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "failed to resolve primary container IP" >&2
  exit 1
fi

for replica in 1 2; do
  cat >"$runtime_dir/replica-${replica}.conf" <<EOF
bind 0.0.0.0
protected-mode no
port 0
tls-port 6379
tls-cert-file /asb/server.crt
tls-key-file /asb/server.key
tls-ca-cert-file /asb/ca.crt
tls-auth-clients no
tls-protocols "TLSv1.3"
tls-prefer-server-ciphers yes
tls-replication yes
replicaof $primary_ip 6379
replica-read-only yes
save ""
appendonly yes
appendfsync always
EOF
done
chmod 0644 "$runtime_dir"/replica-*.conf

docker run -d \
  --name "$replica_one" \
  --network "$network" \
  --network-alias redis-replica-1 \
  -p 127.0.0.1::6379 \
  -v "$runtime_dir:/asb" \
  "$redis_image" redis-server /asb/replica-1.conf >/dev/null
docker run -d \
  --name "$replica_two" \
  --network "$network" \
  --network-alias redis-replica-2 \
  -p 127.0.0.1::6379 \
  -v "$runtime_dir:/asb" \
  "$redis_image" redis-server /asb/replica-2.conf >/dev/null

wait_until "Redis replica 1" redis_ready "$replica_one"
wait_until "Redis replica 2" redis_ready "$replica_two"
wait_until "two connected replicas" replicas_connected "$primary" 2

sentinel_containers=("$sentinel_one" "$sentinel_two" "$sentinel_three")
for sentinel_index in "${!sentinel_containers[@]}"; do
  sentinel_number=$((sentinel_index + 1))
  container="${sentinel_containers[$sentinel_index]}"
  sentinel_dir="$work_dir/sentinel-${sentinel_number}"
  mkdir -p "$sentinel_dir"
  chmod 0777 "$sentinel_dir"
  cat >"$sentinel_dir/sentinel.conf" <<EOF
bind 0.0.0.0
protected-mode no
port 0
tls-port 26379
tls-cert-file /tls/server.crt
tls-key-file /tls/server.key
tls-ca-cert-file /tls/ca.crt
tls-auth-clients no
tls-protocols "TLSv1.3"
tls-replication yes
dir /tmp
sentinel monitor asb-primary $primary_ip 6379 2
sentinel down-after-milliseconds asb-primary 2000
sentinel failover-timeout asb-primary 15000
sentinel parallel-syncs asb-primary 1
EOF
  chmod 0666 "$sentinel_dir/sentinel.conf"
  docker run -d \
    --name "$container" \
    --network "$network" \
    -v "$runtime_dir:/tls:ro" \
    -v "$sentinel_dir:/sentinel" \
    "$redis_image" redis-server /sentinel/sentinel.conf --sentinel >/dev/null
done

wait_until "Sentinel 1 quorum" sentinel_quorum_ready "$sentinel_one"
wait_until "Sentinel 2 quorum" sentinel_quorum_ready "$sentinel_two"
wait_until "Sentinel 3 quorum" sentinel_quorum_ready "$sentinel_three"
wait_until "Sentinel 1 topology discovery" sentinel_topology_ready "$sentinel_one"
wait_until "Sentinel 2 topology discovery" sentinel_topology_ready "$sentinel_two"
wait_until "Sentinel 3 topology discovery" sentinel_topology_ready "$sentinel_three"

primary_port="$(docker port "$primary" 6379/tcp | sed -n '1s/.*://p')"
seeded_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
go run ./cmd/redis-failover-redteam \
  --phase seed \
  --state-file "$state_file" \
  --address "127.0.0.1:${primary_port}" \
  --server-name redis.local \
  --ca-file "$runtime_dir/ca.crt" \
  --required-replicas 1 \
  --replication-timeout 2s \
  --operation-timeout 5s \
  --ttl 15m

replay_key_sha256="$(sed -n 's/.*"replay_key_sha256": "\([0-9a-f]*\)".*/\1/p' "$state_file")"
if [[ -z "$replay_key_sha256" ]]; then
  echo "failed to extract replay-key fingerprint" >&2
  exit 1
fi

failover_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Stopping Redis primary to trigger automatic Sentinel failover"
timeout --signal=KILL 20s docker stop --time 5 "$primary" >/dev/null

new_primary=""
promotion_deadline=$((SECONDS + 90))
while ((SECONDS < promotion_deadline)); do
  if is_master "$replica_one"; then
    new_primary="$replica_one"
    break
  fi
  if is_master "$replica_two"; then
    new_primary="$replica_two"
    break
  fi
  sleep 1
done
if [[ -z "$new_primary" ]]; then
  echo "Sentinel did not promote either replica" >&2
  exit 1
fi

wait_until "a replica attached to the promoted primary" replicas_connected "$new_primary" 1
failover_completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
new_primary_port="$(docker port "$new_primary" 6379/tcp | sed -n '1s/.*://p')"

go run ./cmd/redis-failover-redteam \
  --phase verify \
  --state-file "$state_file" \
  --address "127.0.0.1:${new_primary_port}" \
  --server-name redis.local \
  --ca-file "$runtime_dir/ca.crt" \
  --required-replicas 1 \
  --replication-timeout 2s \
  --operation-timeout 5s \
  --ttl 15m

# A fresh post-promotion insert proves WAIT is also usable on the new topology.
go run ./cmd/redis-failover-redteam \
  --phase seed \
  --state-file "$post_failover_state_file" \
  --address "127.0.0.1:${new_primary_port}" \
  --server-name redis.local \
  --ca-file "$runtime_dir/ca.crt" \
  --required-replicas 1 \
  --replication-timeout 2s \
  --operation-timeout 5s \
  --ttl 15m
go run ./cmd/redis-failover-redteam \
  --phase verify \
  --state-file "$post_failover_state_file" \
  --address "127.0.0.1:${new_primary_port}" \
  --server-name redis.local \
  --ca-file "$runtime_dir/ca.crt" \
  --required-replicas 1 \
  --replication-timeout 2s \
  --operation-timeout 5s \
  --ttl 15m

cat >"$artifact_dir/report.md" <<EOF
# Redis Sentinel failover evidence

- Result: PASS
- Redis image tag: \`$redis_image\`
- Resolved image: \`$resolved_image\`
- Topology: one primary, two replicas, three Sentinels
- Transport: certificate-verified TLS 1.3
- Replay write: \`SET NX PX\` followed by same-connection \`WAIT 1 2000\`
- Failed primary: \`$primary\`
- Promoted primary: \`$new_primary\`
- Seeded at: \`$seeded_at\`
- Failover started at: \`$failover_started_at\`
- Failover completed at: \`$failover_completed_at\`
- Replay-key SHA-256: \`$replay_key_sha256\`
- Post-failover result: the original replay remained rejected after ASB process restart
- Promoted-primary result: a fresh replay insert received one replica acknowledgement

This is reproducible self-operated Redis Sentinel evidence. It is not evidence
for a managed provider's endpoint convergence, persistence contract, or SLA.
EOF

echo "Redis Sentinel failover gate passed; evidence: $artifact_dir/report.md"
