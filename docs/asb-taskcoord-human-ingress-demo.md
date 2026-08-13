# ASB Human TaskCoord TLS ingress demo

Status: Experimental / Repository-local

このdemoは、Human-facing gatewayをASB Actorとして扱い、受付service自身がTLSを終端して
Human operationを検証・保存する最小の外部入口を示す。

## Demonstrated boundary

```text
Human
  -> Human-facing gateway / ASB Actor
  -> TLS 1.3 mutual TLS
  -> POST /v1/human-operations/challenge
  <- verifier nonce + server-computed request digest
  -> Actor derives the TLS exporter from its connection
  -> signed Identity Grant + Session Binding Statement
  -> POST /v1/human-operations/execute
  -> exact request verification
  -> replay insert
  -> TaskCoord Store revision CAS / immutable interaction append
```

受付serviceは次をHTTP requestから取得しない。

- `actor_id`;
- client certificate hash;
- TLS exporter hash;
- request context hash;
- current Assignment snapshot;
- current Participant kind/status;
- replay acceptance result。

これらは、検証済みTLS connection、署名済みASB token、Participant registry、
TaskCoord Store、replay storeから導出する。

serverはTLS exporter hashをchallenge応答へ返さない。Actorは自身のTLS connection stateから
exporterを導出し、Session Binding Statementへ署名する。serverも同じconnectionから独立に
導出し、両者が一致した場合だけ受理する。

challengeとexecuteは同じTLS 1.3 connection上で行う。HTTP/2 connection reuseが推奨される。
connection切断、redirect、別serverへのretry後に古いchallengeを再利用せず、新しいchallengeを
取得する。

## Run

repository rootで次を実行する。

```sh
GOCACHE=/tmp/asb-human-binding-go-cache \
go test -run '^TestHumanTaskCoordIngressDemo$' -v ./pkg/taskcoord/asbbinding
```

このtestはlocalhost listenerを作るため、制限されたsandboxではnetwork permissionが必要になる。

成功時には概ね次が表示される。

```text
bound: request_digest=... tls_exporter_sha256=...
accepted: participant=human:alice actor=service:human-gateway status=ACCEPTED revision=2
appended: interaction=interaction:live kind=QUESTION content_digest=...
--- PASS: TestHumanTaskCoordIngressDemo
```

testはmocked HTTP metadataではなく、次を実際に生成・検査する。

- test CAが発行したserver/client certificate;
- TLS 1.3 mutual TLS connection;
- connection固有TLS exporter;
- server生成32-byte nonceとchallenge ID;
- operation-authority署名Identity Grant;
- Actor署名Session Binding Statement;
- exact request digest;
- directory-backed atomic replay entry;
- `MemoryStore`へのAssignment revision CAS commit;
- immutable Interaction append。

## Negative demonstrations

全security caseは次で実行できる。

```sh
GOCACHE=/tmp/asb-human-binding-go-cache \
go test -run '^(TestHumanTaskCoordIngressDemo|TestIngress|TestServerTLSConfig)' \
-v ./pkg/taskcoord/asbbinding
```

検査対象は次である。

- plaintext HTTP拒否;
- client certificateなしのTLS拒否;
- challengeの別TLS connectionへの持出し拒否;
- challenge後のrequest改変拒否;
- stale Assignment revision拒否;
- unsupported/unknown JSON member拒否;
- duplicate JSON member拒否;
- replayの逐次・並行拒否。

## Integration API

server側は、検証済みclient CAとserver certificateから直接TLSを終端するserverを生成する。

```go
ingress := &asbbinding.Ingress{
    Store: taskStore,
    Policy: asbbinding.IngressPolicy{
        Grant:          grantVerificationPolicy,
        SessionBinding: actorProofVerificationPolicy,
        Identity:       localActorPolicy,
        ReplayCache:    sharedReplayStore,
    },
}
server, err := ingress.NewTLSServer(":8443", serverCertificate, clientCAPool)
if err != nil {
    return err
}
err = server.ListenAndServeTLS("", "")
```

certificateは`TLSConfig`へ設定済みなので、`ListenAndServeTLS`のcertificate pathは空にする。
外部reverse proxyがTLSを終端して作った通常のHTTP headerを、このAPIのTLS bindingとして
使用してはならない。

demoの`DirectoryReplayCache`は、同じfilesystem directoryを使う複数process間で
atomic insert-if-absentを共有できる。entryを安全側で保持し続けるため、長期productionでは
容量管理、可用性、backup policyを持つdatabaseまたはRedis adapterへ置き換える。
repositoryの`identitypolicy.NewSetNXReplayCache`へRedis/Valkey等の`SetNXStore` adapterを渡せば、
profileが要求するTTL付きdistributed replay semanticsを利用できる。

`MemoryStore`もdemo用である。production adapterは既存`taskcoord.Store`契約に従い、
Assignment snapshotとeventを一つのtransactionでrevision CAS commitする。

## Retry boundary

ASB replay insertはTaskCoord Store commitの直前に行うが、両者は同じtransactionではない。
Store commitが失敗した場合、そのproofは再利用せず、新しいchallenge、nonce、proofでretryする。
このdemoはfail-closedを示すが、databaseとreplay stateをまたぐexactly-onceを主張しない。
