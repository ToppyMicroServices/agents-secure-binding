# ASB Human TaskCoord TLS ingress demo

Status: Experimental / Repository-local

本HTTP profileの安定したrequirement ID、英日共通mapping、production boundaryは
[Human Coordination conformance registry](human-coordination-conformance-v1.md)で管理する。

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
  -> trusted delegation decision verification when operation is DELEGATION
  -> replay insert
  -> TaskCoord Store create / revision CAS / atomic delegation / immutable interaction append
```

The ingress accepts the four `gateway-asserted-for-human` request kinds defined
by the binding profile: `ASSIGNMENT_OFFER`, `ASSIGNMENT_TRANSITION`,
`ASSIGNMENT_DELEGATION`, and `INTERACTION_APPEND`. Delegation is disabled unless
the deployment configures a `DelegationDecisionVerifier`.

`gateway-asserted-for-human` means that the operation authority authorizes the
gateway Actor, and the gateway proves possession and the exact TLS-bound
request. The signed ASB material is not a Human-held signature and does not
establish authenticated-Human evidence, Human liveness, UI confirmation, or
legal consent. Audit systems must retain the distinct Actor and Participant
identifiers and label this profile's assurance accordingly.

このHTTP surfaceで実装済みなのは、次の2 endpointだけである。

- `POST /v1/human-operations/challenge`: successは`201 Created`;
- `POST /v1/human-operations/execute`: successは`200 OK`。

Agent-to-Human relay専用endpointとAction lifecycle用endpointは実装していない。
`pkg/humanrelay`と`pkg/actionlifecycle`の内部APIを、この2 endpointの一部として扱っては
ならない。

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

## HTTP response contract

すべての応答は`X-Request-ID`を持つ。値はserverが生成する
`asbreq-` + 32文字lowercase hexadecimalであり、error bodyの`request_id`と同じ値である。
clientが送ったrequest IDを信頼してechoしない。success bodyとstatusは上記の既存形式を
変更しない。

error bodyは次のadditive JSON形式である。既存の`{"error":"..."}` decoderは
`error`を引き続きstringとして読める。

```json
{
  "error": "request is invalid",
  "code": "INVALID_REQUEST",
  "retryable": false,
  "request_id": "asbreq-0123456789abcdef0123456789abcdef"
}
```

公開するstatus、code、message、同一HTTP requestの自動retry可否は次に固定する。

| HTTP | `code` | `error` | `retryable` |
| ---: | --- | --- | :---: |
| 400 | `INVALID_REQUEST` | `request is invalid` | false |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | `Content-Type must be application/json` | false |
| 401 | `AUTHENTICATION_REQUIRED` | `authenticated TLS client is required` | false |
| 401 | `CHALLENGE_REJECTED` | `challenge is invalid or unavailable` | false |
| 403 | `OPERATION_REJECTED` | `operation is not authorized` | false |
| 404 | `NOT_FOUND` | `resource was not found` | false |
| 409 | `STATE_CONFLICT` | `operation conflicts with current state` | false |
| 405 | `METHOD_NOT_ALLOWED` | `method is not allowed` | false |
| 429 | `RATE_LIMITED` | `too many outstanding challenges` | true |
| 503 | `OPERATION_OUTCOME_UNKNOWN` | `operation outcome is unknown` | false |
| 500 | `INTERNAL_ERROR` | `internal service error` | false |

`RATE_LIMITED`には`Retry-After: 1`を付ける。`retryable`は同じHTTP requestを自動再送して
よいことだけを表し、一般的なrecovery可能性を表さない。特にexecuteの
`OPERATION_OUTCOME_UNKNOWN`は、mutationがcommit済みの可能性があるため自動retryしない。
Section "Retry boundary"の手順でtrusted stateからreconcileする。

backend、replay store、random source、delegation verifier等のraw error textは応答へ
含めない。外部応答は上表へcollapseする。内部詳細を記録する場合は、request IDで相関できる
access-controlled server-side logだけを使う。request bodyは対応するendpoint専用schemaで
検証するため、challenge bodyを
executeへ、execute bodyをchallengeへ送ると`INVALID_REQUEST`になる。success/error bodyは
`schemas/asb-taskcoord-human-ingress-response-v1.schema.json`で検証できる。

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

Offerとdelegationのlive TLS pathsはfocused ingress testsで検査する。delegation testは、
ASB grant/session proofが受理される前にdeployment policy verifierが呼ばれないこと、
parent transition、child offer、provenance edgeが`CommitDelegation`へ一括して渡ることも確認する。

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
- proof未検証時にはAssignmentをloadせず、missing、stale、wrong-taskを同一403へ
  collapseすること;
- stale Assignment revision拒否;
- delegation policy verifier未設定時の拒否;
- ASB proof不正時にdelegation decision lookupを行わないこと;
- clientが自己申告した`verified_delegation`またはpolicy projectionの拒否;
- trusted delegation decisionとparent、child、Participant、authority digestの不一致拒否;
- unsupported/unknown JSON member拒否;
- duplicate JSON member拒否;
- replayの逐次・並行拒否。

## Integration API

server側は、検証済みclient CAとserver certificateから直接TLSを終端するserverを生成する。

```go
ingress := &asbbinding.Ingress{
    Store:           taskStore,
    MaxPending:      8,
    MaxTotalPending: 256,
    Policy: asbbinding.IngressPolicy{
        Grant:          grantVerificationPolicy,
        SessionBinding: actorProofVerificationPolicy,
        Identity:       localActorPolicy,
        ReplayCache:    sharedReplayStore,
        DelegationVerifier: deploymentDelegationVerifier,
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

challenge stateはTTL expiryまたはexecute時に解放される。`MaxPending`は一つのTLS connectionと
一つのverified client public keyのそれぞれに適用され、connectionを増やしても同じkeyのquotaを
回避できない。`MaxTotalPending`は異なるconnectionとclient keyを含むIngress instance全体のhard
capである。両方とも0なら有限default（8と256）を使い、負値はconfiguration errorになる。

`DelegationDecisionVerifier`はclient requestに含まれるpolicy objectを採用せず、trusted
policy stateから`taskcoord.VerifiedDelegation`を生成する。Ingressはexact ASB grantとsession
proofを検証してからverifierを呼び、その後にstate machine validation、replay insert、
`Store.CommitDelegation`を行う。`verified_delegation`、`policy_ref`、policy evidenceなどを
wire requestへ追加するとstrict schema validationで拒否される。

demoの`DirectoryReplayCache`は、同じfilesystem directoryを使う複数process間で
atomic insert-if-absentを共有できる。entryを安全側で保持し続けるため、長期productionでは
容量管理、可用性、backup policyを持つdatabaseまたはRedis adapterへ置き換える。
repositoryの`identitypolicy.NewSetNXReplayCache`へRedis/Valkey等の`SetNXStore` adapterを渡せば、
profileが要求するTTL付きdistributed replay semanticsを利用できる。

`MemoryStore`もdemo用である。repositoryには`production.RedisTaskCoordStore`という
Redis/Valkey adapter候補があり、offer、通常transition、delegation、Interactionと
transactional outboxをLuaでatomic commitする。ただしstateful TLS protocol test doubleでの
検査までで、実Redis/Valkey、persistence、replication、failoverは未qualificationである。
replica acknowledgement有効時のidempotent retryは同一connection上のreplication barrierと
`WAIT`を通るが、非同期replicationのzero-lossを保証しない。

## Retry boundary

ASB replay insertはTaskCoord Store commitの直前に行うが、両者は同じtransactionではない。
execute応答またはStore commit結果が失われた場合、そのproofは再利用せず、結果をunknownとして
trusted Store stateとevent historyからreconcileする。fresh proofによる同じeventのblind retryは、
最初のcommitが成功していればrevision conflictまたはevent conflictになり得る。これは最初の
operation失敗の証拠ではない。

このdemoはrepositoryの`pkg/operationjournal`へ接続されておらず、外部向けstatus/read
endpointも、cross-proof retryへ以前のresponseを返すapplication transactionもない。
必要なdeploymentはrequest digestに束縛したreservationとresponseをTaskCoord mutationと
atomicに保存する。このdemoはfail-closedを示すが、databaseとreplay stateをまたぐ
exactly-onceまたはend-to-end idempotencyを主張しない。
