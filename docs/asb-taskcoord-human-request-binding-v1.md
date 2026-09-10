# ASB TaskCoord Human Request Binding v1

Status: Experimental / Repository-local

本profileを含む安定したproduct profile ID、英日共通要件、実装・qualification statusは
[Human Coordination conformance registry](human-coordination-conformance-v1.md)で管理する。

本書は、Split Agentのapplication substrateでHuman Participantへ帰属させるTaskCoord requestを、
既存のAgent Secure Binding (ASB) acceptanceへ最小限の追加情報で結合する
application profileを定義する。本書はHumanをAgentとして扱わず、新しい暗号方式、
Human専用token、transport protocol、またはHuman identity proofing方式を定義しない。

本書の`MUST`、`MUST NOT`、`SHOULD`、`MAY`は規範要件を表す。

identifierのoctet単位、whitespace、case、Unicodeの共通規則は
[`human-coordination-field-semantics-v1.md`](human-coordination-field-semantics-v1.md)で定義する。

## 1. Profile identifiers

| 項目 | 値 |
| --- | --- |
| Application profile | `asb.taskcoord-human-request/v1` |
| Request digest domain | `ASB-TASKCOORD-HUMAN-REQUEST-v1` |
| Request context domain | `ASB-TASKCOORD-HUMAN-CONTEXT-v1` |
| Authorization detail prefix | `urn:asb:taskcoord-human-request:v1:sha256:` |

### 1.1 Realm binding

`ASB-HC-CORE-010`のrealmはwire document内のcaller-controlled fieldではなく、
verifier-local contextである。同じrealmはexact audience、Participant resolverとStore
namespace、replay namespace、Human reachability grant namespace、outbox namespaceを
一貫して選択しなければならない。identifierはrealm内でのみ一意であり、別realmの同じ
文字列をglobal identityとして扱ってはならない。v1 documentをrealm間で移送する場合は、
暗黙のglobal IDを仮定せず、新しいprofile versionで明示的なrealm bindingを定義する。

## 2. Goal

このprofileが保証する受理条件は、次の論理積だけである。

```text
trusted ASB operation-authority grant
AND current ASB Actor holder-of-key/session proof
AND exact local request digest authorized by that grant
AND same request digest bound to the current ASB request context
AND trusted registry resolves the accountable Participant as HUMAN
AND current Participant/application policy permits the request
AND freshness, revocation, and one-shot replay checks succeed
```

ここでHumanは責任・意思の主体である`Participant(kind = HUMAN)`、Human-facing
gateway、device、またはworkloadは実際にrequestを送信するASB `Actor`である。
両者を同じidentity categoryとして解釈してはならず、identifierの一致も要求しない。
deploymentは運用上の混同を避けるため、role-separated namespaceを使用することが望ましい。

### 2.1 Human assurance vocabulary

Humanへの帰属は、証拠を作ったprincipalとその証拠が束縛する内容で区別する。
次のidentifierはprotocol、conformance manifest、audit表示で共通に使う。

| Assurance level | Evidence meaning | v1 status |
| --- | --- | --- |
| `gateway-asserted-for-human` | operation authorityがgateway Actorにexact requestの代理送信を許可し、ASBがgatewayのholder-of-key/session proofを検証してHuman Participantへ帰属させる。 | 現profileで実装済み |
| `authenticated-human-evidence` | trusted Human authentication authorityが生成した別のHuman認証artifactをoperationへ束縛する。artifact自体がexact request confirmationを含むとは限らない。 | 未実装 |
| `human-held-key-exact-request` | enrolmentされたHuman-held keyがdomain-separated exact requestとverifier contextへ署名する。 | 未実装 |

この三つは互換のmarketing labelではなく、検証可能な証拠の違いである。
`asb.taskcoord-human-request/v1`が供給するのは
`gateway-asserted-for-human`だけである。Identity GrantとSession Binding
Statementの署名鍵はgateway Actorまたはoperation authorityの鍵であり、Human-held
keyではない。`participant_id`をHumanの署名者として表示したり、
`proof_id`をHuman signature IDと呼んだりしてはならない。

将来のprofileが別の保証を使う場合は、artifactのissuer、key enrolment、
exact requestとrealm/audience/freshnessの束縛、revocation、audit表示をversioned
extensionとして定義する。caller-controlledな`assurance_level`を現在のwire
documentへ追加してはならない。assurance levelはaccepted profileと検証済み
evidenceからverifierが決定する。

accepted Human ingressは、この固定pairを`TransitionRecord`、
`DelegationRecord`、`InteractionEvent`へ監査provenanceとして保存する。
trusted-internalまたはlegacy recordではfieldを省略できるが、省略値から
Human assuranceを推測してはならない。Human ingressのresponseでは省略を許さない。

## 3. Minimality rule

requestの認可判断、永続state、帰属、または返却対象を変更できるcaller-controlled値は、
すべて一つの`request_digest`へ含める。個々の値をASB claimへ重複して追加しては
ならない。

次の値は別claimとして追加しない。

- Humanの`kind`、`status`、`identity_ref`;
- Humanの名前、Email、SNS account、電話番号、Homepage;
- `actor_id`;
- TLS exporter、grant hash、attestation binder等のASB session値;
- grant ID、proof ID、issued/expiry、nonce;
- current Assignment status等、revisionで特定されるtrusted local state;
- UI表示文、自然言語prompt、response本文。

理由は次のとおりである。

- Humanのkindとstatusは受理時のregistryから取得し、token内の古い値を信頼しない。
- Actorは署名済みIdentity Grantのsubject/D4 identityとholder-of-key proofから導出する。
- ASB session値、freshness、replayは既存ASB profileがすでに束縛する。
- requestの意味は一つのdomain-separated digestで固定できる。
- 生の連絡先や本文を署名tokenへ複製する必要はない。

## 4. Existing ASB material

このprofileは既存のDirect-Agent Identity GrantとSession Binding Statementを再利用する。
wire token typeやclaim nameを追加しない。

### 4.1 Identity Grant

Identity Grantは既存ASB要件に加え、次を満たさなければならない。

- issuerは対象audienceについてこのHuman operation profileを発行できる、ローカルに
  信頼された単一のoperation authorityであること;
- `sub`または検証済みD4 Agent値が実際のgateway Actorを識別すること;
- `jti`を持ち、受理後の`authorization_id`はこの検証済み値から導出すること;
- `authorization_details`は、Section 6のauthorization detail一要素だけからなる
  exact setであること;
- `iat`、`exp`、`aud`、`cnf`を既存ASB規則どおり検証すること。

operation authorityは、Humanをどのように認証し、どのActorに代理を許したかを自身の
発行policyで判断する。ASB verifierは署名済みgrantを検証するが、issuer内部の本人確認
方法を推論しない。

### 4.2 Session Binding Statement

Session Binding Statementは新しいclaimを必要としない。既存の次の値を検証する。

- statement `jti`;
- exact grant hashとaudience;
- grantが許可したActor confirmation keyによる署名;
- accepted endpoint key、TLS exporter、request context hash;
- verifier nonce、`iat`、`exp`;
- deployment policyが要求する場合のattestation binder。

受理後の`proof_id`は検証済みstatement `jti`から導出する。untrusted requestが指定した
IDを使用してはならない。

## 5. Canonical encoding

### 5.1 Field encoding

lengthとrevisionはunsigned big-endianである。fieldは次のようにencodeする。

```text
field(name, value) =
  uint16_be(len(name)) || ASCII(name) ||
  uint32_be(len(value)) || value
```

規則は次のとおりである。

- field順はrequest kindごとにSection 7で固定する;
- optional fieldも省略せず、absentをzero-length valueとしてencodeする;
- stringはstrict decoderと意味validatorを通過したUTF-8 bytesをそのまま使用する;
- receiverはcase変換、Unicode normalization、alias解決、trim、再serializeを行わない;
- enumは仕様に記載されたASCII valueを使用する;
- revisionは8 byte `uint64_be`とする;
- SHA-256 digest fieldは64文字hexをdecodeしたraw 32 bytesとする;
- timestampは8 byte two's-complement signed Unix secondsと4 byte unsigned nanosecondsを
  big-endianで連結する;
- request transcriptは最大1 MiBとする;
- unknown field、duplicate JSON member、invalid UTF-8はdigest計算前に拒否する。

### 5.2 Request transcript and digest

```text
request_transcript =
  ASCII("ASB-TASKCOORD-HUMAN-REQUEST-v1") || 0x00 ||
  field("request_kind", ASCII(request_kind)) ||
  kind_specific_fields

request_digest = SHA-256(request_transcript)
```

`request_digest`の表示形は64文字lowercase hexadecimalである。

### 5.3 Request context

```text
request_context =
  ASCII("ASB-TASKCOORD-HUMAN-CONTEXT-v1") || 0x00 ||
  field("request_digest", request_digest)

request_context_sha256 = SHA-256(request_context)
```

ASB accepted bindingをTLS sessionから導出する際のapplication contextは、上記の
`request_context` exact bytesでなければならない。単にpeerが送信した
`request_context_sha256`を採用してはならない。

## 6. Authorization detail

Identity Grantへ入れる唯一のapplication authorization detailは次である。

```text
"urn:asb:taskcoord-human-request:v1:sha256:" ||
lowercase_hex(request_digest)
```

verifierは`authorization_details`をset包含ではなくexact setとして比較し、要素数が
厳密に1であることを確認する。別purpose、scope、output schema等がrequestの意味を
変える場合、それらは該当request kindのtranscriptへ含め、別の未結合claimとして
追加しない。

## 7. Bound request kinds

v1は次の4種類だけを定義する。記載順がcanonical field順である。

### 7.1 `ASSIGNMENT_OFFER`

| field | encoding | source |
| --- | --- | --- |
| `participant_id` | UTF-8 | accountable Human offerer |
| `event_id` | UTF-8 | idempotency/audit ID |
| `task_id` | UTF-8 | target Task |
| `assignment_id` | UTF-8 | new Assignment |
| `target_participant_id` | UTF-8 | offered Participant |
| `role` | ASCII enum | offered role |
| `authority_digest` | raw 32 bytes | exact delegated/offered authority |
| `due_at` | absentまたは12 bytes | optional due time |

`offered_at`はverifier clockから生成するため、requestへ含めない。

### 7.2 `ASSIGNMENT_TRANSITION`

| field | encoding | source |
| --- | --- | --- |
| `participant_id` | UTF-8 | accountable Human |
| `event_id` | UTF-8 | idempotency/audit ID |
| `task_id` | UTF-8 | current Assignmentから照合するTask |
| `assignment_id` | UTF-8 | transition target |
| `operation` | ASCII enum | `ACCEPT`、`DECLINE`、`RELEASE`、`REVOKE`、`FULFILL` |
| `expected_revision` | uint64 | compare-and-swap revision |
| `detail` | UTF-8またはabsent | bounded diagnostic detail |
| `evidence_ref` | UTF-8またはabsent | immutable evidence reference |

current statusやauthority digestはtrusted snapshotのrevisionで特定されるため重複して
encodeしない。event `at`はverifier clockから生成する。

### 7.3 `ASSIGNMENT_DELEGATION`

| field | encoding |
| --- | --- |
| `participant_id` | UTF-8 |
| `event_id` | UTF-8 |
| `parent_task_id` | UTF-8 |
| `parent_assignment_id` | UTF-8 |
| `expected_revision` | uint64 |
| `detail` | UTF-8またはabsent |
| `evidence_ref` | UTF-8またはabsent |
| `decision_id` | UTF-8、trusted `VerifiedDelegation`との照合対象 |
| `child_event_id` | UTF-8 |
| `child_task_id` | UTF-8 |
| `child_assignment_id` | UTF-8 |
| `target_participant_id` | UTF-8 |
| `role` | ASCII enum |
| `authority_digest` | raw 32 bytes |
| `due_at` | absentまたは12 bytes |

`VerifiedDelegation`は別のpolicy verifierによるtrusted inputであり、既存TaskCoord
validatorがparent、child、Participant、authority digestとの一致を検査する。Human
requestは結果の権限範囲を固定する`authority_digest`を束縛し、policy evidenceの格納先を
暗号上のHuman意思へ重複して結合しない。

### 7.4 `INTERACTION_APPEND`

| field | encoding |
| --- | --- |
| `participant_id` | UTF-8 |
| `event_id` | UTF-8 |
| `interaction_id` | UTF-8 |
| `task_id` | UTF-8 |
| `assignment_id` | UTF-8 |
| `kind` | ASCII enum |
| `in_reply_to` | UTF-8またはabsent |
| `supersedes` | UTF-8またはabsent |
| `finality` | ASCII enumまたはabsent |
| `content_ref` | UTF-8またはabsent |
| `content_digest` | raw 32 bytesまたはabsent |
| `evidence_ref` | UTF-8またはabsent |

本文は含めず、そのexact bytesを固定する`content_digest`を使用する。event `at`は
verifier clockから生成する。

## 8. Verification algorithm

verifier adapterは一つの閉じたcall boundaryで次を行わなければならない。外部ingressは
Step 2から9の認証を完了するまでAssignmentを参照せず、対象の存在、revision、statusを
応答差として公開してはならない。

1. strict decode済みtyped requestからSection 5のdigestとcontextを再計算する。
2. accepted TLS/session stateから導出したexpected bindingの
   `request_context_sha256`がSection 5.3と一致することを確認する。
3. trusted operation-authority key、issuer、audience、revocation、time policyにより
   Identity Grantを検証する。
4. `authorization_details`がSection 6の一要素exact setであることを確認する。
5. grantが許可したActor keyでSession Binding Statementを検証する。
6. grant hash、accepted endpoint、TLS exporter、request context、nonce、expiry、
   optional attestation binderをlocal expected stateと比較する。
7. configured ASB identity policyを評価する。
8. verified grantとstatementから`actor_id`、`authorization_id`、`proof_id`、nonce、
    有効期間を導出する。
9. Participant resolverからrequestのParticipantを解決し、schema、ID、
   `kind = HUMAN`、`status = ACTIVE`を確認する。Step 2から9のfailureは、外部ingressで
   同じauthorization failureとして返す。
10. この認証済みacceptanceをexact request digestへ再結合したまま、trusted application
    snapshotをloadし、request対象、revision、operation-specific status policyを確認する。
11. delegationの場合は、Step 2から10の検証後にdeployment-controlled
    `DelegationDecisionVerifier`を呼び、trusted policy stateから`VerifiedDelegation`を
    取得する。client-supplied policy projectionを使用してはならない。
12. 同じtyped requestとtrusted snapshotからTaskCoord operation/eventをmemory上で構築し、
    既存state machineによるsemantic validationを完了する。
13. distributed deploymentではshared replay storeへone-shot keyをatomic insertする。
14. 検証済みtransition/eventを返す。durable Store commitはdeployment adapterが別途行う。

raw requestから`AuthenticatedOperation`または`AuthenticatedInteraction`を自己申告で
構築し、Step 1から13を迂回してはならない。

## 9. Projection rules

TaskCoordへ渡すprojectionは次のように導出する。

| field | source |
| --- | --- |
| `participant_id` | digest対象request + trusted HUMAN registry resolution |
| `actor_id` | verified Identity Grant subject/D4 Actor |
| `authorization_id` | verified grant `jti` |
| `proof_id` | verified Session Binding Statement `jti` |
| `verifier_nonce` | verified Session Binding Statement nonce |
| `issued_at` | grantとstatementの遅い方 |
| `expires_at` | grant、statement、trusted attestation/local acceptance windowの最も早い期限 |

projectionは未検証token、HTTP header、request JSON内の同名fieldから値を取得しては
ならない。

## 10. Freshness, replay, and retry

- ASB session proof nonceはone-shotでなければならない。
- replay keyは既存ASB profileのgrant hash、audience、TLS exporter hash、request context
  hash、nonceを含まなければならない。
- 全検証後、TaskCoord projectionを返す前にreplay insertを行う。
- state machineがrequestを拒否した場合は検証済みresultを返さず、replay insertも行わない。
- productionでreplay storeがmissingまたはunavailableの場合はfail closedとする。
- 同じTLS connection上の異なるrequestは異なるrequest contextとfresh proofを使用する。
- Store-level idempotencyは同じproof、時刻、snapshotを含む同一durable recordの再commitに
  限られる。新しいASB proofでは`proof_id`、nonce、verifier時刻が変わるため、同じevent ID
  でも以前の結果を自動的には返さない。
- execute応答を失った場合、結果はunknownとしてtrusted Store stateとevent historyを読み、
  最初のcommit有無をreconcileする。fresh proofによるblind retryは、最初のcommitが成功して
  いればrevision conflictまたはevent conflictになり得る。このconflictを「最初のoperationが
  失敗した」と解釈してはならない。
- このdemo ingressには外部向けstatus/read endpointとstable business-request outcome journalが
  ない。cross-proof end-to-end idempotencyを必要とするdeploymentは、request digestに束縛した
  operation reservationとresponseをTaskCoord mutationとatomicに永続化しなければならない。
- replay consumeとTaskCoord Store commitは現実装では同一transactionではない。
  commit error後も結果をunknownとしてreconcileする。このprofileはexactly-onceを主張しない。

## 11. Participant status

statusはtokenやdigestへ固定せず、operation受理時に再解決する。v1 adapterは実装する
4種類のrequestについて`ACTIVE` Humanを要求する。

将来、`SUSPENDED`または`REVOKED` Humanにもauthority-reducing operationだけを許可する
場合は、revocation/withdrawal専用entrypointと明示的local policyを定義する。一律に
inactive Humanへ新しい権限を与えてはならない。

## 12. Privacy

authorization detailとrequest contextが運ぶapplication値はdigestだけである。token、
projection、audit recordへHumanの直接連絡先や本文を追加してはならない。

SHA-256 digestは暗号化ではない。低entropy requestの内容秘匿をdigestだけに依存しては
ならない。v1 requestは一意なevent IDを含むが、秘密性が必要なartifactは暗号化storageへ
置き、TaskCoordはopaque referenceとdigestだけを保持する。

## 13. Explicit non-goals

このprofileは次を証明または実装しない。

- gateway assertionとは別のauthenticated-Human evidence;
- Human-held keyのpossessionまたはexact requestへのHuman signature;
- Humanの同時的な存在やliveness;
- exact requestをHumanに表示し、HumanがUIで確認した事実;
- 実在Humanの本人確認または法的に有効な同意;
- Humanの判断、回答、能力、正しさ;
- operation authorityまたはgateway compromiseへの耐性;
- Human discovery、contact vault、Email/SNS/TEL delivery;
- Split Agent planner、quorum、shard topology、Action lifecycle;
- AssignmentからAction authorizationへの自動変換;
- Human `FINAL` responseからAssignment fulfillment、Action success、receiptへの自動変換;
- delegation scope narrowingそのもの;
- availability、Human latency、timeout semantics;
- Humanであることを理由とするattestationの一律必須化。

Human IdPとAgent Managerを別authorityにするdeploymentはv1の単一operation-authority
modelに含まれない。その場合は、別署名Human authorization artifactのexact-byte digestを
Identity Grantへ束縛するversioned extensionが必要である。二つのauthorityを暗黙に
同一視してはならない。

## 14. Conformance tests

少なくとも次を検査する。

- 全request kindの固定canonical digest vector;
- request kindをまたぐcross-type substitution拒否;
- participant、Actor、event、Task、Assignment、operation、revision、target、role、
  authority digest、due timeの一項目差し替え拒否;
- Interaction content ref/digest、reply、supersession、finality差し替え拒否;
- wrong issuer、audience、profile、confirmation key、grant hash、TLS exporter、request
  context、nonceの拒否;
- missing、future、expired、revoked grant/proofの拒否;
- inactive/non-Human Participantの拒否;
- proof未検証時はAssignmentをlookupせず、missing、stale、wrong-taskを同じ外部errorへ
  collapseすること;
- replayの逐次および並行拒否;
- replay store unavailable時のfail-closed;
- verified grant/statement `jti`のprojectionへの正しい伝播;
- projection expiryが構成要素の最短期限であること;
- authorization detail、context、projectionにHuman contactや本文がないこと;
- HumanがAgent discovery結果へ入らないこと。

## 15. Implementation boundary

repository implementationは次の境界に置く。

- canonical request digestとASB adapter: `pkg/taskcoord/asbbinding`;
- Task responsibility、state machine、Interaction: `pkg/taskcoord`;
- JWT signature、grant/session proof、identity policy、replay: 既存
  `pkg/clients`と`pkg/atls/identitypolicy`;
- Participant registry: `taskcoord.ParticipantResolver`;
- TLS/aTLS accepted bindingの導出: ASB transport/verifier adapter;
- durable Store、distributed replay、contact relay: deployment adapter。

Reachability consent、approval、revocationのASB write wrappersはv1の初期実装範囲外であり、
接続されるまではtrusted internal APIとして扱う。

現実装の`Evidence.Options.ExpectedBinding`は、TLS/aTLSを受理したtrusted transport adapterが
導出した値を渡すための境界である。`pkg/taskcoord/asbbinding`自身はincoming connectionから
endpoint keyやTLS exporterを導出するTLS 1.3/mTLS受付serviceを含む。受付serviceの構成と
実行可能なdemoは
[`asb-taskcoord-human-ingress-demo.md`](asb-taskcoord-human-ingress-demo.md)で定義する。
外部requestが指定したheaderやJSON値を`ExpectedBinding`として使用してはならない。

低レベル`Profile`はcallerから渡されたcurrent Assignmentをtrusted Store snapshotとして扱い、
transitionをStoreへcommitしない。`Ingress`は4種類の
`gateway-asserted-for-human` requestを受け、request
IDからsnapshotを自身でloadし、profile callとStore commitを一つのapplication boundaryに
置く。Offerはrevision 1のAssignmentを作成し、通常transitionはrevision CASを行い、
delegationはparent transition、child offer、provenance edgeをatomic commitする。

`ASSIGNMENT_DELEGATION`はdeploymentが`DelegationDecisionVerifier`を設定した場合だけ有効に
なる。IngressはASB grant/session proofを検証してからverifierを呼び、返されたdecisionと
parent、child、Participant、authority digestの一致をstate machineで検査する。wire schemaは
`verified_delegation`、`policy_ref`等のclient-supplied policy projectionを受理しない。
低レベル`Profile.Delegate`も同じverifierを必須とし、caller-supplied
`VerifiedDelegation`を受理しない。verifierへ渡すAssignmentとrequestはdeep-copyし、callbackが
pointer fieldを書き換えてもASB-bound requestやtrusted snapshotを変更できないようにする。

Ingressのpending challengeはTTLに加えて、TLS connection単位、verified client public key単位、
Ingress instance全体の有限quotaで制限する。全体quotaは異なるconnection keyを作ることで回避
できず、consumeとexpiryは同じmutex下で全counterを解放する。

## 16. Wire format and JSON Schema boundary

canonical binding profile自体はJSON表現へ依存しない。repositoryのHTTP受付serviceは独立した
`schemas/asb-taskcoord-human-ingress-v1.schema.json`でchallenge/execute envelopeを検証する。
公開済みschema IDはrequest-only unionのまま維持し、endpoint実装はその
`challengeEnvelope`または`executeEnvelope`部分schemaを選んで検証する。これにより、
challenge形状をexecute routeへ送るcross-route substitutionをchallenge lookupより前に拒否する。
認証済みprojectionやASB evidenceは既存Task Participant durable-document unionへ追加しない。
JSON Schemaによるshape検査は署名、issuer、audience、live TLS binding、registry state、
current revision、replayを証明しない。

challenge success、4種類のexecute success、公開error bodyは
`schemas/asb-taskcoord-human-ingress-response-v1.schema.json`で定義する。success status/bodyは
challengeの`201`とexecuteの`200`を維持する。全応答はserver生成の`X-Request-ID`を持ち、
error bodyは既存string `error`に`code`、`retryable`、`request_id`を追加する。公開errorの
正確なstatus/code表、`Retry-After: 1`、raw内部errorのredaction、結果不明executeを
自動retryしない境界は
[`asb-taskcoord-human-ingress-demo.md`](asb-taskcoord-human-ingress-demo.md)で定義する。
relay専用HTTP ingressとAction HTTP ingressはこのprofileの実装範囲外である。

JSON等を受けるtransport adapterは、1 MiBの上限、unknown member、duplicate member、invalid
UTF-8を拒否してから本profileのtyped requestを構築しなければならない。将来wire formatを
標準化する場合は、durable state schemaとは別のversioned schemaとして定義する。
