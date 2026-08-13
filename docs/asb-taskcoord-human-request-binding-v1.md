# ASB TaskCoord Human Request Binding v1

Status: Experimental / Repository-local

本書は、Split Agentのapplication substrateでHumanが行うTaskCoord requestを、
既存のAgent Secure Binding (ASB) acceptanceへ最小限の追加情報で結合する
application profileを定義する。本書はHumanをAgentとして扱わず、新しい暗号方式、
Human専用token、transport protocol、またはHuman identity proofing方式を定義しない。

本書の`MUST`、`MUST NOT`、`SHOULD`、`MAY`は規範要件を表す。

## 1. Profile identifiers

| 項目 | 値 |
| --- | --- |
| Application profile | `asb.taskcoord-human-request/v1` |
| Request digest domain | `ASB-TASKCOORD-HUMAN-REQUEST-v1` |
| Request context domain | `ASB-TASKCOORD-HUMAN-CONTEXT-v1` |
| Authorization detail prefix | `urn:asb:taskcoord-human-request:v1:sha256:` |

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

verifier adapterは一つの閉じたcall boundaryで次を行わなければならない。Step 1から
10の副作用を伴わない検査は、同じ受理条件を維持する限り並べ替えてよい。

1. strict decode済みtyped requestからSection 5のdigestとcontextを再計算する。
2. trusted application snapshotとParticipant resolverを使い、request対象、revision、
   registry recordを解決する。
3. recordのschema、ID、`kind = HUMAN`、operation-specific status policyを確認する。
4. accepted TLS/session stateから導出したexpected bindingの
   `request_context_sha256`がSection 5.3と一致することを確認する。
5. trusted operation-authority key、issuer、audience、revocation、time policyにより
   Identity Grantを検証する。
6. `authorization_details`がSection 6の一要素exact setであることを確認する。
7. grantが許可したActor keyでSession Binding Statementを検証する。
8. grant hash、accepted endpoint、TLS exporter、request context、nonce、expiry、
   optional attestation binderをlocal expected stateと比較する。
9. configured ASB identity policyを評価する。
10. verified grantとstatementから`actor_id`、`authorization_id`、`proof_id`、nonce、
    有効期間を導出する。
11. 同じtyped requestとtrusted snapshotからTaskCoord operation/eventをmemory上で構築し、
    既存state machineによるsemantic validationを完了する。
12. distributed deploymentではshared replay storeへone-shot keyをatomic insertする。
13. 検証済みtransition/eventを返す。durable Store commitはdeployment adapterが別途行う。

raw requestから`AuthenticatedOperation`または`AuthenticatedInteraction`を自己申告で
構築し、Step 1から12を迂回してはならない。

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
- application retryは同じevent IDとrequest内容、新しいASB proofを使用する。Storeの
  idempotencyが以前の結果を返す。
- replay consumeとTaskCoord Store commitは現実装では同一transactionではない。
  commit失敗時はfresh authorization/proofによるretryを要求する。このprofileは
  exactly-onceを主張しない。

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

- 実在Humanの本人確認、liveness、法的同意、UI操作の事実;
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
transitionをStoreへcommitしない。`Ingress`はrequest IDからsnapshotを自身でloadし、profile
callとrevision CAS commitを一つのapplication boundaryに置く。

## 16. Wire format and JSON Schema boundary

canonical binding profile自体はJSON表現へ依存しない。repositoryのHTTP受付serviceは独立した
`schemas/asb-taskcoord-human-ingress-v1.schema.json`でchallenge/execute envelopeを検証する。
認証済みprojectionやASB evidenceは既存Task Participant durable-document unionへ追加しない。
JSON Schemaによるshape検査は署名、issuer、audience、live TLS binding、registry state、
current revision、replayを証明しない。

JSON等を受けるtransport adapterは、1 MiBの上限、unknown member、duplicate member、invalid
UTF-8を拒否してから本profileのtyped requestを構築しなければならない。将来wire formatを
標準化する場合は、durable state schemaとは別のversioned schemaとして定義する。
