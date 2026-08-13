# Task Participant v1 実装仕様

Status: Experimental / Repository-local

本書は `pkg/taskcoord` と `schemas/task-participant-v1.schema.json` に実装された
Task Participant v1 の仕様を日本語で集約したものである。IETF標準、外部task
protocolとの相互運用仕様、または本番運用の適合宣言ではない。

本書では、`MUST`を実装上必須、`MUST NOT`を禁止、`SHOULD`を合理的な理由が
ない限り推奨される要件として用いる。

## 1. 目的

Taskを進行させる責任主体として、Human、Agent、要件を満たす自動サービスを
共通の`Participant`で表現する。ただし、共通の入出力抽象を持つことは、Humanを
Agentと同一視することを意味しない。

本仕様が分離する主要概念は次のとおりである。

| 概念 | 意味 |
| --- | --- |
| Participant | Taskに対して責任を引き受ける主体 |
| Actor | 認証済みoperationを実際に送信する主体 |
| Assignment | TaskとParticipant間の持続的な責任関係 |
| Action state | `RUNNING`や`WAITING`等の実行状態 |
| Executor lease | 実行環境に与える短期の実行権限 |
| Interaction | 問い合わせ、複数回答、訂正、撤回の履歴 |
| Discovery | Agentだけを対象とする検索 |
| Human reachability | 明示的同意に基づくHumanへの仲介接続 |

Human向けUIやgatewayが`Actor`となり、実在のHumanが`Participant`となることが
できる。両IDは一致を仮定せず、authorizationが両者と対象operationを結合する。

## 2. 適用範囲と責務の優先順位

適合性は次の順で判定する。

1. Goのconstructor、`Validate`、Store実装が意味上の不変条件を定義する。
2. JSON Schemaが永続documentの構造と基本formatを定義する。
3. 本書と`docs/task-participant-v1.md`が設計意図と運用境界を説明する。

JSON Schemaに通ることだけでは、時系列、registry binding、authorization、
revocation、idempotency等の意味上の適合を証明しない。受信側はSchema検証に加え、
対応するGo validatorとStore境界の検査を実行しなければならない。

## 3. Participant

### 3.1 種別

| `kind` | 定義 | Agent検索 |
| --- | --- | --- |
| `HUMAN` | 実在または組織内で識別された人 | 禁止 |
| `AGENT` | Agentとして登録された自律的主体 | 許可 |
| `AUTOMATED_SERVICE` | Assignmentを受けられる適格な自動サービス | 禁止 |

APIやToolは存在するだけでは`AUTOMATED_SERVICE`にならない。Assignment受領、
durable state、認証済み結果報告、delegation policyへの対応が必要である。

### 3.2 Registry status

`Participant.status`は`ACTIVE`、`SUSPENDED`、`REVOKED`のいずれかである。これは
registry上の利用可否であり、TaskやActionの実行状態ではない。

新規Assignment、Agent検索、Human matching、reachability grantの発行・取得は、
必要なParticipantが`ACTIVE`であることを要求する。Human matchingとgrant取得は
読み出し時にもHumanのstatusを再解決する。

### 3.3 Human identity

Humanの`identity_ref`は内部resolverで解決するopaque referenceでなければならない。
次の値をHuman identityとして公開documentに格納してはならない。

- HTTPまたはHTTPSの公開profile;
- `mailto:`、`tel:`、`sms:`、`sip:`、`sips:`による直接連絡先。

Homepage、SNS profile、公開directoryに連絡先が掲載されていても、それはAgentから
の検索、連絡、二次利用への同意を意味しない。

## 4. Assignment lifecycle

Assignmentは責任関係を表し、次の状態遷移だけを許可する。

```text
OFFER -> OFFERED -> ACCEPT  -> ACCEPTED -> FULFILL -> FULFILLED
                  |                      -> RELEASE -> RELEASED
                  |                      -> REVOKE  -> REVOKED
                  -> DECLINE -> DECLINED
                  -> REVOKE  -> REVOKED
```

- `ACCEPT`、`DECLINE`、`RELEASE`、`FULFILL`はAssignmentを所有するParticipantが
  実行しなければならない。
- `REVOKE`は別途認証されたoperationであり、assignee operationとは区別される。
- terminal stateからの追加遷移は禁止する。
- revision compare-and-swapによりlost updateを防止する。
- event timestampは現在snapshotより前であってはならない。
- `WAITING`、`PAUSED`、`ORPHANED`、timeout、実行成否をAssignment stateとして
  追加してはならない。これらはTaskまたはAction lifecycleの責務である。

Humanの応答待ちでもAssignmentは通常`ACCEPTED`のままである。応答期限超過は、
Assignment失敗、Action失敗、executor orphaningを自動的には意味しない。

## 5. Delegation

`DELEGATE`は`ACCEPTED`の親Assignmentに対する認証済みeventである。

- delegatorは親AssignmentのParticipantかつ`may_delegate = true`でなければならない。
- self-delegationは禁止する。
- 親Assignmentは`ACCEPTED`のままrevisionだけを進める。
- 子Assignmentを`OFFERED`で生成する。
- 親event、子offer、`DelegationRecord`を一つのatomic commitとして保存する。
- child authorityがparent authorityより適切に限定されていることは、外部policy
  verifierが`VerifiedDelegation`として証明する。digestの一致だけからscope narrowing
  を推論してはならない。

Delegationは責任の自動移転、親Assignmentのrelease、Task dependencyの生成を
意味しない。

## 6. Interaction / response

Humanの遅延、問い合わせ、複数回答、訂正、撤回はAssignment stateではなく、
append-onlyな`InteractionEvent`として記録する。

| kind | 必須関係 | 内容 |
| --- | --- | --- |
| `QUESTION` | 新規または既存thread | 問い合わせ |
| `RESPONSE` | `in_reply_to` | 同一質問への回答。複数存在可能 |
| `CORRECTION` | `in_reply_to`、`supersedes` | 自分の過去回答を新しい内容で訂正 |
| `WITHDRAWAL` | `in_reply_to`、`supersedes` | 過去回答を削除せず撤回 |

`RESPONSE`と`CORRECTION`は`INTERIM`または`FINAL`を宣言する。`FINAL`はその
回答versionについてのauthor assertionにすぎず、Interaction、Assignment、Taskを
自動的にcloseまたはfulfillしない。後続訂正や別Participantの回答を禁止しない。

contentはinline保存せず、`content_ref`と64文字のlowercase hex
`content_digest`で参照・固定する。訂正や撤回は既存eventを上書きしてはならない。
直接連絡先schemeを`content_ref`として使用してはならない。

## 7. Agent discovery

Agent discoveryはHuman reachabilityとは別のinterfaceである。

- `AgentDiscoveryRecord.kind`は常に`AGENT`でなければならない。
- 登録時と検索時に`participant_id`をregistryへ再解決し、active Agentであることを
  確認する。serialized `kind`だけを信頼してはならない。
- HumanをAgentへ変換して登録した場合は`ErrHumanNotDiscoverable`とする。
- `AUTOMATED_SERVICE`を暗黙にAgentへ変換してはならない。
- `invocation_ref`はabsolute HTTPS referenceでなければならない。
- capability検索は完全一致とし、`*`と`?`による列挙を禁止する。
- 1 queryの結果上限は20件とする。
- 未発効、期限切れ、inactiveになったrecordを返してはならない。

このdirectoryはapplication-layer stubであり、network discovery protocolではない。

## 8. Human matchingとreachability

### 8.1 基本フロー

```text
HumanMatchConsent
       |
       v
AuthenticatedHumanMatchQuery -- exact match --> HumanMatchCandidate
                                                     |
                                              Human approval
                                                     |
                                                     v
                                      HumanReachabilityGrant
                                                     |
                                  AuthenticatedReachabilityAccess
                                                     |
                                                     v
                                            HTTPS relay session
```

HumanをAgent directoryへ含めるのではなく、明示的opt-inに基づく別経路を使用する。

### 8.2 HumanMatchConsent

一つのconsentは次のscopeをすべて固定する。

- internal Human Participant ID;
- Agent requester ID;
- Humanとrequesterのpairに束縛したopaque `candidate_id`;
- purpose;
- capability;
- `EMAIL`、`SNS`、`TEL`のいずれかのbrokered channel;
- HTTPS contact-request relay;
- `granted_at`から`expires_at`までの有効期間;
- Actor、authorization、proofの内部監査参照。

同じ`candidate_id`を別Humanまたは別requesterへ再束縛してはならない。同一scopeで
有効期間が重なるconsentは、先行consentが適切にrevocation済みでない限り拒否する。

### 8.3 Matching queryと結果

`AuthenticatedHumanMatchQuery`は完全なqueryに加え、Actor ID、authorization ID、
proof ID、verifier nonce、issued/expiry時刻を持つ。directoryは構造と現在時刻を
検査するが、署名検証、policy判断、nonceの一回限り使用は外部verifierの責務である。

queryはrequester、purpose、capability、channelを完全一致させなければならず、
wildcardを禁止し、結果を最大20件に制限する。

`HumanMatchCandidate`がrequesterへ返せる値は次だけである。

- pairwise `candidate_id`;
- capability;
- channelの種別;
- HTTPS contact-request relay reference;
- expiry。

Human Participant ID、consent ID、Actor、authorization、proof、生のEmail、SNS account、
電話番号を結果に含めてはならない。

### 8.4 HumanReachabilityGrant

Humanがcontact requestを承認した後、brokerは内部のconsentとapproval evidenceを検査し、
requester向けgrantを発行できる。

- grantはcandidate、requester、purpose、capability、channel、有効期間をconsentと
  完全一致させる。
- grantの有効期間はconsentを超えてはならず、発行時点で有効でなければならない。
- requester向けgrantはHTTPS relay sessionだけを公開する。
- Human ID、consent ID、approval Actor、authorization、proof、生の連絡先をgrantへ
  含めてはならない。approval evidenceはbroker内部に保持する。
- grant取得には完全なscopeとfresh verifier projectionを持つ
  `AuthenticatedReachabilityAccess`を要求する。
- requester mismatch、scope mismatch、missing、expired、revokedは同じ`ErrNotFound`
  として扱い、存在確認によるprobe情報を減らす。

### 8.5 Revocation

- Humanは`HumanMatchConsentRevocation`でmatching consentを撤回できる。
- consent revocationはそのconsentから発行済みのgrantも直ちに無効化する。
- Humanまたは正しいAgent requesterは`HumanReachabilityRevocation`でgrantを撤回できる。
- revocationはimmutable eventとして保存し、対象recordを削除または上書きしない。
- exact retryはidempotentとし、同じevent IDで内容が異なる場合はconflictとする。

## 9. Privacyと連絡先管理

このpackageはEmail address、SNS account、電話番号を保存しない。production実装は
連絡先を別の暗号化vaultに保持し、opaque candidateまたはrelay sessionからのみ
解決しなければならない。

relay referenceは次を満たさなければならない。

- absolute HTTPS URI;
- userinfoなし;
- queryなし;
- fragmentなし。

これは構造上のguardrailであり、完全なDLPではない。production relayはHTTPS path、
message body、log、trace、metric、diagnosticへの生の連絡先混入を別途防止し、access
control、rate limit、abuse monitoring、retention、deletion、auditを実装すべきである。

## 10. 認証済みprojection

`AuthenticatedOperation`、`AuthenticatedInteraction`、
`AuthenticatedHumanMatchQuery`、`AuthenticatedReachabilityAccess`は、外部ASB verifier
が検証済み結果をapplication modelへ投影するための型である。

projectionは少なくとも次を具体的対象へ束縛する。

- accountable Participant;
- actual Actor;
- authorizationとproof;
- 対象operationまたはquery全体;
- verifier nonce;
- issued/expiry window。

`pkg/taskcoord`はbinding、必須値、時刻範囲を検査するが、token、signature、holder-of-key、
authorization policy、nonce replay storeを実装しない。呼出側は未検証のrequestから
projectionを自己申告で生成してはならない。

## 11. Split Agentのsubstrateとしての利用

Split Agentを複数のAgent、Tool、Humanが協調する上位applicationとして構成する場合、
このpackageはParticipant、責任関係、認証済みoperation、Interactionを扱うbinding
substrateとして使用できる。ただし、Split Agent全体のpolicy plane、planner、executor、
transportを提供するものではない。

HumanはSplit Agentの一部として動作できるが、`AGENT`またはAgent shardへ変換しては
ならない。Humanが取り得る役割は次のとおりである。

| 役割 | 表現 | 境界 |
| --- | --- | --- |
| Taskの責任主体 | `Participant(kind = HUMAN)`と`Assignment` | Agent discoveryの対象外 |
| 質問者・回答者 | `InteractionEvent.participant_id` | gatewayのActor IDと分離 |
| 承認・取消の意思主体 | 認証済みoperationの`participant_id` | Interaction上の回答だけではAction authorizationにならない |
| Agentからの連絡先 | consent、candidate、reachability grant | 生の連絡先をAgentへ公開しない |

Humanによるoperationは次の経路を通す。

```text
Human
  -> Human-facing UI / gateway (Actor)
  -> external verifier
  -> AuthenticatedOperation / AuthenticatedInteraction
  -> Assignment / Interaction store
```

verifierは実在のHuman Participant、実際にrequestを送信したgateway Actor、authorization、
proof、対象operation全体、freshnessを結合する。gatewayのservice identityをHuman identity
として記録したり、Humanの自己申告だけから認証済みprojectionを生成したりしては
ならない。

Split Agent側は次の分離を維持しなければならない。

- `Assignment`は誰がTaskの責任を持つかを表し、保護されたside effectの実行許可を
  表さない。
- Humanの`FINAL` responseは回答versionの表明であり、`ActionAuthorization`、
  Assignmentの`FULFILL`、Actionの成功を自動的に生成しない。
- Action authorization、execution outcome、artifact receiptはそれぞれ独立に検証する。
- Human待ちはInteractionまたはTask/Actionのwait conditionとして表し、Assignmentへ
  `WAITING`や`FAILED`を追加しない。
- 独立して責任を持ち、検索またはdelegationされるsub-Agentには固有のAgent
  Participantを与える。内部runtime componentや単なるToolまで自動的にParticipantへ
  昇格させない。
- Humanの回答、承認、訂正をprovenanceへ含める場合はimmutable event IDまたはdigestを
  参照し、生の内容や連絡先をexecution receiptへ複製しない。

上位のSplit Agent application profileは、requestの認可判断、永続state、帰属、返却対象を
変える値だけを同じ検証contextへ束縛する必要がある。purpose、実行対象、期待するoutputは、
該当operationに存在し、その判断または結果を変える場合に限って束縛する。このprofileの
wire formatとpolicy semanticsは本仕様のout of scopeであり、core modelへ暗黙に組み込まない。

Human operationをASBへ最小束縛するapplication profileは
[`asb-taskcoord-human-request-binding-v1.md`](asb-taskcoord-human-request-binding-v1.md)
で定義する。TLS 1.3/mTLSを直接終端する受付serviceと実行可能なdemoは
[`asb-taskcoord-human-ingress-demo.md`](asb-taskcoord-human-ingress-demo.md)を参照する。

## 12. 永続document

JSON Schemaが扱うdurable documentは次の10種類である。

| document | schema identifier |
| --- | --- |
| Participant | `asb.task-participant/v1` |
| Assignment | `asb.task-assignment/v1` |
| Dependency | `asb.task-dependency/v1` |
| DelegationRecord | schema identifierなし、field shapeで識別 |
| InteractionEvent | `asb.task-interaction-event/v1` |
| AgentDiscoveryRecord | `asb.agent-discovery-record/v1` |
| HumanMatchConsent | `asb.human-match-consent/v1` |
| HumanMatchConsentRevocation | `asb.human-match-consent-revocation/v1` |
| HumanReachabilityGrant | `asb.human-reachability-grant/v1` |
| HumanReachabilityRevocation | `asb.human-reachability-revocation/v1` |

strict decoderは次を要求する。

- 最大1 MiB;
- valid UTF-8;
- unknown fieldなし;
- trailing JSON valueなし;
- 対応する意味validatorに合格。

`Authenticated*` query、definition、transition requestは内部application projectionであり、
上記durable document unionには含めない。

## 13. Storeとatomicity

- `CommitAssignment`はrevision CAS、完全snapshot、transition event deduplicationを
  一つのatomic commitで行う。
- `CommitDelegation`は親event、子offer、delegation provenanceをatomicに保存する。
- `AppendInteractionEvent`はappend-onlyかつevent ID単位でidempotentにする。
- Interaction appendはAssignment snapshotやrevisionを変更してはならない。
- `AgentDirectory`、`HumanReachabilityDirectory`、Assignment `Store`を別境界とする。
- production通知を行う場合、outbox entryをstate変更と同じDB transactionへ含める。

`MemoryStore`、`MemoryAgentDirectory`、`MemoryReachabilityDirectory`は並行安全な
in-process stubであり、restart durability、replication、failoverを保証しない。

## 14. JSON Schema validation

SchemaはJSON Schema Draft 2020-12を使用する。CIは次を検査する。

- meta-schemaへの適合;
- `date-time`と`uri`を含むformat assertion;
- 全10 durable documentのpositive fixture;
- HumanのAgent discovery化、公開Human identity、直接連絡先relay、grantへの生Email
  追加、不正date-timeのnegative fixture。

Schema検証はingressで再利用できるが、現在はCI/test gateとしてのみ実装されている。

## 15. 実装済み範囲

- Participant、Assignment、delegation、dependency model;
- Assignment lifecycleとCAS contract;
- immutable Interaction event;
- Agent-only discovery;
- requester-scoped Human consentとprivacy-minimized matching;
- relay-only reachability grantとrevocation;
- strict JSON decoder;
- Draft 2020-12 Schema validatorを含むCI test;
- concurrency-safe in-memory stub。

## 16. 未実装・out of scope

- database adapterと永続transaction backend;
- outbox publisher;
- HTTP、A2A、AGTP等のtransport binding;
- network Agent directoryまたはHuman matching protocol;
- Split Agentのplanner、policy plane、application binding profile;
- verifier adapterによる実token/signature/policy検証;
- nonce replay store;
- 暗号化contact vault;
- Email/SNS/TEL relayとdelivery;
- rate limit、abuse monitoring、retention/deletion運用;
- Participant status変更のaudit log;
- 別packageのAction lifecycleとの統合。

## 17. 最小適合チェックリスト

実装を本仕様に適合と呼ぶ前に、少なくとも次を確認する。

- [ ] HumanがAgent検索結果に入らない。
- [ ] Participant registry bindingを登録時と読出時に再確認する。
- [ ] Human matchingは明示的・期限付き・requester/purpose/capability/channel限定である。
- [ ] queryとgrant accessが外部verifierのfresh projectionを要求する。
- [ ] candidateとgrantにHuman ID、生の連絡先、内部consent/approval evidenceが出ない。
- [ ] consent/grantのexpiry、Participant status、revocationを読出時に再確認する。
- [ ] 連絡先vaultとrelayが`pkg/taskcoord`の外にある。
- [ ] Interactionがappend-onlyで、訂正・撤回が過去eventを消さない。
- [ ] Humanの回答・承認をAction authorizationまたはexecution successと同一視しない。
- [ ] Assignment stateとAction/Task stateを混同しない。
- [ ] JSON Schemaと意味validatorの両方を実行する。
- [ ] production adapterがatomicity、idempotency、audit、abuse対策を実装する。
