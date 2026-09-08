# Human Coordination conformance registry v1

Status: Developer Preview registry. It is repository-local, is not an IETF
standard, and does not make a production-readiness claim.

This document is the readable English/Japanese index for stable Human
Coordination profile and requirement identifiers. The machine-readable source,
including exact normative text, test names, evidence paths, and current status,
is
[`testdata/human-coordination-conformance-v1.json`](../testdata/human-coordination-conformance-v1.json).
Candidate cross-implementation topics are kept separately in the
[IETF review note](human-coordination-ietf-review.md); that note does not change
these repository-local requirements or create an IETF conformance claim.

## Profiles

| Profile ID | Purpose | Dependencies | Current maturity |
| --- | --- | --- | --- |
| `asb.human-coordination.core/v1` | Participants, Assignments, Interactions, delegation, and optional reachability | none | Developer Preview |
| `asb.human-coordination.task-action/v1` | Immutable Assignment-to-Action binding and independent execution lifecycle | core | Developer Preview; reference Store |
| `asb.human-coordination.relay/v1` | One consent-scoped Agent-to-Human gateway delivery intent | core | Developer Preview; local gateway only |
| `asb.human-coordination.http/v1` | TLS 1.3/mTLS challenge and execute ingress for Human operations | core | Developer Preview |
| `asb.human-coordination.production/v1` | Capability-specific deployment and qualification overlay | core; a declaration separately names each selected profile | Unavailable |

Task–Action, relay, Human matching, and production are capabilities, not
features implied by core conformance. SNP, TDX, TPM, and Cocos are separate
attestation or integration modules and are not Human Coordination profile
dependencies.

The production profile has one static manifest dependency: core. Its
capability-based declaration then lists every additional selected profile and
its qualification evidence. That claim-selection rule does not turn optional
profiles into static dependencies.

## Status terms

| Status | Meaning |
| --- | --- |
| `implemented` | Repository behavior exists and has mapped tests. It does not by itself prove live or production operation. |
| `reference-only` | The contract or in-process/test-double behavior exists, but a production implementation or durable cross-process guarantee is not supplied. |
| `unqualified` | A candidate or boundary exists, but the required live environment evidence has not been collected. |
| `unimplemented` | The named product capability is not implemented in this repository. |

Each requirement has one stable ID in both languages. Translation changes do
not create a new requirement. An incompatible semantic change requires a new
profile version or requirement ID; an implementation must not silently reuse a
v1 ID for different behavior.

## Human assurance vocabulary

These identifiers describe the evidence that links an accepted operation to a
Human Participant. They are verifier-derived audit vocabulary, not values that
a caller may select in a request.

| Assurance level | English | 日本語 | Current status |
| --- | --- | --- | --- |
| `gateway-asserted-for-human` | An authenticated gateway Actor exercises an operation-authority grant for the exact request attributed to a Human Participant. | 認証済みgateway Actorがoperation-authority grantを行使し、exact requestをHuman Participantへ帰属させる。 | Implemented by `asb.taskcoord-human-request/v1` |
| `authenticated-human-evidence` | A trusted Human authentication authority supplies separate evidence bound to the operation. | trusted Human authentication authorityがoperationへ束縛した別のHuman認証evidenceを供給する。 | Not implemented |
| `human-held-key-exact-request` | An enrolled Human-held key signs the domain-separated exact request and verifier context. | enrolmentされたHuman-held keyがdomain-separated exact requestとverifier contextへ署名する。 | Not implemented |

The current profile supplies only `gateway-asserted-for-human`. Its ASB
holder-of-key proof belongs to the gateway Actor, not the Human Participant.
It does not prove authenticated-Human evidence, Human-held-key possession,
Human liveness, Human-facing UI confirmation, or legal consent. Audit displays
must retain the distinct Actor and Participant identifiers and must not label a
gateway `proof_id` as a Human signature.

## Fixed Developer Preview decisions

- Assignment roles describe responsibility. They are not permission grants;
  authorization is verifier-local policy.
- One Assignment has zero or one immutable Action binding in v1. A second
  distinct Action is rejected atomically. Multi-Action aggregation requires a
  later profile version.
- A terminal Assignment cannot transition again, but its append-only
  Interaction history remains open to authorized audit and reconciliation
  events. An append cannot mutate the Assignment snapshot or revision.
- A realm is verifier-local policy context and identifier namespace. Human
  Coordination wire documents do not accept a caller-controlled realm field,
  and identifiers have no cross-realm meaning by default.
- Human matching is optional and consent-scoped. A Human is never published in
  Agent discovery, and matching results expose only bounded opaque candidate
  and relay references.
- Human TaskCoord ingress has the fixed assurance level
  `gateway-asserted-for-human`; stronger Human evidence requires a separately
  versioned profile and cannot be asserted by a caller field.

## Operation trust boundaries

An `implemented` requirement means that the mapped state-machine or application
behavior exists. It does not mean that every exported Go struct is safe as an
untrusted wire input. Developer Preview v1 has only these two external ASB
profiles:

| Surface | Boundary | Profile or owner | Debug evidence |
| --- | --- | --- | --- |
| Human Assignment offer, transition, delegation, and Interaction append | external-ASB | `asb.taskcoord-human-request/v1` | signed simulated ASB |
| Agent relay-intent authorization | external-ASB | `asb.taskcoord-agent-relay/v1` | signed simulated ASB |
| Agent Assignment and Interaction operations | trusted-internal | enclosing application verifier | fixture projection |
| Initial Action acceptance | trusted-internal | Task–Action application verifier | fixture projection |
| Later Action mutations and recovery operations | trusted-internal | Task–Action application verifier | fixture projection |
| Human matching | trusted-internal | reachability broker | fixture projection |
| Consent and reachability-grant administration | trusted-internal | reachability broker administration | fixture projection |
| Relay queue transaction | trusted-internal | adapter consuming the external relay projection | ASB-derived projection |
| Relay dispatch and reconciliation | trusted-internal | relay Worker | trusted Worker |

`trusted-internal` means the Go caller is inside the deployment TCB. Structural
validation of an `Authenticated*` value checks its fields, not its provenance.
An HTTP, RPC, plugin, queue, or other untrusted input must not be decoded or
copied directly into one of those projections. No Action, matching,
reachability-administration, or relay-Worker network route is supplied by this
repository. A deployment that runs an untrusted plugin in the same process must
isolate it or define and implement a separate exact ASB profile first.

The machine-readable `operation_boundaries` registry records the operations,
profile and transcript where present, Actor and Participant sources, realm,
freshness, replay, error, Store ordering, network exposure, debug evidence, and
positive or negative tests. The `human-taskcoord` boundary also records
`assurance_level = gateway-asserted-for-human`. Conformance tests reject an
unclassified surface, an internal surface that claims an external profile, or
an external profile without mapped tests.

## Core profile matrix

| ID | Status | English | 日本語 |
| --- | --- | --- | --- |
| `ASB-HC-CORE-001` | implemented | Keep accountable Participant and submitting Actor distinct, and bind both to the accepted operation. | 責任主体Participantと送信Actorを分離し、両者をaccepted operationへ束縛する。 |
| `ASB-HC-CORE-002` | implemented | Enforce Assignment transitions, revision comparison, and terminal rules; do not add Action execution states to Assignment. | Assignmentの遷移、revision比較、terminal規則を強制し、Action実行状態をAssignmentへ追加しない。 |
| `ASB-HC-CORE-003` | implemented | Bind every Assignment mutation and Interaction append to one fresh, exact authenticated operation. | Assignment mutationとInteraction appendを、freshでexactな認証済みoperationへ束縛する。 |
| `ASB-HC-CORE-004` | implemented | Treat roles as responsibility labels, not permissions. | roleはpermissionではなく責任labelとして扱う。 |
| `ASB-HC-CORE-005` | implemented | Commit delegation parent event, offered child, and immutable provenance atomically while the parent stays accepted. | parentをACCEPTEDに保ち、delegation event、OFFERED child、immutable provenanceをatomicにcommitする。 |
| `ASB-HC-CORE-006` | implemented | Preserve questions, responses, corrections, withdrawals, and lineage in append-only Interaction history. | 質問、回答、訂正、撤回とlineageをappend-onlyなInteraction履歴として保持する。 |
| `ASB-HC-CORE-007` | implemented | Allow authorized Interaction appends after Assignment terminal state without mutating its snapshot or revision. | Assignment terminal後も認証済みInteraction追記を許可し、snapshotとrevisionは変更しない。 |
| `ASB-HC-CORE-008` | implemented | Keep reachability grants opaque, scoped, revocable, and revalidate current consent and Participant state before use. | reachability grantをopaque、scoped、revocableにし、利用前にconsentとParticipantの現在状態を再検証する。 |
| `ASB-HC-CORE-009` | reference-only | A durable Store atomically provides revision CAS, exact deduplication, immutable state, and required outbox writes. | durable Storeはrevision CAS、exact deduplication、immutable state、必要なoutbox writeをatomicに提供する。 |
| `ASB-HC-CORE-010` | reference-only | Bind realm as verifier-local context and namespace; do not accept a caller-controlled realm field. | realmをverifier-local contextとnamespaceとして束縛し、caller-controlled realm fieldを受理しない。 |
| `ASB-HC-CORE-011` | implemented | Exclude Humans from Agent discovery; optional matching returns opaque bounded candidates without direct contacts. | HumanをAgent discoveryから除外し、任意matchingでは直接連絡先を含まないopaqueでboundedなcandidateだけを返す。 |

## Task–Action profile matrix

| ID | Status | English | 日本語 |
| --- | --- | --- | --- |
| `ASB-HC-TA-001` | implemented | Bind zero or one immutable Action to each Assignment and atomically reject a second distinct Action. | 各Assignmentへ0または1件のimmutable Actionだけを束縛し、2件目の異なるActionをatomicに拒否する。 |
| `ASB-HC-TA-002` | implemented | Keep Assignment responsibility and Action execution independent; neither lifecycle silently mutates the other. | Assignment責任とAction実行を独立させ、一方のlifecycleから他方を暗黙変更しない。 |
| `ASB-HC-TA-003` | implemented | Atomically verify the exact accepted Assignment and authorization, derive the initial Action, and commit its binding. | exactなACCEPTED Assignmentとauthorizationをatomicに検証し、initial Actionを導出してbindingをcommitする。 |
| `ASB-HC-TA-004` | implemented | Bind complete Action mutations and reapply them under Store CAS with current authorization and lease checks. | Action mutation全体を束縛し、現在のauthorizationとleaseを確認してStore CAS内で再適用する。 |
| `ASB-HC-TA-005` | implemented | Release the executor lease while waiting and resume only with the required current authenticated evidence. | WAITING中はexecutor leaseを解放し、必要な現在の認証済みevidenceでのみresumeする。 |
| `ASB-HC-TA-006` | implemented | Orphan on lease expiry without claiming failure; use higher fencing or reconciliation for takeover. | lease expiryを失敗と断定せずORPHANEDにし、takeoverには上位fencingまたはreconciliationを用いる。 |
| `ASB-HC-TA-007` | implemented | Use current topology and satisfaction state for dependency wait/resume; keep other waits as external escape paths. | dependency wait/resumeでは現在のtopologyとsatisfactionを使い、他のwaitはexternal escape pathとして扱う。 |
| `ASB-HC-TA-008` | reference-only | A production Store supplies multi-record atomicity, strict durable schemas, event reapplication, and restart durability. | production Storeはmulti-record atomicity、strict durable schema、event再適用、restart durabilityを提供する。 |
| `ASB-HC-TA-009` | reference-only | Keep acceptance business identity, exact proof-attempt identity, and the first canonical result separate; recover the exact attempt after expiry, never create state with an expired proof, and require reconciliation for a different proof. | acceptanceのbusiness identity、exact proof-attempt identity、最初のcanonical resultを分離し、exact attemptは期限後も回収し、expired proofでは新規stateを作らず、異なるproofにはreconciliationを要求する。 |

## Relay profile matrix

| ID | Status | English | 日本語 |
| --- | --- | --- | --- |
| `ASB-HC-RLY-001` | implemented | Authorize one exact relay intent with a fresh ASB proof and one-shot replay consumption. | 一つのexact relay intentをfresh ASB proofとone-shot replay消費で認可する。 |
| `ASB-HC-RLY-002` | implemented | Atomically bind at most one intent to an exact active grant and recheck scope, consent, expiry, and Participants; the grant is not exact-content Human approval. | exactでactiveなgrant一件に最大一件のintentをatomicに束縛し、scope、consent、expiry、Participantを再検証する。grantをHumanによるexact-content承認と扱わない。 |
| `ASB-HC-RLY-003` | implemented | Omit Human identity, consent, approval, session, provider, and direct-contact data from Agent-visible records. | Agent向けrecordからHuman identity、consent、approval、session、provider、直接連絡先を除外する。 |
| `ASB-HC-RLY-004` | reference-only | Serialize final dispatch authorization with revocation, persist `DISPATCHING` before callback, and use `CANCELED` only when no callback occurred. | final dispatch authorizationとrevocationを直列化し、callback前に`DISPATCHING`を保存し、callbackなしの場合だけ`CANCELED`とする。 |
| `ASB-HC-RLY-005` | reference-only | Permit at most one provider call across workers and keep unknown outcomes in `DISPATCHING` without blind retry. | worker間でprovider callを最大一回にし、unknown outcomeをblind retryせず`DISPATCHING`に保つ。 |
| `ASB-HC-RLY-006` | implemented | Derive and validate relay event IDs from the versioned status-and-intent transcript. | versioned status-and-intent transcriptからrelay event IDを導出・検証する。 |
| `ASB-HC-RLY-007` | implemented | Treat provider acknowledgement as transport state, never as Human receipt, approval, completion, or lifecycle mutation. | provider acknowledgementをtransport stateだけとして扱い、Humanの受領、承認、完了、lifecycle mutationとは解釈しない。 |
| `ASB-HC-RLY-008` | unimplemented | A production relay needs durable state, fenced dispatch, provider reconciliation, a protected contact vault, abuse controls, and qualified adapters. | production relayにはdurable state、fenced dispatch、provider reconciliation、保護されたcontact vault、abuse control、qualified adapterが必要である。 |

## HTTP profile matrix

| ID | Status | English | 日本語 |
| --- | --- | --- | --- |
| `ASB-HC-HTTP-001` | implemented | Expose only the documented POST challenge (`201`) and execute (`200`) operations; return structured errors elsewhere. | 文書化したPOST challenge (`201`)とexecute (`200`)だけを公開し、他はstructured errorにする。 |
| `ASB-HC-HTTP-002` | implemented | Terminate verified TLS 1.3/mTLS and derive Actor and session bindings from the accepted connection. | verified TLS 1.3/mTLSを終端し、accepted connectionからActorとsession bindingを導出する。 |
| `ASB-HC-HTTP-003` | implemented | Bind a challenge to one connection, digest, nonce, expiry, and execute attempt; never replace a live challenge on ID collision; reject cross-connection use. | challengeを一つのconnection、digest、nonce、expiry、execute attemptへ束縛し、ID衝突でlive challengeを置換せず、別connection利用を拒否する。 |
| `ASB-HC-HTTP-004` | implemented | Require JSON and the endpoint-specific bounded strict schema; reject duplicate, unknown, trailing, and opposite envelopes. | JSONとendpoint固有のbounded strict schemaを要求し、duplicate、unknown、trailing、opposite envelopeを拒否する。 |
| `ASB-HC-HTTP-005` | implemented | Generate every request ID server-side and never trust or echo an inbound request ID. | request IDは常にserver側で生成し、inbound request IDを信頼またはechoしない。 |
| `ASB-HC-HTTP-006` | implemented | Use the fixed public error matrix and redact backend, verifier, replay, and persistence details. | 固定public error matrixを使い、backend、verifier、replay、persistenceの詳細を秘匿する。 |
| `ASB-HC-HTTP-007` | implemented | Only rate limiting permits the documented automatic retry; reconcile unknown mutation outcomes from trusted state. | 文書化した自動retryはrate limitだけに許可し、mutation結果不明時はtrusted stateからreconcileする。 |
| `ASB-HC-HTTP-008` | implemented | Bind every decision-relevant caller field in the request digest and preserve proof-before-state ordering where required. | 判断へ影響する全caller fieldをrequest digestへ束縛し、必要箇所でproof-before-state順序を守る。 |
| `ASB-HC-HTTP-009` | implemented | Do not expose relay Worker or Task–Action internal APIs as Human ingress endpoints. | relay WorkerやTask–Action内部APIをHuman ingress endpointとして公開しない。 |

## Production overlay matrix

| ID | Status | English | 日本語 |
| --- | --- | --- | --- |
| `ASB-HC-PROD-001` | reference-only | Name each selected capability and its evidence; core does not imply Task–Action or relay. | 選択した各capabilityとevidenceを明示し、coreからTask–Actionやrelayを暗黙に主張しない。 |
| `ASB-HC-PROD-002` | reference-only | Persist TaskCoord Assignment, delegation, Interaction, conflict, and outbox state atomically. | TaskCoordのAssignment、delegation、Interaction、conflict、outbox stateをatomicに永続化する。 |
| `ASB-HC-PROD-003` | reference-only | Combine verified TLS ingress, shared replay protection, and a durable TaskCoord Store. | verified TLS ingress、shared replay protection、durable TaskCoord Storeを組み合わせる。 |
| `ASB-HC-PROD-004` | reference-only | Supply the integrated durable Task–Action transaction and recovery contract. | integrated durable Task–Action transactionとrecovery contractを提供する。 |
| `ASB-HC-PROD-005` | reference-only | Supply durable grant-scoped relay serialization and provider idempotency. | durableなgrant-scoped relay serializationとprovider idempotencyを提供する。 |
| `ASB-HC-PROD-006` | unqualified | Qualify the selected live Redis/Valkey service for persistence, replication, failover, backup, recovery, and unknown writes. | 選択したlive Redis/Valkeyをpersistence、replication、failover、backup、recovery、unknown writeについてqualificationする。 |
| `ASB-HC-PROD-007` | unqualified | Complete live operational qualification for every selected ingress, replay, outbox, recovery, and provider boundary. | 選択したingress、replay、outbox、recovery、provider boundaryごとにlive operational qualificationを完了する。 |
| `ASB-HC-PROD-008` | unimplemented | Supply missing production Task–Action, relay/provider recovery, and durable outcome-reconciliation adapters when selected. | 選択時に不足しているproduction Task–Action、relay/provider recovery、durable outcome reconciliation adapterを提供する。 |

The detailed deployment gates and current unavailable decision are in
[`human-coordination-production-v1.md`](human-coordination-production-v1.md).

## Non-normative future topics

The following are not v1 requirements and must not be inferred from a current
profile declaration:

- multiple Actions under one Assignment or aggregate fulfillment semantics;
- general-purpose public Human discovery or a Human matching network;
- external ASB profiles for Agent TaskCoord, Action acceptance or mutation,
  Human matching, and consent/grant administration; their current operation
  boundaries are explicitly trusted-internal;
- relay Worker or Task–Action HTTP endpoints;
- Email, SNS, telephone, or other production delivery adapters;
- a production contact vault or Human-facing product UI; and
- mandatory SNP, TDX, TPM, Cocos, or other hardware-attestation composition.

## Conformance evidence

Every manifest requirement names its current status, mapped test cases, and
source or document evidence. A declaration should include the manifest version,
profile IDs, claimed optional capabilities, implementation revision, executed
test/evidence list, environment, and date. It must retain `unknown` rather than
inferring success for an unexecuted live gate.

The deterministic Mac/CI walkthrough is available through:

```sh
make mac-human-coordination-e2e
```

It writes `build/human-coordination-e2e/evidence.json` and exercises the core,
Task–Action, and relay application boundaries. The report identifies every
in-process or simulated boundary and fixes `production_claim` to `false`. It is
runnable Developer Preview evidence, not live TLS, provider, durable Store, or
hardware qualification. See the
[debug-simple E2E guide](../examples/human-coordination-e2e/README.md).

Repository conformance checks:

```sh
jq -e . testdata/human-coordination-conformance-v1.json
GOWORK=off go test ./schemas
make human-coordination-gate
```

Passing these repository checks establishes only the mapped Developer Preview
behavior. It does not change `asb.human-coordination.production/v1` from
unavailable.
