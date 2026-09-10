# Task–Action lifecycle binding v1 実装仕様

Status: unreleased, additive repository profile。本書はInternet-Draftではなく、
Direct-Agent v1のwire profileを変更しない。

安定したproduct profile IDと英日共通のconformance mappingは
[Human Coordination conformance registry](human-coordination-conformance-v1.md)で管理する。

本仕様は、`pkg/taskcoord`の持続的な責任関係と、`pkg/actionlifecycle`のdurableな
実行状態を、`pkg/taskcoord/actionbinding`で接続する。両者のstate machineは
統合せず、明示的なbindingだけを追加する。

## 1. 最小モデル

```text
Participant ── Assignment ── Task
                    │
                    │ immutable Binding
                    ▼
                  Action ── lease / wait / recovery / outcome
```

Assignmentは「誰がTaskへの責任を持つか」を表す。Actionは「どの実行が進行し、
結果について何がdurableに判明しているか」を表す。Actorは一回のoperationを送る
認証済み主体であり、Participantやexecutorと同一である必要はない。

Bindingは次だけを保持する。

- `task_id`;
- `assignment_id`;
- `action_id`;
- `created_at`。

`participant_id`、kind、status、role、authority、`owner_id`は複製しない。
これらはAssignmentとActionのauthoritative snapshotから再解決する。

## 2. Binding生成条件

Bindingは次の条件を全て満たす場合だけ生成する。

1. Assignmentがvalidかつ`ACCEPTED`である;
2. freshに検証された`AuthenticatedOperation`が、この`ACCEPT`全体を認可している;
3. Actionがrevision 1のvalidな`ACCEPT` snapshotであり、そのtransitionが認可の
   provenance、Assignment context digest、final request digestを保持する;
4. `Action.owner_id == Assignment.participant_id`である;
5. Action acceptanceがAssignment acceptanceより前でない;
6. Assignment snapshot、認証済みacceptance request、初期Action snapshotと
   transition、Bindingを一つのapplication transactionで保存する。

transactionはAssignment revisionを比較し、Actionのexpected revisionを0として、
Store自身のclockでauthorizationのfreshnessを再確認し、`accepted_at`を導出して、
Action `event_id`をdeduplicateする。Assignmentをlockした後、初期ActionとBindingを
再構成する。独立した二つのStoreをprocess内で順番に呼ぶだけでは、このatomicityを
満たさない。

`ASB-HC-TA-001`はDeveloper Previewのcardinalityを、1 Assignmentあたり0または1 Actionに
固定する。Taskが複数Actionを持つ場合は、それぞれを別Assignmentへ結合する。
`CommitAcceptance`は、既に結合済みのAssignmentへ別Actionを追加する操作をatomicに
拒否し、敗者側のAction、Binding、eventを部分保存してはならない。1 Assignmentに
複数Actionを認めるには、一覧取得と集約fulfillment規則を定める新しいprofile versionが
必要である。

`actionbinding.AcceptanceRequestDigest`は、このoperation用のversioned final digestを
返す。まずAssignment IDとrevision、trusted Assignmentの`task_id`、`participant_id`、
`role`、`authority_digest`、`status = ACCEPTED`から`AcceptanceContextDigest`を導出する。
lifecycle側のdigestは、このcontext digestと`operation = ACCEPT`、`event_id`、`action_id`、
`action_digest`、導出したowner、recovery policyの全field（`mode`、`max_attempts`、
`idempotency_key`）を束縛する。`NewSnapshot`はfinal digestを再計算し、StoreはAssignmentを
lockした後にcontext digestを再計算する。callerが選ぶAction fieldの変更やAssignmentの
差替えはauthorizationを無効にする。`accepted_at`はcaller値ではなく
`Store.CommitAcceptance`がtransaction clockから導出するため、このdigestには含めない。

acceptance persistenceでは、`AcceptanceRequestDigest`によるbusiness identity、
`AcceptanceAttemptFingerprint`によるverifier attempt identity、最初にcommitされた
canonical `View`を区別して保存する。同じrequestと同じverifier attemptのexact retryは、
proof期限後でも最初の結果を返す。期限切れattemptから新規stateを作ってはならない。
同じbusiness requestに別proofを使った場合は`ErrAcceptanceReconciliationRequired`を返し、
最初のproofやresultを置換しない。不確実な応答から自動復旧するには、元のauthenticated
attemptを保持するか、明示的なreconciliation flowへ移る必要がある。

二層digestは、固定順序のlanguage-independent
[Action request transcript v1](action-transcript-v1.md)を使用する。同profileは
primitive encoding、field order、absence、timestamp、16 KiB上限をbyte単位で
定義し、machine-readable golden vectorがexact transcriptとdigestを固定する。
以前のfield-ordered Go JSON形式はunreleasedであり、互換encodingとして受理しない。

## 3. lifecycleを混同しない

cross-lifecycle mutationを暗黙に行ってはならない。

| 観測 | 許される結論 | 暗黙に意味しないもの |
| --- | --- | --- |
| Action=`SUCCEEDED`かつAssignment=`ACCEPTED` | 別途認証された`FULFILL`を提案可能 | 既にfulfill済み |
| Assignment=`RELEASED`または`REVOKED` | application policyによる後続判断が必要 | Action canceled |
| Action=`WAITING`または`PAUSED` | 現在実行していない | 責任関係が終了した |
| Action=`ORPHANED` | executor leaseが失効した | Action failed |
| Action=`INDETERMINATE` | reconciliationが必要 | terminal outcomeが既知 |

`FulfillmentEligible`はread-only predicateであり、`FULFILL`を実行しない。
Assignmentのrelease/revokeもAction履歴を変更しない。

## 4. dependency wait

Taskの複数dependency groupはANDで結合し、group内は`ALL`、`ANY`、`QUORUM`で
評価する。

`WaitForDependencies`は新しいAction stateを追加せず、次を行う。

1. Binding、`ACCEPTED` Assignment、`RUNNING` Actionを再検証する;
2. bound Taskから出るactive dependencyを検証しcanonicalizeする;
3. 全groupが既に満たされている場合はWAITを拒否する;
4. mutableな`satisfied`を除外したtopologyをdomain-separated SHA-256で束縛する;
5. derived `SIGNAL`を持つ通常のAction `WAITING` transitionを生成する;
6. Action revision、sorted dependency IDs、topology digest、時刻を持つimmutable
   `DependencyWait`を生成する。

WAITING transitionとDependencyWaitは、Assignment、Action、dependency rowの
current stateを比較した同一transactionで保存する。

`ResumeDependencyWait`はdependencyを再読込し、topology変更または未充足groupを
拒否する。exact topologyが満たされた場合、stored waitとcurrent satisfactionを
束縛するdeterministic evidence referenceを生成し、通常の認証済みAction
`RESUME`を適用する。resumeも同じapplication transaction境界でcommitする。

dependency satisfactionは暗号学的proofではなくapplication stateである。
production adapterはdependency更新の認証、直列化、evidence retentionを担う。

## 5. deadlock projection

`ProjectTaskLiveness`はlinked Actionを既存`taskcoord.TaskLiveness`へ投影する。

| Action条件 | 投影 |
| --- | --- |
| `ACCEPTED`、`RUNNING`、`CANCELING` | `Runnable` |
| 検証済みTask dependency wait | graph内部だけでblocked |
| time、availability、signal、manual wait | `ExternalEscape` |
| `PAUSED`、`ORPHANED`、`INDETERMINATE` | `ExternalEscape` |
| non-terminal Actionとnon-`ACCEPTED` Assignment | application判断への`ExternalEscape` |
| linked Actionが全てterminal | `Terminal` |

検証済みDependencyWaitだけが`ExternalEscape`を外せる。wait record欠落、未知target、
graph外の進捗可能性はfalse-positive deadlockを発生させない。投影結果は既存の
`DetectDeadlockedTasks`へ渡す。

## 6. Storeとatomicity

`actionbinding.Store`はTaskCoordとAction lifecycleを接続するproduction persistence
contractである。acceptance、execution開始・延長、dependency WAIT、dependency RESUMEは、
checked revisionとdependency rowをcommitまで保護する一つのatomic database transaction、
または同等のprimitiveでcommitする。

`CommitAcceptance`はtransaction timestampを所有し、最初にcommitされたcanonical `View`を
返す。business digest、exact attempt fingerprint、canonical resultを、Action、Binding、
event、Assignment-to-Action indexと同じtransactionで保存しなければならない。

`START`、`RESUME`、`TAKEOVER`、lease renewalでは、`CommitExecutionTransition`が
`ACCEPTED` Assignment、immutable Binding、current Actionを同じcommit内で比較する。
これにより、事前確認後にAssignmentがrelease/revokeされるTOCTOUで新しい実行権限が
成立することを防ぐ。既に開始されたeffectを収束させるterminal、cancel、failure、
reconciliation transitionは`CommitAuthorizedTransition`を使う。このmethodは
execution transitionとtrusted lease expiryを拒否する。integrated Storeはgenericな
`actionlifecycle.Store.Commit`を公開しない。

全mutation commitは、proposed Transitionとともに元のEventをStoreへ渡す。adapterは
比較対象rowをlockした後、stored current ActionへそのEventを再適用し、導出された
Transition全体がproposed Transitionと一致する場合だけ書き込む。これにより、構造上
validなnext snapshotを直接組み立ててstate machineを迂回することを防ぐ。
authenticated commitでは、続いてtransaction clockによりfuture-dated transition、
期限切れauthorization、期限切れcurrent executor leaseを拒否する。新規または更新
leaseの期限はauthorization期限を超えてはならない。unauthenticated mutationは、
stored leaseと同じtrusted clockを用いる`CommitTrustedLeaseExpiry`だけである。同じ
`event_id`のretryも、EventとTransitionの組を再検証した後だけdeduplicateする。

`actionbinding.Service`をapplication entry pointとする。ServiceはBinding、
Assignment、Action、dependencyをStoreからloadするため、callerはtrusted snapshot
ではなく、verifierが生成したauthenticated operationを入力する。`Service.Accept`は
request shapeを検証した後、時刻所有、freshness、derivation、commit、retry recoveryを
`Store.CommitAcceptance`へ委ねる。lower-levelの`actionlifecycle.NewSnapshot`も、
acceptance authorizationの欠落または不一致を拒否する。またdependency WAIT/RESUMEを
通常transitionから拒否し、topology検証の迂回を防ぐ。

`actionbinding.MemoryStore`はprocess内lockによりmulti-record atomicity、CAS、event
deduplication、dependency TOCTOU rejectionを検証するreference adapterである。
restart durabilityを持たず、production database implementationではない。

本repositoryはstate machine、application service、reference adapter、Store
contractを実装する。production database adapter、replication、outbox、disaster
recoveryを実装済みとは主張しない。

## 7. JSON Schemaとsemantic validation

- `schemas/action-lifecycle-v1.schema.json`: complete Action snapshot;
- `schemas/task-action-binding-v1.schema.json`: BindingとDependencyWait。

`schemas` packageは両schemaのstartup preparationとJSON shape validatorを提供する。
JSON Schemaだけではcross-snapshot invariantを検証できないため、strict decoderと
`actionlifecycle` / `actionbinding`のsemantic validatorも必須である。

## 8. security boundary

全てのexternally requested Action mutationは、freshに検証されたASB operationの
projectionを要求し、初期`ACCEPT`もこれに含む。unauthenticated transitionはtrusted
lease-expiry observationだけである。signature、token、policy、TLS binding、nonce
replay、exact request digest検証はenclosing verifier/application adapterの責務である。
fieldがacceptance requestと一致して見える場合でも、raw network claimを直接
`AuthenticatedOperation`へ変換してはならない。

Bindingに連絡先やpublic Human discovery dataを入れない。Human identity resolutionと
Email/SNS/TEL relayはTask Participant profileどおりpackage外に保持する。

## 9. 最小適合チェック

- [ ] unaccepted Assignment、missing/stale/request-mismatched `ACCEPT` authorization、
      non-initial Action、owner mismatchをBinding時に拒否する。
- [ ] Action completionがAssignment stateを変更しない。
- [ ] Assignment release/revokeがAction stateを変更しない。
- [ ] START/RESUME/TAKEOVER/lease renewalがAssignmentとActionを同一commitで再確認する。
- [ ] authorizationがevent全体の`mutation_digest`をbindingし、Store clock時点でも有効である。
- [ ] future-dated transitionと期限切れexecutor mutationをcommit時に拒否する。
- [ ] 初期`ACCEPT` transitionがauthenticated provenance、Assignment context
      digest、versioned final request digestを保持する。
- [ ] exact acceptance-attempt retryがproof期限後でも最初のcanonical resultを返し、
      期限切れの新規attemptはstateを作らず、同じbusiness requestへの別proofは
      reconciliationを要求する。
- [ ] 唯一のunauthenticated transitionである`LEASE_EXPIRED`をtrusted lease monitor
      だけがcommitできる。
- [ ] dependency WAIT/RESUMEがcurrent CAS snapshotと同一topologyを使用する。
- [ ] `ALL`、`ANY`、`QUORUM`と複数group ANDを検査する。
- [ ] non-dependency waitをexternal progress pathとして投影する。
- [ ] strict JSONとDraft 2020-12 Schemaの両方を検証する。
- [ ] production Storeがdocumented atomic commitを実装する。
