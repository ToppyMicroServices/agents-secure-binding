# Task–Action lifecycle binding v1 実装仕様

Status: unreleased, additive repository profile。本書はInternet-Draftではなく、
Direct-Agent v1のwire profileを変更しない。

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
2. Actionがrevision 1のvalidな`ACCEPT` snapshotである;
3. `Action.owner_id == Assignment.participant_id`である;
4. Action acceptanceがAssignment acceptanceより前でない;
5. Assignment snapshot、初期Action snapshotとtransition、Bindingを一つの
   application transactionで保存する。

transactionはAssignment revisionを比較し、Actionのexpected revisionを0として、
Action `event_id`をdeduplicateする。独立した二つのStoreをprocess内で順番に呼ぶだけ
では、このatomicityを満たさない。

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
contractである。Binding生成、dependency WAIT、dependency RESUMEは、checked
revisionとdependency rowをcommitまで保護する一つのatomic database transaction、
または同等のprimitiveでcommitする。
通常のAction transitionは、embedded `actionlifecycle.Store`のsnapshot CASと
`event_id` deduplication contractを使用する。

`actionbinding.Service`をapplication entry pointとする。ServiceはBinding、
Assignment、Action、dependencyをStoreからloadするため、callerはtrusted snapshotを
入力しない。またdependency WAIT/RESUMEを通常transitionから拒否し、topology検証の
迂回を防ぐ。

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

lease expiry以外のAction mutationは、freshに検証されたASB operationのprojectionを
要求する。signature、token、policy、TLS binding、nonce replay、exact request digest
検証はenclosing verifier/application adapterの責務である。raw network claimを直接
`AuthenticatedOperation`へ変換してはならない。

Bindingに連絡先やpublic Human discovery dataを入れない。Human identity resolutionと
Email/SNS/TEL relayはTask Participant profileどおりpackage外に保持する。

## 9. 最小適合チェック

- [ ] unaccepted Assignment、non-initial Action、owner mismatchをBinding時に拒否する。
- [ ] Action completionがAssignment stateを変更しない。
- [ ] Assignment release/revokeがAction stateを変更しない。
- [ ] dependency WAIT/RESUMEがcurrent CAS snapshotと同一topologyを使用する。
- [ ] `ALL`、`ANY`、`QUORUM`と複数group ANDを検査する。
- [ ] non-dependency waitをexternal progress pathとして投影する。
- [ ] strict JSONとDraft 2020-12 Schemaの両方を検証する。
- [ ] production Storeがdocumented atomic commitを実装する。
