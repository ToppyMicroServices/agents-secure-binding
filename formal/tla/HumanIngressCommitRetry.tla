\* Copyright (c) 2026 ToppyMicroServices OÜ
\* SPDX-License-Identifier: Apache-2.0
---------------------- MODULE HumanIngressCommitRetry -----------------------
EXTENDS Integers, Naturals

\* Finite target model for a durable Human-ingress operation journal.  The
\* model starts after cryptographic verification.  journalStatus is durable;
\* clientOutcome is what the caller most recently learned.  effectCalls and
\* effectApplied are write-only ghost histories: no implementation action uses
\* them to decide whether another effect may run.  Trusted reconciliation
\* evidence is produced by an environment observation and consumed separately.

CONSTANTS OperationIds, Digests, Proofs

ASSUME /\ OperationIds # {}
       /\ Digests # {}
       /\ Proofs # {}
       /\ "<none-digest>" \notin Digests

JournalStatuses ==
    {"NONE", "ACCEPTED", "RUNNING", "INDETERMINATE", "SUCCEEDED", "FAILED"}
WorkerPhases ==
    {"IDLE", "READY", "RETURNED_SUCCESS", "RETURNED_FAILURE",
     "RECOVERY_REQUIRED", "DONE"}
ClientOutcomes == {"NONE", "UNKNOWN", "SUCCEEDED", "FAILED"}
EvidenceOutcomes == {"NONE", "EFFECT_COMMITTED", "NO_EFFECT"}
NoDigest == "<none-digest>"

VARIABLES
    journalStatus,
    boundDigest,
    workerPhase,
    executionAttempts,
    effectCalls,
    effectApplied,
    proofUses,
    clientOutcome,
    trustedEvidence,
    unknownSeen,
    unknownCallSnapshot,
    reconciled,
    conflicts,
    rejectedUnknownRetries,
    rejectedProofReuses

vars ==
    << journalStatus,
       boundDigest,
       workerPhase,
       executionAttempts,
       effectCalls,
       effectApplied,
       proofUses,
       clientOutcome,
       trustedEvidence,
       unknownSeen,
       unknownCallSnapshot,
       reconciled,
       conflicts,
       rejectedUnknownRetries,
       rejectedProofReuses >>

Init ==
    /\ journalStatus = [op \in OperationIds |-> "NONE"]
    /\ boundDigest = [op \in OperationIds |-> NoDigest]
    /\ workerPhase = [op \in OperationIds |-> "IDLE"]
    /\ executionAttempts = [op \in OperationIds |-> 0]
    /\ effectCalls = [op \in OperationIds |-> 0]
    /\ effectApplied = [op \in OperationIds |-> FALSE]
    /\ proofUses = [proof \in Proofs |-> 0]
    /\ clientOutcome = [op \in OperationIds |-> "NONE"]
    /\ trustedEvidence = [op \in OperationIds |-> "NONE"]
    /\ unknownSeen = {}
    /\ unknownCallSnapshot = [op \in OperationIds |-> 0]
    /\ reconciled = {}
    /\ conflicts = {}
    /\ rejectedUnknownRetries = {}
    /\ rejectedProofReuses = {}

\* Replay consumption and operation reservation form one durable transaction.
\* Reserving an operation does not claim that execution has started.
Reserve(op, requestDigest, proof) ==
    /\ journalStatus[op] = "NONE"
    /\ proofUses[proof] = 0
    /\ journalStatus' = [journalStatus EXCEPT ![op] = "ACCEPTED"]
    /\ boundDigest' = [boundDigest EXCEPT ![op] = requestDigest]
    /\ proofUses' = [proofUses EXCEPT ![proof] = @ + 1]
    /\ UNCHANGED
        << workerPhase,
           executionAttempts,
           effectCalls,
           effectApplied,
           clientOutcome,
           trustedEvidence,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           conflicts,
           rejectedUnknownRetries,
           rejectedProofReuses >>

\* RUNNING is durable before the application effect is attempted.
StartExecution(op) ==
    /\ journalStatus[op] = "ACCEPTED"
    /\ workerPhase[op] = "IDLE"
    /\ executionAttempts[op] = 0
    /\ journalStatus' = [journalStatus EXCEPT ![op] = "RUNNING"]
    /\ workerPhase' = [workerPhase EXCEPT ![op] = "READY"]
    /\ executionAttempts' = [executionAttempts EXCEPT ![op] = @ + 1]
    /\ UNCHANGED
        << boundDigest,
           effectCalls,
           effectApplied,
           proofUses,
           clientOutcome,
           trustedEvidence,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           conflicts,
           rejectedUnknownRetries,
           rejectedProofReuses >>

\* These two actions model a call that returns while the Worker remains alive.
\* Their enabledness depends only on Worker control state, never on ghost truth.
EffectReturnsCommitted(op) ==
    /\ journalStatus[op] = "RUNNING"
    /\ workerPhase[op] = "READY"
    /\ workerPhase' = [workerPhase EXCEPT ![op] = "RETURNED_SUCCESS"]
    /\ effectCalls' = [effectCalls EXCEPT ![op] = @ + 1]
    /\ effectApplied' = [effectApplied EXCEPT ![op] = TRUE]
    /\ UNCHANGED
        << journalStatus,
           boundDigest,
           executionAttempts,
           proofUses,
           clientOutcome,
           trustedEvidence,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           conflicts,
           rejectedUnknownRetries,
           rejectedProofReuses >>

EffectReturnsNoEffect(op) ==
    /\ journalStatus[op] = "RUNNING"
    /\ workerPhase[op] = "READY"
    /\ workerPhase' = [workerPhase EXCEPT ![op] = "RETURNED_FAILURE"]
    /\ effectCalls' = [effectCalls EXCEPT ![op] = @ + 1]
    /\ UNCHANGED
        << journalStatus,
           boundDigest,
           executionAttempts,
           effectApplied,
           proofUses,
           clientOutcome,
           trustedEvidence,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           conflicts,
           rejectedUnknownRetries,
           rejectedProofReuses >>

\* A crash can happen before the call, during a call that did or did not apply
\* its effect, or after a known return but before a terminal journal write.
\* In every case the durable journal remains RUNNING and recovery cannot call
\* the effect again.
CrashBeforeEffect(op) ==
    /\ journalStatus[op] = "RUNNING"
    /\ workerPhase[op] = "READY"
    /\ workerPhase' = [workerPhase EXCEPT ![op] = "RECOVERY_REQUIRED"]
    /\ clientOutcome' = [clientOutcome EXCEPT ![op] = "UNKNOWN"]
    /\ unknownSeen' = unknownSeen \cup {op}
    /\ unknownCallSnapshot' =
        [unknownCallSnapshot EXCEPT ![op] = effectCalls[op]]
    /\ UNCHANGED
        << journalStatus,
           boundDigest,
           executionAttempts,
           effectCalls,
           effectApplied,
           proofUses,
           trustedEvidence,
           reconciled,
           conflicts,
           rejectedUnknownRetries,
           rejectedProofReuses >>

CrashDuringCommittedEffect(op) ==
    /\ journalStatus[op] = "RUNNING"
    /\ workerPhase[op] = "READY"
    /\ workerPhase' = [workerPhase EXCEPT ![op] = "RECOVERY_REQUIRED"]
    /\ effectCalls' = [effectCalls EXCEPT ![op] = @ + 1]
    /\ effectApplied' = [effectApplied EXCEPT ![op] = TRUE]
    /\ clientOutcome' = [clientOutcome EXCEPT ![op] = "UNKNOWN"]
    /\ unknownSeen' = unknownSeen \cup {op}
    /\ unknownCallSnapshot' =
        [unknownCallSnapshot EXCEPT ![op] = effectCalls[op] + 1]
    /\ UNCHANGED
        << journalStatus,
           boundDigest,
           executionAttempts,
           proofUses,
           trustedEvidence,
           reconciled,
           conflicts,
           rejectedUnknownRetries,
           rejectedProofReuses >>

CrashDuringNoEffect(op) ==
    /\ journalStatus[op] = "RUNNING"
    /\ workerPhase[op] = "READY"
    /\ workerPhase' = [workerPhase EXCEPT ![op] = "RECOVERY_REQUIRED"]
    /\ effectCalls' = [effectCalls EXCEPT ![op] = @ + 1]
    /\ clientOutcome' = [clientOutcome EXCEPT ![op] = "UNKNOWN"]
    /\ unknownSeen' = unknownSeen \cup {op}
    /\ unknownCallSnapshot' =
        [unknownCallSnapshot EXCEPT ![op] = effectCalls[op] + 1]
    /\ UNCHANGED
        << journalStatus,
           boundDigest,
           executionAttempts,
           effectApplied,
           proofUses,
           trustedEvidence,
           reconciled,
           conflicts,
           rejectedUnknownRetries,
           rejectedProofReuses >>

CrashAfterKnownReturn(op) ==
    /\ journalStatus[op] = "RUNNING"
    /\ workerPhase[op] \in {"RETURNED_SUCCESS", "RETURNED_FAILURE"}
    /\ workerPhase' = [workerPhase EXCEPT ![op] = "RECOVERY_REQUIRED"]
    /\ clientOutcome' = [clientOutcome EXCEPT ![op] = "UNKNOWN"]
    /\ unknownSeen' = unknownSeen \cup {op}
    /\ unknownCallSnapshot' =
        [unknownCallSnapshot EXCEPT ![op] = effectCalls[op]]
    /\ UNCHANGED
        << journalStatus,
           boundDigest,
           executionAttempts,
           effectCalls,
           effectApplied,
           proofUses,
           trustedEvidence,
           reconciled,
           conflicts,
           rejectedUnknownRetries,
           rejectedProofReuses >>

RecordSuccess(op) ==
    /\ journalStatus[op] = "RUNNING"
    /\ workerPhase[op] = "RETURNED_SUCCESS"
    /\ journalStatus' = [journalStatus EXCEPT ![op] = "SUCCEEDED"]
    /\ workerPhase' = [workerPhase EXCEPT ![op] = "DONE"]
    /\ UNCHANGED
        << boundDigest,
           executionAttempts,
           effectCalls,
           effectApplied,
           proofUses,
           clientOutcome,
           trustedEvidence,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           conflicts,
           rejectedUnknownRetries,
           rejectedProofReuses >>

RecordFailure(op) ==
    /\ journalStatus[op] = "RUNNING"
    /\ workerPhase[op] = "RETURNED_FAILURE"
    /\ journalStatus' = [journalStatus EXCEPT ![op] = "FAILED"]
    /\ workerPhase' = [workerPhase EXCEPT ![op] = "DONE"]
    /\ UNCHANGED
        << boundDigest,
           executionAttempts,
           effectCalls,
           effectApplied,
           proofUses,
           clientOutcome,
           trustedEvidence,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           conflicts,
           rejectedUnknownRetries,
           rejectedProofReuses >>

\* Response delivery is separate from the terminal durable write.  Losing a
\* response changes caller knowledge, not journalStatus.
DeliverTerminalResponse(op) ==
    /\ journalStatus[op] \in {"SUCCEEDED", "FAILED"}
    /\ clientOutcome[op] \in {"NONE", "UNKNOWN"}
    /\ clientOutcome' =
        [clientOutcome EXCEPT
            ![op] = IF journalStatus[op] = "SUCCEEDED"
                     THEN "SUCCEEDED" ELSE "FAILED"]
    /\ UNCHANGED
        << journalStatus,
           boundDigest,
           workerPhase,
           executionAttempts,
           effectCalls,
           effectApplied,
           proofUses,
           trustedEvidence,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           conflicts,
           rejectedUnknownRetries,
           rejectedProofReuses >>

LoseTerminalResponse(op) ==
    /\ journalStatus[op] \in {"SUCCEEDED", "FAILED"}
    /\ clientOutcome[op] = "NONE"
    /\ clientOutcome' = [clientOutcome EXCEPT ![op] = "UNKNOWN"]
    /\ UNCHANGED
        << journalStatus,
           boundDigest,
           workerPhase,
           executionAttempts,
           effectCalls,
           effectApplied,
           proofUses,
           trustedEvidence,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           conflicts,
           rejectedUnknownRetries,
           rejectedProofReuses >>

MarkIndeterminate(op) ==
    /\ journalStatus[op] = "RUNNING"
    /\ workerPhase[op] = "RECOVERY_REQUIRED"
    /\ journalStatus' = [journalStatus EXCEPT ![op] = "INDETERMINATE"]
    /\ UNCHANGED
        << boundDigest,
           workerPhase,
           executionAttempts,
           effectCalls,
           effectApplied,
           proofUses,
           clientOutcome,
           trustedEvidence,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           conflicts,
           rejectedUnknownRetries,
           rejectedProofReuses >>

\* These are environment observations from a trusted application/result
\* adapter.  They may inspect external truth; the reconciliation actions below
\* inspect only the resulting evidence.
ObserveCommittedEvidence(op) ==
    /\ journalStatus[op] = "INDETERMINATE"
    /\ workerPhase[op] = "RECOVERY_REQUIRED"
    /\ trustedEvidence[op] = "NONE"
    /\ effectApplied[op]
    /\ trustedEvidence' =
        [trustedEvidence EXCEPT ![op] = "EFFECT_COMMITTED"]
    /\ UNCHANGED
        << journalStatus,
           boundDigest,
           workerPhase,
           executionAttempts,
           effectCalls,
           effectApplied,
           proofUses,
           clientOutcome,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           conflicts,
           rejectedUnknownRetries,
           rejectedProofReuses >>

ObserveNoEffectEvidence(op) ==
    /\ journalStatus[op] = "INDETERMINATE"
    /\ workerPhase[op] = "RECOVERY_REQUIRED"
    /\ trustedEvidence[op] = "NONE"
    /\ ~effectApplied[op]
    /\ trustedEvidence' = [trustedEvidence EXCEPT ![op] = "NO_EFFECT"]
    /\ UNCHANGED
        << journalStatus,
           boundDigest,
           workerPhase,
           executionAttempts,
           effectCalls,
           effectApplied,
           proofUses,
           clientOutcome,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           conflicts,
           rejectedUnknownRetries,
           rejectedProofReuses >>

ReconcileCommitted(op) ==
    /\ journalStatus[op] = "INDETERMINATE"
    /\ workerPhase[op] = "RECOVERY_REQUIRED"
    /\ trustedEvidence[op] = "EFFECT_COMMITTED"
    /\ op \notin reconciled
    /\ journalStatus' = [journalStatus EXCEPT ![op] = "SUCCEEDED"]
    /\ workerPhase' = [workerPhase EXCEPT ![op] = "DONE"]
    /\ reconciled' = reconciled \cup {op}
    /\ UNCHANGED
        << boundDigest,
           executionAttempts,
           effectCalls,
           effectApplied,
           proofUses,
           clientOutcome,
           trustedEvidence,
           unknownSeen,
           unknownCallSnapshot,
           conflicts,
           rejectedUnknownRetries,
           rejectedProofReuses >>

ReconcileNoEffect(op) ==
    /\ journalStatus[op] = "INDETERMINATE"
    /\ workerPhase[op] = "RECOVERY_REQUIRED"
    /\ trustedEvidence[op] = "NO_EFFECT"
    /\ op \notin reconciled
    /\ journalStatus' = [journalStatus EXCEPT ![op] = "FAILED"]
    /\ workerPhase' = [workerPhase EXCEPT ![op] = "DONE"]
    /\ reconciled' = reconciled \cup {op}
    /\ UNCHANGED
        << boundDigest,
           executionAttempts,
           effectCalls,
           effectApplied,
           proofUses,
           clientOutcome,
           trustedEvidence,
           unknownSeen,
           unknownCallSnapshot,
           conflicts,
           rejectedUnknownRetries,
           rejectedProofReuses >>

\* Every exact retry, including a retry of an unresolved operation, consumes a
\* fresh proof and returns only the current durable outcome.  It never starts an
\* effect.  A terminal result can therefore be recovered after response loss.
ObserveExactRetry(op, requestDigest, proof) ==
    /\ journalStatus[op] # "NONE"
    /\ boundDigest[op] = requestDigest
    /\ proofUses[proof] = 0
    /\ proofUses' = [proofUses EXCEPT ![proof] = @ + 1]
    /\ clientOutcome' =
        [clientOutcome EXCEPT
            ![op] = IF journalStatus[op] = "SUCCEEDED" THEN "SUCCEEDED"
                     ELSE IF journalStatus[op] = "FAILED" THEN "FAILED"
                     ELSE "UNKNOWN"]
    /\ rejectedUnknownRetries' =
        IF journalStatus[op] \in {"ACCEPTED", "RUNNING", "INDETERMINATE"}
        THEN rejectedUnknownRetries \cup {op}
        ELSE rejectedUnknownRetries
    /\ UNCHANGED
        << journalStatus,
           boundDigest,
           workerPhase,
           executionAttempts,
           effectCalls,
           effectApplied,
           trustedEvidence,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           conflicts,
           rejectedProofReuses >>

RejectDigestConflict(op, requestDigest) ==
    /\ journalStatus[op] # "NONE"
    /\ boundDigest[op] # requestDigest
    /\ conflicts' = conflicts \cup {<<op, requestDigest>>}
    /\ UNCHANGED
        << journalStatus,
           boundDigest,
           workerPhase,
           executionAttempts,
           effectCalls,
           effectApplied,
           proofUses,
           clientOutcome,
           trustedEvidence,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           rejectedUnknownRetries,
           rejectedProofReuses >>

RejectProofReuse(op, proof) ==
    /\ proofUses[proof] = 1
    /\ rejectedProofReuses' = rejectedProofReuses \cup {<<op, proof>>}
    /\ UNCHANGED
        << journalStatus,
           boundDigest,
           workerPhase,
           executionAttempts,
           effectCalls,
           effectApplied,
           proofUses,
           clientOutcome,
           trustedEvidence,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           conflicts,
           rejectedUnknownRetries >>

Next ==
    \/ \E op \in OperationIds, requestDigest \in Digests, proof \in Proofs :
        Reserve(op, requestDigest, proof)
    \/ \E op \in OperationIds : StartExecution(op)
    \/ \E op \in OperationIds : EffectReturnsCommitted(op)
    \/ \E op \in OperationIds : EffectReturnsNoEffect(op)
    \/ \E op \in OperationIds : CrashBeforeEffect(op)
    \/ \E op \in OperationIds : CrashDuringCommittedEffect(op)
    \/ \E op \in OperationIds : CrashDuringNoEffect(op)
    \/ \E op \in OperationIds : CrashAfterKnownReturn(op)
    \/ \E op \in OperationIds : RecordSuccess(op)
    \/ \E op \in OperationIds : RecordFailure(op)
    \/ \E op \in OperationIds : DeliverTerminalResponse(op)
    \/ \E op \in OperationIds : LoseTerminalResponse(op)
    \/ \E op \in OperationIds : MarkIndeterminate(op)
    \/ \E op \in OperationIds : ObserveCommittedEvidence(op)
    \/ \E op \in OperationIds : ObserveNoEffectEvidence(op)
    \/ \E op \in OperationIds : ReconcileCommitted(op)
    \/ \E op \in OperationIds : ReconcileNoEffect(op)
    \/ \E op \in OperationIds, requestDigest \in Digests, proof \in Proofs :
        ObserveExactRetry(op, requestDigest, proof)
    \/ \E op \in OperationIds, requestDigest \in Digests :
        RejectDigestConflict(op, requestDigest)
    \/ \E op \in OperationIds, proof \in Proofs :
        RejectProofReuse(op, proof)

Spec == Init /\ [][Next]_vars

TypeInvariant ==
    /\ journalStatus \in [OperationIds -> JournalStatuses]
    /\ boundDigest \in [OperationIds -> Digests \cup {NoDigest}]
    /\ workerPhase \in [OperationIds -> WorkerPhases]
    /\ executionAttempts \in [OperationIds -> 0..2]
    /\ effectCalls \in [OperationIds -> 0..2]
    /\ effectApplied \in [OperationIds -> BOOLEAN]
    /\ proofUses \in [Proofs -> 0..2]
    /\ clientOutcome \in [OperationIds -> ClientOutcomes]
    /\ trustedEvidence \in [OperationIds -> EvidenceOutcomes]
    /\ unknownSeen \subseteq OperationIds
    /\ unknownCallSnapshot \in [OperationIds -> 0..1]
    /\ reconciled \subseteq unknownSeen
    /\ conflicts \subseteq (OperationIds \X Digests)
    /\ rejectedUnknownRetries \subseteq OperationIds
    /\ rejectedProofReuses \subseteq (OperationIds \X Proofs)

StateShapeInvariant ==
    \A op \in OperationIds :
        /\ (journalStatus[op] = "NONE") <=>
              (boundDigest[op] = NoDigest)
        /\ (journalStatus[op] \in {"NONE", "ACCEPTED"} =>
              workerPhase[op] = "IDLE")
        /\ (journalStatus[op] = "RUNNING" =>
              workerPhase[op] \in
                {"READY", "RETURNED_SUCCESS", "RETURNED_FAILURE",
                 "RECOVERY_REQUIRED"})
        /\ (journalStatus[op] = "INDETERMINATE" =>
              workerPhase[op] = "RECOVERY_REQUIRED")
        /\ (journalStatus[op] \in {"SUCCEEDED", "FAILED"} =>
              workerPhase[op] = "DONE")
        /\ (journalStatus[op] \in {"NONE", "ACCEPTED"} =>
              executionAttempts[op] = 0)
        /\ (journalStatus[op] \in
              {"RUNNING", "INDETERMINATE", "SUCCEEDED", "FAILED"} =>
              executionAttempts[op] = 1)
        /\ effectCalls[op] <= executionAttempts[op]
        /\ (effectApplied[op] => effectCalls[op] = 1)
        /\ (workerPhase[op] = "RETURNED_SUCCESS" => effectApplied[op])
        /\ (workerPhase[op] = "RETURNED_FAILURE" => ~effectApplied[op])

NoDoubleEffectInvariant ==
    \A op \in OperationIds :
        /\ executionAttempts[op] <= 1
        /\ effectCalls[op] <= 1

OutcomeConsistencyInvariant ==
    \A op \in OperationIds :
        /\ (journalStatus[op] = "SUCCEEDED" => effectApplied[op])
        /\ (journalStatus[op] = "FAILED" => ~effectApplied[op])
        /\ (clientOutcome[op] = "SUCCEEDED" =>
              journalStatus[op] = "SUCCEEDED" /\ effectApplied[op])
        /\ (clientOutcome[op] = "FAILED" =>
              journalStatus[op] = "FAILED" /\ ~effectApplied[op])
        /\ (trustedEvidence[op] = "EFFECT_COMMITTED" =>
              effectApplied[op])
        /\ (trustedEvidence[op] = "NO_EFFECT" => ~effectApplied[op])

UnknownOutcomePreservedInvariant ==
    \A op \in (unknownSeen \ reconciled) :
        /\ journalStatus[op] \in {"RUNNING", "INDETERMINATE"}
        /\ workerPhase[op] = "RECOVERY_REQUIRED"
        /\ clientOutcome[op] = "UNKNOWN"

ConflictIsolationInvariant ==
    \A conflict \in conflicts :
        /\ boundDigest[conflict[1]] # NoDigest
        /\ conflict[2] # boundDigest[conflict[1]]

ProofOneShotInvariant ==
    \A proof \in Proofs : proofUses[proof] <= 1

NoBlindRetryInvariant ==
    /\ \A op \in unknownSeen :
           /\ executionAttempts[op] = 1
           /\ effectCalls[op] = unknownCallSnapshot[op]
    /\ rejectedUnknownRetries \subseteq
          {op \in OperationIds : journalStatus[op] # "NONE"}

ReconciliationInvariant ==
    \A op \in reconciled :
        /\ trustedEvidence[op] # "NONE"
        /\ workerPhase[op] = "DONE"
        /\ (trustedEvidence[op] = "EFFECT_COMMITTED" =>
              journalStatus[op] = "SUCCEEDED")
        /\ (trustedEvidence[op] = "NO_EFFECT" =>
              journalStatus[op] = "FAILED")

=============================================================================
