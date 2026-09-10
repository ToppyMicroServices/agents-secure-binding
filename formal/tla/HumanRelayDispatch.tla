\* Copyright (c) 2026 ToppyMicroServices OÜ
\* SPDX-License-Identifier: Apache-2.0
------------------------ MODULE HumanRelayDispatch --------------------------
EXTENDS Integers, Naturals

\* Finite target model for the grant-scoped relay dispatch boundary.  Grant
\* revocation and dispatch reservation share one ordering boundary.  Worker
\* control state, rather than ghost provider history, determines whether a
\* callback may start.  providerCalls and providerTruth are write-only ghost
\* histories used only by invariants and trusted environment observations.

CONSTANTS IntentOne, IntentTwo, WorkerOne, WorkerTwo, GrantOne, GrantTwo

Intents == {IntentOne, IntentTwo}
Workers == {WorkerOne, WorkerTwo}
Grants == {GrantOne, GrantTwo}
IntentGrant(intent) == IF intent = IntentOne THEN GrantOne ELSE GrantTwo

ASSUME /\ IntentOne # IntentTwo
       /\ WorkerOne # WorkerTwo
       /\ GrantOne # GrantTwo
       /\ "<none-worker>" \notin Workers
       /\ "<none-intent>" \notin Intents

Statuses ==
    {"QUEUED", "DISPATCHING", "PROVIDER_ACKNOWLEDGED", "CANCELED"}
WorkerPhases ==
    {"IDLE", "READY", "RETURNED_ACK", "RECOVERY_REQUIRED", "DONE"}
ProviderTruths == {"NONE", "NO_EFFECT", "ACKNOWLEDGED"}
ProviderOutcomes == {"NONE", "UNKNOWN", "ACKNOWLEDGED"}
EvidenceOutcomes == {"NONE", "NO_EFFECT", "ACKNOWLEDGED"}
NoWorker == "<none-worker>"
NoIntent == "<none-intent>"

VARIABLES
    status,
    grantRevoked,
    dispatchOwner,
    workerPhase,
    providerCalls,
    providerTruth,
    returnedAckIntent,
    acknowledgedIntent,
    providerOutcome,
    reconciliationEvidence,
    revokedBeforeReservation,
    unknownSeen,
    unknownCallSnapshot,
    reconciled,
    rejectedBlindRetries,
    rejectedWorkers,
    rejectedAcknowledgements

vars ==
    << status,
       grantRevoked,
       dispatchOwner,
       workerPhase,
       providerCalls,
       providerTruth,
       returnedAckIntent,
       acknowledgedIntent,
       providerOutcome,
       reconciliationEvidence,
       revokedBeforeReservation,
       unknownSeen,
       unknownCallSnapshot,
       reconciled,
       rejectedBlindRetries,
       rejectedWorkers,
       rejectedAcknowledgements >>

Init ==
    /\ status = [intent \in Intents |-> "QUEUED"]
    /\ grantRevoked = [grant \in Grants |-> FALSE]
    /\ dispatchOwner = [intent \in Intents |-> NoWorker]
    /\ workerPhase = [intent \in Intents |-> "IDLE"]
    /\ providerCalls = [intent \in Intents |-> 0]
    /\ providerTruth = [intent \in Intents |-> "NONE"]
    /\ returnedAckIntent = [intent \in Intents |-> NoIntent]
    /\ acknowledgedIntent = [intent \in Intents |-> NoIntent]
    /\ providerOutcome = [intent \in Intents |-> "NONE"]
    /\ reconciliationEvidence = [intent \in Intents |-> "NONE"]
    /\ revokedBeforeReservation = {}
    /\ unknownSeen = {}
    /\ unknownCallSnapshot = [intent \in Intents |-> 0]
    /\ reconciled = {}
    /\ rejectedBlindRetries = {}
    /\ rejectedWorkers = {}
    /\ rejectedAcknowledgements = {}

GrantCriticalSectionHeld(grant) ==
    \E intent \in Intents :
        /\ IntentGrant(intent) = grant
        /\ workerPhase[intent] \in {"READY", "RETURNED_ACK"}

\* Revocation can cancel an unreserved intent.  A live Worker holds the same
\* grant-scoped boundary from reservation through callback return and durable
\* acknowledgement, so revocation cannot interleave with those phases.
RevokeGrant(grant) ==
    /\ ~grantRevoked[grant]
    /\ ~GrantCriticalSectionHeld(grant)
    /\ grantRevoked' = [grantRevoked EXCEPT ![grant] = TRUE]
    /\ status' =
        [intent \in Intents |->
            IF IntentGrant(intent) = grant /\ status[intent] = "QUEUED"
            THEN "CANCELED"
            ELSE status[intent]]
    /\ revokedBeforeReservation' =
        revokedBeforeReservation \cup
          {intent \in Intents :
              IntentGrant(intent) = grant /\ status[intent] = "QUEUED"}
    /\ UNCHANGED
        << dispatchOwner,
           workerPhase,
           providerCalls,
           providerTruth,
           returnedAckIntent,
           acknowledgedIntent,
           providerOutcome,
           reconciliationEvidence,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           rejectedBlindRetries,
           rejectedWorkers,
           rejectedAcknowledgements >>

BeginDispatch(intent, worker) ==
    /\ status[intent] = "QUEUED"
    /\ ~grantRevoked[IntentGrant(intent)]
    /\ status' = [status EXCEPT ![intent] = "DISPATCHING"]
    /\ dispatchOwner' = [dispatchOwner EXCEPT ![intent] = worker]
    /\ workerPhase' = [workerPhase EXCEPT ![intent] = "READY"]
    /\ UNCHANGED
        << grantRevoked,
           providerCalls,
           providerTruth,
           returnedAckIntent,
           acknowledgedIntent,
           providerOutcome,
           reconciliationEvidence,
           revokedBeforeReservation,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           rejectedBlindRetries,
           rejectedWorkers,
           rejectedAcknowledgements >>

\* A provider acknowledgement is untrusted until its intent identity is
\* checked.  The actual provider outcome is nondeterministic when the returned
\* acknowledgement names another intent.
ProviderReturnsAcknowledgement(intent, worker, ackIntent, actualOutcome) ==
    /\ status[intent] = "DISPATCHING"
    /\ dispatchOwner[intent] = worker
    /\ workerPhase[intent] = "READY"
    /\ actualOutcome \in {"NO_EFFECT", "ACKNOWLEDGED"}
    /\ (ackIntent = intent => actualOutcome = "ACKNOWLEDGED")
    /\ workerPhase' = [workerPhase EXCEPT ![intent] = "RETURNED_ACK"]
    /\ providerCalls' = [providerCalls EXCEPT ![intent] = @ + 1]
    /\ providerTruth' =
        [providerTruth EXCEPT ![intent] = actualOutcome]
    /\ returnedAckIntent' =
        [returnedAckIntent EXCEPT ![intent] = ackIntent]
    /\ UNCHANGED
        << status,
           grantRevoked,
           dispatchOwner,
           acknowledgedIntent,
           providerOutcome,
           reconciliationEvidence,
           revokedBeforeReservation,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           rejectedBlindRetries,
           rejectedWorkers,
           rejectedAcknowledgements >>

\* A timeout, provider error, or crash during the callback leaves the true
\* external result unknown to the Worker.  Both possible external outcomes are
\* explored, but neither is used to decide whether another call may start.
ProviderCallOutcomeUnknown(intent, worker, actualOutcome) ==
    /\ status[intent] = "DISPATCHING"
    /\ dispatchOwner[intent] = worker
    /\ workerPhase[intent] = "READY"
    /\ actualOutcome \in {"NO_EFFECT", "ACKNOWLEDGED"}
    /\ workerPhase' =
        [workerPhase EXCEPT ![intent] = "RECOVERY_REQUIRED"]
    /\ providerCalls' = [providerCalls EXCEPT ![intent] = @ + 1]
    /\ providerTruth' =
        [providerTruth EXCEPT ![intent] = actualOutcome]
    /\ providerOutcome' = [providerOutcome EXCEPT ![intent] = "UNKNOWN"]
    /\ unknownSeen' = unknownSeen \cup {intent}
    /\ unknownCallSnapshot' =
        [unknownCallSnapshot EXCEPT
            ![intent] = IF intent \in unknownSeen
                        THEN @
                        ELSE providerCalls[intent] + 1]
    /\ UNCHANGED
        << status,
           grantRevoked,
           dispatchOwner,
           returnedAckIntent,
           acknowledgedIntent,
           reconciliationEvidence,
           revokedBeforeReservation,
           reconciled,
           rejectedBlindRetries,
           rejectedWorkers,
           rejectedAcknowledgements >>

CrashBeforeProvider(intent, worker) ==
    /\ status[intent] = "DISPATCHING"
    /\ dispatchOwner[intent] = worker
    /\ workerPhase[intent] = "READY"
    /\ workerPhase' =
        [workerPhase EXCEPT ![intent] = "RECOVERY_REQUIRED"]
    /\ providerOutcome' = [providerOutcome EXCEPT ![intent] = "UNKNOWN"]
    /\ unknownSeen' = unknownSeen \cup {intent}
    /\ unknownCallSnapshot' =
        [unknownCallSnapshot EXCEPT ![intent] = providerCalls[intent]]
    /\ UNCHANGED
        << status,
           grantRevoked,
           dispatchOwner,
           providerCalls,
           providerTruth,
           returnedAckIntent,
           acknowledgedIntent,
           reconciliationEvidence,
           revokedBeforeReservation,
           reconciled,
           rejectedBlindRetries,
           rejectedWorkers,
           rejectedAcknowledgements >>

CrashAfterReturnedAcknowledgement(intent, worker) ==
    /\ status[intent] = "DISPATCHING"
    /\ dispatchOwner[intent] = worker
    /\ workerPhase[intent] = "RETURNED_ACK"
    /\ workerPhase' =
        [workerPhase EXCEPT ![intent] = "RECOVERY_REQUIRED"]
    /\ providerOutcome' = [providerOutcome EXCEPT ![intent] = "UNKNOWN"]
    /\ unknownSeen' = unknownSeen \cup {intent}
    /\ unknownCallSnapshot' =
        [unknownCallSnapshot EXCEPT ![intent] = providerCalls[intent]]
    /\ UNCHANGED
        << status,
           grantRevoked,
           dispatchOwner,
           providerCalls,
           providerTruth,
           returnedAckIntent,
           acknowledgedIntent,
           reconciliationEvidence,
           revokedBeforeReservation,
           reconciled,
           rejectedBlindRetries,
           rejectedWorkers,
           rejectedAcknowledgements >>

CommitProviderAcknowledgement(intent, worker) ==
    /\ status[intent] = "DISPATCHING"
    /\ dispatchOwner[intent] = worker
    /\ workerPhase[intent] = "RETURNED_ACK"
    /\ returnedAckIntent[intent] = intent
    /\ status' = [status EXCEPT ![intent] = "PROVIDER_ACKNOWLEDGED"]
    /\ workerPhase' = [workerPhase EXCEPT ![intent] = "DONE"]
    /\ acknowledgedIntent' =
        [acknowledgedIntent EXCEPT ![intent] = intent]
    /\ providerOutcome' =
        [providerOutcome EXCEPT ![intent] = "ACKNOWLEDGED"]
    /\ UNCHANGED
        << grantRevoked,
           dispatchOwner,
           providerCalls,
           providerTruth,
           returnedAckIntent,
           reconciliationEvidence,
           revokedBeforeReservation,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           rejectedBlindRetries,
           rejectedWorkers,
           rejectedAcknowledgements >>

RejectMismatchedAcknowledgement(intent, worker) ==
    /\ status[intent] = "DISPATCHING"
    /\ dispatchOwner[intent] = worker
    /\ workerPhase[intent] = "RETURNED_ACK"
    /\ returnedAckIntent[intent] # intent
    /\ workerPhase' =
        [workerPhase EXCEPT ![intent] = "RECOVERY_REQUIRED"]
    /\ providerOutcome' = [providerOutcome EXCEPT ![intent] = "UNKNOWN"]
    /\ unknownSeen' = unknownSeen \cup {intent}
    /\ unknownCallSnapshot' =
        [unknownCallSnapshot EXCEPT ![intent] = providerCalls[intent]]
    /\ rejectedAcknowledgements' =
        rejectedAcknowledgements \cup
          {<<intent, returnedAckIntent[intent]>>}
    /\ UNCHANGED
        << status,
           grantRevoked,
           dispatchOwner,
           providerCalls,
           providerTruth,
           returnedAckIntent,
           acknowledgedIntent,
           reconciliationEvidence,
           revokedBeforeReservation,
           reconciled,
           rejectedBlindRetries,
           rejectedWorkers >>

RejectCompetingWorker(intent, worker) ==
    /\ status[intent] = "DISPATCHING"
    /\ dispatchOwner[intent] # worker
    /\ rejectedWorkers' = rejectedWorkers \cup {<<intent, worker>>}
    /\ UNCHANGED
        << status,
           grantRevoked,
           dispatchOwner,
           workerPhase,
           providerCalls,
           providerTruth,
           returnedAckIntent,
           acknowledgedIntent,
           providerOutcome,
           reconciliationEvidence,
           revokedBeforeReservation,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           rejectedBlindRetries,
           rejectedAcknowledgements >>

RejectBlindRetry(intent, worker) ==
    /\ status[intent] = "DISPATCHING"
    /\ intent \in unknownSeen
    /\ dispatchOwner[intent] = worker
    /\ workerPhase[intent] \in {"RECOVERY_REQUIRED", "DONE"}
    /\ rejectedBlindRetries' = rejectedBlindRetries \cup {intent}
    /\ UNCHANGED
        << status,
           grantRevoked,
           dispatchOwner,
           workerPhase,
           providerCalls,
           providerTruth,
           returnedAckIntent,
           acknowledgedIntent,
           providerOutcome,
           reconciliationEvidence,
           revokedBeforeReservation,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           rejectedWorkers,
           rejectedAcknowledgements >>

\* Environment observations represent a trusted provider-status adapter.  The
\* broker reconciliation transitions consume only this evidence, not ghost
\* providerTruth.
ObserveProviderAcknowledged(intent) ==
    /\ status[intent] = "DISPATCHING"
    /\ workerPhase[intent] = "RECOVERY_REQUIRED"
    /\ reconciliationEvidence[intent] = "NONE"
    /\ providerTruth[intent] = "ACKNOWLEDGED"
    /\ reconciliationEvidence' =
        [reconciliationEvidence EXCEPT ![intent] = "ACKNOWLEDGED"]
    /\ UNCHANGED
        << status,
           grantRevoked,
           dispatchOwner,
           workerPhase,
           providerCalls,
           providerTruth,
           returnedAckIntent,
           acknowledgedIntent,
           providerOutcome,
           revokedBeforeReservation,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           rejectedBlindRetries,
           rejectedWorkers,
           rejectedAcknowledgements >>

ObserveProviderNoEffect(intent) ==
    /\ status[intent] = "DISPATCHING"
    /\ workerPhase[intent] = "RECOVERY_REQUIRED"
    /\ reconciliationEvidence[intent] = "NONE"
    /\ providerTruth[intent] \in {"NONE", "NO_EFFECT"}
    /\ reconciliationEvidence' =
        [reconciliationEvidence EXCEPT ![intent] = "NO_EFFECT"]
    /\ UNCHANGED
        << status,
           grantRevoked,
           dispatchOwner,
           workerPhase,
           providerCalls,
           providerTruth,
           returnedAckIntent,
           acknowledgedIntent,
           providerOutcome,
           revokedBeforeReservation,
           unknownSeen,
           unknownCallSnapshot,
           reconciled,
           rejectedBlindRetries,
           rejectedWorkers,
           rejectedAcknowledgements >>

ReconcileAcknowledged(intent) ==
    /\ status[intent] = "DISPATCHING"
    /\ workerPhase[intent] = "RECOVERY_REQUIRED"
    /\ reconciliationEvidence[intent] = "ACKNOWLEDGED"
    /\ intent \notin reconciled
    /\ status' = [status EXCEPT ![intent] = "PROVIDER_ACKNOWLEDGED"]
    /\ workerPhase' = [workerPhase EXCEPT ![intent] = "DONE"]
    /\ acknowledgedIntent' =
        [acknowledgedIntent EXCEPT ![intent] = intent]
    /\ providerOutcome' =
        [providerOutcome EXCEPT ![intent] = "ACKNOWLEDGED"]
    /\ reconciled' = reconciled \cup {intent}
    /\ UNCHANGED
        << grantRevoked,
           dispatchOwner,
           providerCalls,
           providerTruth,
           returnedAckIntent,
           reconciliationEvidence,
           revokedBeforeReservation,
           unknownSeen,
           unknownCallSnapshot,
           rejectedBlindRetries,
           rejectedWorkers,
           rejectedAcknowledgements >>

\* The current relay vocabulary has no safe requeue state after a dispatch
\* reservation.  Even trusted NO_EFFECT evidence leaves the receipt
\* DISPATCHING and closes this Worker's attempt.
ReconcileNoEffect(intent) ==
    /\ status[intent] = "DISPATCHING"
    /\ workerPhase[intent] = "RECOVERY_REQUIRED"
    /\ reconciliationEvidence[intent] = "NO_EFFECT"
    /\ intent \notin reconciled
    /\ workerPhase' = [workerPhase EXCEPT ![intent] = "DONE"]
    /\ reconciled' = reconciled \cup {intent}
    /\ UNCHANGED
        << status,
           grantRevoked,
           dispatchOwner,
           providerCalls,
           providerTruth,
           returnedAckIntent,
           acknowledgedIntent,
           providerOutcome,
           reconciliationEvidence,
           revokedBeforeReservation,
           unknownSeen,
           unknownCallSnapshot,
           rejectedBlindRetries,
           rejectedWorkers,
           rejectedAcknowledgements >>

Next ==
    \/ \E grant \in Grants : RevokeGrant(grant)
    \/ \E intent \in Intents, worker \in Workers :
        BeginDispatch(intent, worker)
    \/ \E intent \in Intents, worker \in Workers,
          ackIntent \in Intents,
          actualOutcome \in {"NO_EFFECT", "ACKNOWLEDGED"} :
        ProviderReturnsAcknowledgement(
          intent, worker, ackIntent, actualOutcome)
    \/ \E intent \in Intents, worker \in Workers,
          actualOutcome \in {"NO_EFFECT", "ACKNOWLEDGED"} :
        ProviderCallOutcomeUnknown(intent, worker, actualOutcome)
    \/ \E intent \in Intents, worker \in Workers :
        CrashBeforeProvider(intent, worker)
    \/ \E intent \in Intents, worker \in Workers :
        CrashAfterReturnedAcknowledgement(intent, worker)
    \/ \E intent \in Intents, worker \in Workers :
        CommitProviderAcknowledgement(intent, worker)
    \/ \E intent \in Intents, worker \in Workers :
        RejectMismatchedAcknowledgement(intent, worker)
    \/ \E intent \in Intents, worker \in Workers :
        RejectCompetingWorker(intent, worker)
    \/ \E intent \in Intents, worker \in Workers :
        RejectBlindRetry(intent, worker)
    \/ \E intent \in Intents : ObserveProviderAcknowledged(intent)
    \/ \E intent \in Intents : ObserveProviderNoEffect(intent)
    \/ \E intent \in Intents : ReconcileAcknowledged(intent)
    \/ \E intent \in Intents : ReconcileNoEffect(intent)

Spec == Init /\ [][Next]_vars

TypeInvariant ==
    /\ status \in [Intents -> Statuses]
    /\ grantRevoked \in [Grants -> BOOLEAN]
    /\ dispatchOwner \in [Intents -> Workers \cup {NoWorker}]
    /\ workerPhase \in [Intents -> WorkerPhases]
    /\ providerCalls \in [Intents -> 0..2]
    /\ providerTruth \in [Intents -> ProviderTruths]
    /\ returnedAckIntent \in [Intents -> Intents \cup {NoIntent}]
    /\ acknowledgedIntent \in [Intents -> Intents \cup {NoIntent}]
    /\ providerOutcome \in [Intents -> ProviderOutcomes]
    /\ reconciliationEvidence \in [Intents -> EvidenceOutcomes]
    /\ revokedBeforeReservation \subseteq Intents
    /\ unknownSeen \subseteq Intents
    /\ unknownCallSnapshot \in [Intents -> 0..1]
    /\ reconciled \subseteq unknownSeen
    /\ rejectedBlindRetries \subseteq Intents
    /\ rejectedWorkers \subseteq (Intents \X Workers)
    /\ rejectedAcknowledgements \subseteq (Intents \X Intents)

ReservationInvariant ==
    \A intent \in Intents :
        /\ (status[intent] \in {"QUEUED", "CANCELED"} =>
              dispatchOwner[intent] = NoWorker /\
              workerPhase[intent] = "IDLE")
        /\ (status[intent] \in
              {"DISPATCHING", "PROVIDER_ACKNOWLEDGED"} =>
              dispatchOwner[intent] \in Workers)
        /\ (workerPhase[intent] \in
              {"READY", "RETURNED_ACK", "RECOVERY_REQUIRED"} =>
              status[intent] = "DISPATCHING")
        /\ (status[intent] = "PROVIDER_ACKNOWLEDGED" =>
              workerPhase[intent] = "DONE")

ProviderHistoryInvariant ==
    \A intent \in Intents :
        /\ providerCalls[intent] <= 1
        /\ ((providerCalls[intent] = 0) <=>
              (providerTruth[intent] = "NONE"))
        /\ (returnedAckIntent[intent] # NoIntent =>
              providerCalls[intent] = 1)

GrantRevocationInvariant ==
    /\ \A intent \in revokedBeforeReservation :
           /\ status[intent] = "CANCELED"
           /\ grantRevoked[IntentGrant(intent)]
           /\ providerCalls[intent] = 0
    /\ \A intent \in Intents :
           grantRevoked[IntentGrant(intent)] /\
           workerPhase[intent] \in {"READY", "RETURNED_ACK"} => FALSE

CanceledMeansNoCallbackInvariant ==
    \A intent \in Intents :
        status[intent] = "CANCELED" => providerCalls[intent] = 0

AcknowledgementInvariant ==
    \A intent \in Intents :
        status[intent] = "PROVIDER_ACKNOWLEDGED" =>
            /\ providerCalls[intent] = 1
            /\ providerTruth[intent] = "ACKNOWLEDGED"
            /\ providerOutcome[intent] = "ACKNOWLEDGED"
            /\ acknowledgedIntent[intent] = intent

UnknownOutcomePreservedInvariant ==
    \A intent \in (unknownSeen \ reconciled) :
        /\ status[intent] = "DISPATCHING"
        /\ workerPhase[intent] = "RECOVERY_REQUIRED"
        /\ providerCalls[intent] = unknownCallSnapshot[intent]
        /\ providerOutcome[intent] = "UNKNOWN"

NoBlindRetryInvariant ==
    /\ \A intent \in unknownSeen :
           providerCalls[intent] = unknownCallSnapshot[intent]
    /\ rejectedBlindRetries \subseteq unknownSeen

ReconciliationInvariant ==
    \A intent \in Intents :
        /\ (intent \in reconciled =>
              reconciliationEvidence[intent] # "NONE" /\
              workerPhase[intent] = "DONE")
        /\ (reconciliationEvidence[intent] = "ACKNOWLEDGED" =>
              providerTruth[intent] = "ACKNOWLEDGED")
        /\ (reconciliationEvidence[intent] = "NO_EFFECT" =>
              providerTruth[intent] \in {"NONE", "NO_EFFECT"})
        /\ (intent \in reconciled /\
            reconciliationEvidence[intent] = "ACKNOWLEDGED" =>
              status[intent] = "PROVIDER_ACKNOWLEDGED" /\
              acknowledgedIntent[intent] = intent)
        /\ (intent \in reconciled /\
            reconciliationEvidence[intent] = "NO_EFFECT" =>
              status[intent] = "DISPATCHING" /\
              providerOutcome[intent] = "UNKNOWN")

RejectedAcknowledgementInvariant ==
    \A rejected \in rejectedAcknowledgements :
        rejected[1] # rejected[2]

=============================================================================
