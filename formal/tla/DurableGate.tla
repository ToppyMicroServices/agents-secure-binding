\* Copyright (c) 2026 ToppyMicroServices OÜ
\* SPDX-License-Identifier: Apache-2.0
----------------------------- MODULE DurableGate -----------------------------
EXTENDS Integers, Naturals, Sequences

\* This model specifies the crash-consistency boundary of a single-writer
\* service.  Cryptographic verification and wire encoding are deliberately
\* outside this module.

CONSTANTS
    ReplayKeys,
    Authorizations,
    LeaseTokens,
    EventIds,
    MaxTime,
    MaxAuditEntries

ASSUME /\ ReplayKeys # {}
       /\ Authorizations # {}
       /\ LeaseTokens # {}
       /\ EventIds # {}
       /\ MaxTime \in Nat
       /\ MaxTime > 0
       /\ MaxAuditEntries \in Nat
       /\ MaxAuditEntries > 0
       /\ "<none-replay>" \notin ReplayKeys
       /\ "<none-auth>" \notin Authorizations
       /\ "<none-lease>" \notin LeaseTokens
       /\ "<none-event>" \notin EventIds

LifecycleStates ==
    {"Stopped", "Ready", "Mutating", "Flushing", "Poisoned"}

WriteStages == {"Idle", "TempWritten", "TempSynced", "Renamed", "DirSynced"}
WritePurposes == {"None", "Mutation", "ClearOutbox"}
MutationKinds == {"Issue", "Revoke", "Consume"}

NoOp ==
    [ kind   |-> "None",
      replay |-> "<none-replay>",
      auth   |-> "<none-auth>",
      lease  |-> "<none-lease>",
      event  |-> "<none-event>",
      time   |-> 0 ]

Operation(kind, replay, auth, lease, event, effectiveTime) ==
    [ kind   |-> kind,
      replay |-> replay,
      auth   |-> auth,
      lease  |-> lease,
      event  |-> event,
      time   |-> effectiveTime ]

PendingOperations ==
    {NoOp} \cup
    [ kind   : MutationKinds,
      replay : ReplayKeys \cup {"<none-replay>"},
      auth   : Authorizations,
      lease  : LeaseTokens \cup {"<none-lease>"},
      event  : EventIds,
      time   : 0..MaxTime ]

LeaseRecords == [token : LeaseTokens, auth : Authorizations]

LeaseRecord(token, auth) == [token |-> token, auth |-> auth]

EmptyState ==
    [ replays   |-> {},
      revoked   |-> {},
      leases    |-> {},
      outbox    |-> <<>>,
      timeFloor |-> 0 ]

StateOK(state) ==
    /\ state.replays \subseteq ReplayKeys
    /\ state.revoked \subseteq Authorizations
    /\ state.leases \subseteq LeaseRecords
    /\ state.outbox \in Seq(EventIds)
    /\ Len(state.outbox) <= 1
    /\ state.timeFloor \in 0..MaxTime

LeaseTokensOf(state) == {lease.token : lease \in state.leases}

LeasesFor(state, auth) ==
    {lease \in state.leases : lease.auth = auth}

OutboxEvents(state) ==
    {state.outbox[index] : index \in 1..Len(state.outbox)}

SequenceValues(sequence) ==
    {sequence[index] : index \in 1..Len(sequence)}

UniqueLeaseTokens(state) ==
    \A left \in state.leases :
        \A right \in state.leases :
            left.token = right.token => left = right

AtMostOneLeasePerAuthorization(state) ==
    \A left \in state.leases :
        \A right \in state.leases :
            left.auth = right.auth => left = right

NoLeaseForRevokedAuthorization(state) ==
    \A lease \in state.leases : lease.auth \notin state.revoked

SemanticStateOK(state) ==
    /\ StateOK(state)
    /\ UniqueLeaseTokens(state)
    /\ AtMostOneLeasePerAuthorization(state)
    /\ NoLeaseForRevokedAuthorization(state)

Max2(left, right) == IF left >= right THEN left ELSE right

Nondecreasing(sequence) ==
    \A left \in 1..Len(sequence) :
        \A right \in 1..Len(sequence) :
            left < right => sequence[left] <= sequence[right]

VARIABLES
    lifecycle,
    disk,
    memory,
    visible,
    candidate,
    writeStage,
    writePurpose,
    pending,
    audit,
    auditHeadAppended,
    observedTime,
    diskValid,
    usedEvents,
    issuedTokens,
    durableEvents,
    retiredLeases,
    ackReplays,
    ackRevoked,
    ackLeases,
    ackConsumed,
    ackEvents,
    responseTimes

vars ==
    << lifecycle,
       disk,
       memory,
       visible,
       candidate,
       writeStage,
       writePurpose,
       pending,
       audit,
       auditHeadAppended,
       observedTime,
       diskValid,
       usedEvents,
       issuedTokens,
       durableEvents,
       retiredLeases,
       ackReplays,
       ackRevoked,
       ackLeases,
       ackConsumed,
       ackEvents,
       responseTimes >>

Init ==
    /\ lifecycle = "Stopped"
    /\ disk = EmptyState
    /\ memory = EmptyState
    /\ visible = EmptyState
    /\ candidate = EmptyState
    /\ writeStage = "Idle"
    /\ writePurpose = "None"
    /\ pending = NoOp
    /\ audit = <<>>
    /\ auditHeadAppended = FALSE
    /\ observedTime = 0
    /\ diskValid = TRUE
    /\ usedEvents = {}
    /\ issuedTokens = {}
    /\ durableEvents = {}
    /\ retiredLeases = {}
    /\ ackReplays = {}
    /\ ackRevoked = {}
    /\ ackLeases = {}
    /\ ackConsumed = {}
    /\ ackEvents = {}
    /\ responseTimes = <<>>

Restart ==
    /\ lifecycle = "Stopped"
    /\ diskValid
    /\ lifecycle' =
        IF Len(disk.outbox) = 0 THEN "Ready" ELSE "Flushing"
    /\ memory' = disk
    /\ visible' = disk
    /\ candidate' = disk
    /\ writeStage' = "Idle"
    /\ writePurpose' = "None"
    /\ pending' = NoOp
    /\ auditHeadAppended' = FALSE
    /\ UNCHANGED
        << disk,
           audit,
           observedTime,
           diskValid,
           usedEvents,
           issuedTokens,
           durableEvents,
           retiredLeases,
           ackReplays,
           ackRevoked,
           ackLeases,
           ackConsumed,
           ackEvents,
           responseTimes >>

BeginIssue ==
    /\ lifecycle = "Ready"
    /\ writeStage = "Idle"
    /\ \E replay \in ReplayKeys :
        \E auth \in Authorizations :
        \E lease \in LeaseTokens :
        \E event \in EventIds :
            /\ replay \notin memory.replays
            /\ auth \notin memory.revoked
            /\ LeasesFor(memory, auth) = {}
            /\ lease \notin issuedTokens
            /\ event \notin usedEvents
            /\ lifecycle' = "Mutating"
            /\ candidate' =
                [memory EXCEPT
                    !.replays = @ \cup {replay},
                    !.leases = @ \cup {LeaseRecord(lease, auth)},
                    !.outbox = <<event>>,
                    !.timeFloor = Max2(@, observedTime)]
            /\ pending' =
                Operation(
                    "Issue",
                    replay,
                    auth,
                    lease,
                    event,
                    Max2(memory.timeFloor, observedTime))
            /\ writeStage' = "TempWritten"
            /\ writePurpose' = "Mutation"
            /\ usedEvents' = usedEvents \cup {event}
            /\ issuedTokens' = issuedTokens \cup {lease}
            /\ UNCHANGED
                << disk,
                   memory,
                   visible,
                   audit,
                   auditHeadAppended,
                   observedTime,
                   diskValid,
                   durableEvents,
                   retiredLeases,
                   ackReplays,
                   ackRevoked,
                   ackLeases,
                   ackConsumed,
                   ackEvents,
                   responseTimes >>

BeginRevoke ==
    /\ lifecycle = "Ready"
    /\ writeStage = "Idle"
    /\ \E replay \in ReplayKeys :
        \E auth \in Authorizations :
        \E event \in EventIds :
            /\ replay \notin memory.replays
            /\ event \notin usedEvents
            /\ lifecycle' = "Mutating"
            /\ candidate' =
                [memory EXCEPT
                    !.replays = @ \cup {replay},
                    !.revoked = @ \cup {auth},
                    !.leases = @ \ LeasesFor(memory, auth),
                    !.outbox = <<event>>,
                    !.timeFloor = Max2(@, observedTime)]
            /\ pending' =
                Operation(
                    "Revoke",
                    replay,
                    auth,
                    "<none-lease>",
                    event,
                    Max2(memory.timeFloor, observedTime))
            /\ writeStage' = "TempWritten"
            /\ writePurpose' = "Mutation"
            /\ usedEvents' = usedEvents \cup {event}
            /\ UNCHANGED
                << disk,
                   memory,
                   visible,
                   audit,
                   auditHeadAppended,
                   observedTime,
                   diskValid,
                   issuedTokens,
                   durableEvents,
                   retiredLeases,
                   ackReplays,
                   ackRevoked,
                   ackLeases,
                   ackConsumed,
                   ackEvents,
                   responseTimes >>

BeginConsume ==
    /\ lifecycle = "Ready"
    /\ writeStage = "Idle"
    /\ \E auth \in Authorizations :
        \E lease \in LeaseTokens :
        \E event \in EventIds :
            /\ LeaseRecord(lease, auth) \in memory.leases
            /\ event \notin usedEvents
            /\ lifecycle' = "Mutating"
            /\ candidate' =
                [memory EXCEPT
                    !.leases = @ \ {LeaseRecord(lease, auth)},
                    !.outbox = <<event>>,
                    !.timeFloor = Max2(@, observedTime)]
            /\ pending' =
                Operation(
                    "Consume",
                    "<none-replay>",
                    auth,
                    lease,
                    event,
                    Max2(memory.timeFloor, observedTime))
            /\ writeStage' = "TempWritten"
            /\ writePurpose' = "Mutation"
            /\ usedEvents' = usedEvents \cup {event}
            /\ UNCHANGED
                << disk,
                   memory,
                   visible,
                   audit,
                   auditHeadAppended,
                   observedTime,
                   diskValid,
                   issuedTokens,
                   durableEvents,
                   retiredLeases,
                   ackReplays,
                   ackRevoked,
                   ackLeases,
                   ackConsumed,
                   ackEvents,
                   responseTimes >>

SyncTemp ==
    /\ lifecycle \in {"Mutating", "Flushing"}
    /\ writeStage = "TempWritten"
    /\ writeStage' = "TempSynced"
    /\ UNCHANGED
        << lifecycle,
           disk,
           memory,
           visible,
           candidate,
           writePurpose,
           pending,
           audit,
           auditHeadAppended,
           observedTime,
           diskValid,
           usedEvents,
           issuedTokens,
           durableEvents,
           retiredLeases,
           ackReplays,
           ackRevoked,
           ackLeases,
           ackConsumed,
           ackEvents,
           responseTimes >>

RenameState ==
    /\ lifecycle \in {"Mutating", "Flushing"}
    /\ writeStage = "TempSynced"
    /\ visible' = candidate
    /\ writeStage' = "Renamed"
    /\ UNCHANGED
        << lifecycle,
           disk,
           memory,
           candidate,
           writePurpose,
           pending,
           audit,
           auditHeadAppended,
           observedTime,
           diskValid,
           usedEvents,
           issuedTokens,
           durableEvents,
           retiredLeases,
           ackReplays,
           ackRevoked,
           ackLeases,
           ackConsumed,
           ackEvents,
           responseTimes >>

SyncDirectory ==
    /\ lifecycle \in {"Mutating", "Flushing"}
    /\ writeStage = "Renamed"
    /\ disk' = candidate
    /\ visible' = candidate
    /\ writeStage' = "DirSynced"
    /\ durableEvents' =
        IF writePurpose = "Mutation"
        THEN durableEvents \cup {pending.event}
        ELSE durableEvents
    /\ retiredLeases' =
        retiredLeases \cup (LeaseTokensOf(disk) \ LeaseTokensOf(candidate))
    /\ UNCHANGED
        << lifecycle,
           memory,
           candidate,
           writePurpose,
           pending,
           audit,
           auditHeadAppended,
           observedTime,
           diskValid,
           usedEvents,
           issuedTokens,
           ackReplays,
           ackRevoked,
           ackLeases,
           ackConsumed,
           ackEvents,
           responseTimes >>

AckReplaysAfter(operation) ==
    IF operation.kind \in {"Issue", "Revoke"}
    THEN ackReplays \cup {operation.replay}
    ELSE ackReplays

AckRevokedAfter(operation) ==
    IF operation.kind = "Revoke"
    THEN ackRevoked \cup {operation.auth}
    ELSE ackRevoked

AckLeasesAfter(operation) ==
    IF operation.kind = "Issue"
    THEN ackLeases \cup {LeaseRecord(operation.lease, operation.auth)}
    ELSE ackLeases

AckConsumedAfter(operation) ==
    IF operation.kind = "Consume"
    THEN ackConsumed \cup {operation.lease}
    ELSE ackConsumed

AckEventsAfter(operation) ==
    IF operation.kind \in MutationKinds
    THEN ackEvents \cup {operation.event}
    ELSE ackEvents

ResponseTimesAfter(operation) ==
    IF operation.kind \in MutationKinds
    THEN Append(responseTimes, operation.time)
    ELSE responseTimes

FinishWrite ==
    /\ lifecycle \in {"Mutating", "Flushing"}
    /\ writeStage = "DirSynced"
    /\ memory' = candidate
    /\ writeStage' = "Idle"
    /\ writePurpose' = "None"
    /\ auditHeadAppended' = FALSE
    /\ IF writePurpose = "Mutation"
       THEN
        /\ lifecycle' = "Flushing"
        /\ pending' = pending
        /\ ackReplays' = ackReplays
        /\ ackRevoked' = ackRevoked
        /\ ackLeases' = ackLeases
        /\ ackConsumed' = ackConsumed
        /\ ackEvents' = ackEvents
        /\ responseTimes' = responseTimes
       ELSE
        /\ writePurpose = "ClearOutbox"
        /\ lifecycle' = "Ready"
        /\ pending' = NoOp
        /\ ackReplays' = AckReplaysAfter(pending)
        /\ ackRevoked' = AckRevokedAfter(pending)
        /\ ackLeases' = AckLeasesAfter(pending)
        /\ ackConsumed' = AckConsumedAfter(pending)
        /\ ackEvents' = AckEventsAfter(pending)
        /\ responseTimes' = ResponseTimesAfter(pending)
    /\ UNCHANGED
        << disk,
           visible,
           candidate,
           audit,
           observedTime,
           diskValid,
           usedEvents,
           issuedTokens,
           durableEvents,
           retiredLeases >>

AppendAudit ==
    /\ lifecycle = "Flushing"
    /\ writeStage = "Idle"
    /\ Len(memory.outbox) = 1
    /\ ~auditHeadAppended
    /\ Len(audit) < MaxAuditEntries
    /\ audit' = Append(audit, Head(memory.outbox))
    /\ auditHeadAppended' = TRUE
    /\ UNCHANGED
        << lifecycle,
           disk,
           memory,
           visible,
           candidate,
           writeStage,
           writePurpose,
           pending,
           observedTime,
           diskValid,
           usedEvents,
           issuedTokens,
           durableEvents,
           retiredLeases,
           ackReplays,
           ackRevoked,
           ackLeases,
           ackConsumed,
           ackEvents,
           responseTimes >>

BeginClearOutbox ==
    /\ lifecycle = "Flushing"
    /\ writeStage = "Idle"
    /\ Len(memory.outbox) = 1
    /\ auditHeadAppended
    /\ candidate' = [memory EXCEPT !.outbox = Tail(@)]
    /\ writeStage' = "TempWritten"
    /\ writePurpose' = "ClearOutbox"
    /\ UNCHANGED
        << lifecycle,
           disk,
           memory,
           visible,
           pending,
           audit,
           auditHeadAppended,
           observedTime,
           diskValid,
           usedEvents,
           issuedTokens,
           durableEvents,
           retiredLeases,
           ackReplays,
           ackRevoked,
           ackLeases,
           ackConsumed,
           ackEvents,
           responseTimes >>

AuditAppendFailure ==
    /\ lifecycle = "Flushing"
    /\ writeStage = "Idle"
    /\ Len(memory.outbox) = 1
    /\ ~auditHeadAppended
    /\ lifecycle' = "Poisoned"
    /\ pending' = NoOp
    /\ auditHeadAppended' = FALSE
    /\ UNCHANGED
        << disk,
           memory,
           visible,
           candidate,
           writeStage,
           writePurpose,
           audit,
           observedTime,
           diskValid,
           usedEvents,
           issuedTokens,
           durableEvents,
           retiredLeases,
           ackReplays,
           ackRevoked,
           ackLeases,
           ackConsumed,
           ackEvents,
           responseTimes >>

PersistenceFailure ==
    /\ lifecycle \in {"Mutating", "Flushing"}
    /\ writeStage # "Idle"
    /\ lifecycle' = "Poisoned"
    \* Keep the interrupted write metadata until Crash resolves whether a
    \* pre-directory-sync rename survived.  Poisoned has no response action.
    /\ pending' = pending
    /\ auditHeadAppended' = FALSE
    /\ UNCHANGED
        << disk,
           memory,
           visible,
           candidate,
           writeStage,
           writePurpose,
           audit,
           observedTime,
           diskValid,
           usedEvents,
           issuedTokens,
           durableEvents,
           retiredLeases,
           ackReplays,
           ackRevoked,
           ackLeases,
           ackConsumed,
           ackEvents,
           responseTimes >>

RecoveryChoices ==
    IF writeStage = "Renamed" THEN {disk, candidate} ELSE {disk}

Crash ==
    /\ lifecycle # "Stopped"
    /\ \E recovered \in RecoveryChoices :
        /\ lifecycle' = "Stopped"
        /\ disk' = recovered
        /\ memory' = recovered
        /\ visible' = recovered
        /\ candidate' = recovered
        /\ writeStage' = "Idle"
        /\ writePurpose' = "None"
        /\ pending' = NoOp
        /\ auditHeadAppended' = FALSE
        /\ durableEvents' =
            IF writeStage = "Renamed"
               /\ recovered = candidate
               /\ writePurpose = "Mutation"
            THEN durableEvents \cup {pending.event}
            ELSE durableEvents
        /\ retiredLeases' =
            retiredLeases \cup
                (LeaseTokensOf(disk) \ LeaseTokensOf(recovered))
        /\ UNCHANGED
            << audit,
               observedTime,
               diskValid,
               usedEvents,
               issuedTokens,
               ackReplays,
               ackRevoked,
               ackLeases,
               ackConsumed,
               ackEvents,
               responseTimes >>

\* This fault represents a serialized state that fails validation at process
\* start.  The content is intentionally abstract; diskValid is the validator's
\* result, not a second on-disk format.
CorruptWhileStopped ==
    /\ lifecycle = "Stopped"
    /\ diskValid
    /\ diskValid' = FALSE
    /\ UNCHANGED
        << lifecycle,
           disk,
           memory,
           visible,
           candidate,
           writeStage,
           writePurpose,
           pending,
           audit,
           auditHeadAppended,
           observedTime,
           usedEvents,
           issuedTokens,
           durableEvents,
           retiredLeases,
           ackReplays,
           ackRevoked,
           ackLeases,
           ackConsumed,
           ackEvents,
           responseTimes >>

RejectInvalidDisk ==
    /\ lifecycle = "Stopped"
    /\ ~diskValid
    /\ lifecycle' = "Poisoned"
    /\ pending' = NoOp
    /\ UNCHANGED
        << disk,
           memory,
           visible,
           candidate,
           writeStage,
           writePurpose,
           audit,
           auditHeadAppended,
           observedTime,
           diskValid,
           usedEvents,
           issuedTokens,
           durableEvents,
           retiredLeases,
           ackReplays,
           ackRevoked,
           ackLeases,
           ackConsumed,
           ackEvents,
           responseTimes >>

ObserveTime ==
    \E newTime \in 0..MaxTime :
        /\ observedTime' = newTime
        /\ UNCHANGED
            << lifecycle,
               disk,
               memory,
               visible,
               candidate,
               writeStage,
               writePurpose,
               pending,
               audit,
               auditHeadAppended,
               diskValid,
               usedEvents,
               issuedTokens,
               durableEvents,
               retiredLeases,
               ackReplays,
               ackRevoked,
               ackLeases,
               ackConsumed,
               ackEvents,
               responseTimes >>

Next ==
    \/ Restart
    \/ BeginIssue
    \/ BeginRevoke
    \/ BeginConsume
    \/ SyncTemp
    \/ RenameState
    \/ SyncDirectory
    \/ FinishWrite
    \/ AppendAudit
    \/ BeginClearOutbox
    \/ AuditAppendFailure
    \/ PersistenceFailure
    \/ Crash
    \/ CorruptWhileStopped
    \/ RejectInvalidDisk
    \/ ObserveTime

Spec == Init /\ [][Next]_vars

AuditEvents == SequenceValues(audit)

TypeInvariant ==
    /\ lifecycle \in LifecycleStates
    /\ SemanticStateOK(disk)
    /\ SemanticStateOK(memory)
    /\ SemanticStateOK(visible)
    /\ SemanticStateOK(candidate)
    /\ writeStage \in WriteStages
    /\ writePurpose \in WritePurposes
    /\ pending \in PendingOperations
    /\ audit \in Seq(EventIds)
    /\ Len(audit) <= MaxAuditEntries
    /\ auditHeadAppended \in BOOLEAN
    /\ observedTime \in 0..MaxTime
    /\ diskValid \in BOOLEAN
    /\ usedEvents \subseteq EventIds
    /\ issuedTokens \subseteq LeaseTokens
    /\ durableEvents \subseteq usedEvents
    /\ retiredLeases \subseteq issuedTokens
    /\ ackReplays \subseteq ReplayKeys
    /\ ackRevoked \subseteq Authorizations
    /\ ackLeases \subseteq LeaseRecords
    /\ ackConsumed \subseteq LeaseTokens
    /\ ackEvents \subseteq EventIds
    /\ responseTimes \in Seq(0..MaxTime)

WriteShapeInvariant ==
    /\ (writeStage = "Idle") = (writePurpose = "None")
    /\ (lifecycle = "Mutating") =>
        (writePurpose = "Mutation" /\ writeStage # "Idle")
    /\ (lifecycle = "Flushing") => Len(memory.outbox) = 1
    /\ (lifecycle = "Ready") => Len(memory.outbox) = 0

ReadyInvariant ==
    lifecycle = "Ready" =>
        /\ diskValid
        /\ writeStage = "Idle"
        /\ writePurpose = "None"
        /\ pending = NoOp
        /\ disk = memory
        /\ memory = visible
        /\ memory.outbox = <<>>
        /\ ~auditHeadAppended

FailClosedInvariant ==
    lifecycle = "Poisoned" =>
        /\ ~auditHeadAppended
        /\ (writeStage = "Idle" => pending = NoOp)

DurableEventCoverageInvariant ==
    durableEvents \subseteq (OutboxEvents(disk) \cup AuditEvents)

AcknowledgedAuditInvariant ==
    /\ ackEvents \subseteq durableEvents
    /\ ackEvents \subseteq AuditEvents

AcknowledgedReplayInvariant ==
    ackReplays \subseteq disk.replays

AcknowledgedRevocationInvariant ==
    ackRevoked \subseteq disk.revoked

AcknowledgedLeaseInvariant ==
    \A lease \in ackLeases :
        lease \in disk.leases \/ lease.token \in retiredLeases

AcknowledgedConsumptionInvariant ==
    /\ ackConsumed \subseteq retiredLeases
    /\ ackConsumed \cap LeaseTokensOf(disk) = {}

MonotonicLogicalTimeInvariant ==
    /\ Nondecreasing(responseTimes)
    /\ \A responseTime \in SequenceValues(responseTimes) :
        responseTime <= disk.timeFloor

=============================================================================
