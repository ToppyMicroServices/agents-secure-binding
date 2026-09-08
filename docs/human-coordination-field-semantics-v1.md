# Human Coordination v1 string and identifier semantics

This document fixes the language-independent rules used by the Human
Coordination schemas and semantic validators. It does not change transcript
encoding: every accepted string is bound as its exact UTF-8 bytes.

## Conformance levels

Human Coordination uses two validation levels:

1. **Schema validation** checks the JSON shape and the constraints expressible
   by JSON Schema 2020-12. For identifiers this includes non-empty strings, a
   256-code-point ceiling, no Unicode control code point (`General_Category=Cc`),
   and no leading or trailing Unicode `White_Space` code point.
2. **Semantic validation** checks the typed profile. Every general identifier
   must encode to at most 256 UTF-8 octets. It also checks profile-specific
   invariants, canonical digests, state, and derived identifiers.

Passing schema validation alone is not protocol conformance. A receiver must
reject a value that fails either level. Rejection is performed on the received
value; a receiver must not trim, normalize, case-fold, or otherwise repair it.

JSON Schema `maxLength` counts Unicode code points, not UTF-8 octets. The
`x-asb-maxUtf8Bytes` keyword records the semantic octet ceiling but is an
annotation, not a standard JSON Schema assertion. Therefore a string such as
129 copies of U+00E9 passes the 256-code-point schema bound but its 258-octet
encoding must fail semantic identifier validation. This is the only intended
schema-versus-semantic gap for a general identifier's lexical rules.

## General identifier rule

Except for the Action-specific restriction below, every field in the table
uses this rule:

- length is 1 to 256 UTF-8 octets;
- matching, uniqueness, replay checks, and transcript input use the exact
  octets;
- identifiers are case-sensitive;
- NFC and NFD are neither required nor produced, and canonically equivalent
  strings remain distinct identifiers;
- Unicode control code points (`Cc`) are forbidden anywhere;
- leading and trailing Unicode `White_Space` are forbidden, while interior
  non-control whitespace is allowed;
- invalid input is rejected rather than trimmed or normalized.

| Surface | Fields using the general identifier rule |
| --- | --- |
| Task Participant, assignment, delegation, interaction, and dependency | `participant_id`, `assignment_id`, `task_id`, `offered_by_participant_id`, `parent_assignment_id`, `event_id`, `actor_id`, `authorization_id`, `proof_id`, `target_task_id`, `target_assignment_id`, `target_participant_id`, `dependency_id`, `from_task_id`, `to_task_id`, `group_id`, `decision_id`, `child_assignment_id`, `parent_task_id`, `child_task_id`, `from_participant_id`, `to_participant_id`, `interaction_id`, `in_reply_to`, and `supersedes` |
| Agent discovery and Human reachability | `record_id`, `capability`, `consent_id`, `human_participant_id`, `candidate_id`, `requester_participant_id`, `purpose`, `grant_id`, `approved_by_participant_id`, `approval_actor_id`, `approval_authorization_id`, and `approval_proof_id` |
| Human ingress request | `participant_id`, `event_id`, `task_id`, `assignment_id`, `target_participant_id`, `parent_task_id`, `parent_assignment_id`, `decision_id`, `child_event_id`, `child_task_id`, `child_assignment_id`, `interaction_id`, `in_reply_to`, and `supersedes` |
| Task to Action binding | `task_id`, `assignment_id`, `event_id`, `action_id`, and each `dependency_ids` member |
| Agent to Human relay | `intent_id`, `grant_id`, `requester_participant_id`, `purpose`, `capability`, `actor_id`, `authorization_id`, `proof_id`, `provider_ack_ref`, and the deployment-only `ack_ref` alias |
| Verifier-created Go projections | `actor_id`, `authorization_id`, `proof_id`, and `verifier_nonce` where the owning profile validates them as identifiers |
| Transactional outbox and Redis projection | `event_id`, `task_id`, `assignment_id`, `participant_id`, `consumer_id`, `lease_id`, and `delivery_id` |

Action Lifecycle identifiers use the same octet, whitespace, control,
normalization, and case rules, but retain the existing additional prohibition
on `<`, `>`, `&`, `"`, and `'`. This applies to `action_id`, `owner_id`,
`lease_id`, `executor_id`, `dependency_action_id`, `signal`, `error_code`, and
the Action transition `event_id`, `actor_id`, `authorization_id`, and
`proof_id` fields, as well as verifier-created `verifier_nonce`.

`asb.human-relay-event/v1.event_id` is not caller-selected. It is the ASCII
prefix `relay-event:v1:` followed by 64 lowercase hexadecimal characters and
must also equal the profile-defined digest of its status and `intent_id`.
Human ingress `challenge_id` is 64 lowercase hexadecimal characters. Its
server-generated error `request_id` is `asbreq-` followed by 32 lowercase
hexadecimal characters. Assurance provenance `profile_id` is the fixed profile
name `asb.taskcoord-human-request/v1`. Digest fields, timestamps, and enums are
also fixed format values rather than general identifiers; their schemas define
their case and lexical form.

The outbox is an internal application boundary, not a peer protocol. Its
caller-provided `consumer_id` and `lease_id` and its returned `delivery_id`
still use the general rule at the Go boundary. The Redis store derives its
`delivery_id` as 64 lowercase hexadecimal characters from the domain
`event_id`, but consumers must treat it as opaque and return it unchanged.

## Go field inventory

This inventory covers every direct identifier-bearing string field in the
exported Human Coordination structs in the listed packages. A wrapper's nested
fields are covered by the row for the nested type. It also includes the two
unexported Redis commit/outbox projections that cross the Lua/Go storage boundary.
References, digests, timestamps, enums, and schema names are classified in
their own rules and are not repeated here.

| Go type | Direct fields | Class |
| --- | --- | --- |
| `taskcoord.AgentDiscoveryDefinition` | `RecordID`, `Capability` | General |
| `taskcoord.AgentDiscoveryRecord` | `RecordID`, `ParticipantID`, `Capability` | General |
| `taskcoord.AgentSearchQuery` | `Capability` | General |
| `taskcoord.Assignment` | `AssignmentID`, `TaskID`, `ParticipantID`, `OfferedByParticipantID`, `ParentAssignmentID` | General |
| `taskcoord.AssignmentDefinition` | `EventID`, `AssignmentID`, `TaskID`, `ParticipantID`, `ParentAssignmentID` | General |
| `taskcoord.AssuranceProvenance` | `ProfileID` | Fixed `asb.taskcoord-human-request/v1` |
| `taskcoord.AuthenticatedHumanMatchQuery` | `ActorID`, `AuthorizationID`, `ProofID`, `VerifierNonce` | General |
| `taskcoord.AuthenticatedInteraction` | `ActorID`, `ParticipantID`, `AuthorizationID`, `ProofID`, `EventID`, `InteractionID`, `TaskID`, `AssignmentID`, `InReplyTo`, `Supersedes`, `VerifierNonce` | General |
| `taskcoord.AuthenticatedOperation` | `ActorID`, `ParticipantID`, `AuthorizationID`, `ProofID`, `TaskID`, `AssignmentID`, `TargetTaskID`, `TargetAssignmentID`, `TargetParticipantID`, `VerifierNonce` | General |
| `taskcoord.AuthenticatedReachabilityAccess` | `GrantID`, `RequesterParticipantID`, `Purpose`, `Capability`, `ActorID`, `AuthorizationID`, `ProofID`, `VerifierNonce` | General |
| `taskcoord.DelegationRecord` | `EventID`, `DecisionID`, `ParentAssignmentID`, `ChildAssignmentID`, `ParentTaskID`, `ChildTaskID`, `FromParticipantID`, `ToParticipantID` | General |
| `taskcoord.Dependency` | `DependencyID`, `FromTaskID`, `ToTaskID`, `GroupID` | General |
| `taskcoord.Event` | `ID` | General event identifier |
| `taskcoord.HumanMatchCandidate` | `CandidateID`, `Capability` | General |
| `taskcoord.HumanMatchConsent` | `ConsentID`, `HumanParticipantID`, `CandidateID`, `RequesterParticipantID`, `Purpose`, `Capability`, `ActorID`, `AuthorizationID`, `ProofID` | General |
| `taskcoord.HumanMatchConsentRevocation` | `EventID`, `ConsentID`, `HumanParticipantID`, `ActorID`, `AuthorizationID`, `ProofID` | General |
| `taskcoord.HumanMatchQuery` | `RequesterParticipantID`, `Purpose`, `Capability` | General |
| `taskcoord.HumanReachabilityDispatchAccess` | `GrantID`, `RequesterParticipantID`, `Purpose`, `Capability` | General |
| `taskcoord.HumanReachabilityGrant` | `GrantID`, `CandidateID`, `RequesterParticipantID`, `Purpose`, `Capability` | General |
| `taskcoord.HumanReachabilityGrantDefinition` | `GrantID`, `ConsentID`, `ApprovedByParticipantID`, `CandidateID`, `RequesterParticipantID`, `Purpose`, `Capability`, `ApprovalActorID`, `ApprovalAuthorizationID`, `ApprovalProofID` | General |
| `taskcoord.HumanReachabilityRevocation` | `EventID`, `GrantID`, `ParticipantID`, `ActorID`, `AuthorizationID`, `ProofID` | General |
| `taskcoord.InteractionEvent` | `EventID`, `InteractionID`, `TaskID`, `AssignmentID`, `InReplyTo`, `Supersedes`, `ActorID`, `ParticipantID`, `AuthorizationID`, `ProofID` | General |
| `taskcoord.InteractionEventDefinition` | `EventID`, `InteractionID`, `TaskID`, `AssignmentID`, `InReplyTo`, `Supersedes` | General |
| `taskcoord.OutboxAcknowledgement` | `DeliveryID`, `ConsumerID`, `LeaseID` | General; internal outbox |
| `taskcoord.OutboxDelivery` | `DeliveryID`, `LeaseID` | General; internal outbox |
| `taskcoord.OutboxEvent` | `EventID`, `TaskID`, `AssignmentID`, `ParticipantID` | General; internal outbox |
| `taskcoord.OutboxPoll` | `ConsumerID`, `LeaseID` | General; internal outbox |
| `taskcoord.Participant` | `ParticipantID` | General |
| `taskcoord.TaskLiveness` | `TaskID` | General |
| `taskcoord.TransitionRecord` | `EventID`, `AssignmentID`, `TaskID`, `ActorID`, `ParticipantID`, `AuthorizationID`, `ProofID` | General |
| `taskcoord.VerifiedDelegation` | `DecisionID`, `ParentAssignmentID`, `ChildAssignmentID`, `FromParticipantID`, `ToParticipantID` | General |
| `taskcoord/asbbinding.ChallengeResponse` | `ChallengeID` | Fixed 64-character lowercase hex |
| `taskcoord/asbbinding.DelegationRequest` | `ParticipantID`, `EventID`, `ParentTaskID`, `ParentAssignmentID`, `DecisionID`, `ChildEventID`, `ChildTaskID`, `ChildAssignmentID`, `TargetParticipantID` | General |
| `taskcoord/asbbinding.ExecuteRequest` | `ChallengeID` | Fixed 64-character lowercase hex |
| `taskcoord/asbbinding.IngressErrorResponse` | `RequestID` | Fixed `asbreq-` plus 32-character lowercase hex |
| `taskcoord/asbbinding.InteractionRequest` | `ParticipantID`, `EventID`, `InteractionID`, `TaskID`, `AssignmentID`, `InReplyTo`, `Supersedes` | General |
| `taskcoord/asbbinding.OfferRequest` | `ParticipantID`, `EventID`, `TaskID`, `AssignmentID`, `TargetParticipantID` | General |
| `taskcoord/asbbinding.TransitionRequest` | `ParticipantID`, `EventID`, `TaskID`, `AssignmentID` | General |
| `taskcoord/actionbinding.AcceptRequest` | `AssignmentID`, `EventID`, `ActionID` | General at this boundary; Action acceptance applies the Action-specific rule |
| `taskcoord/actionbinding.Binding` | `TaskID`, `AssignmentID`, `ActionID` | General |
| `taskcoord/actionbinding.DependencyWait` | `TaskID`, `ActionID`, `DependencyIDs` | General |
| `actionlifecycle.AuthenticatedOperation` | `ActorID`, `AuthorizationID`, `ProofID`, `ActionID`, `VerifierNonce` | Action-specific |
| `actionlifecycle.Definition` | `EventID`, `ActionID`, `OwnerID` | Action-specific |
| `actionlifecycle.Event` | `ID`, `ErrorCode` | Action-specific |
| `actionlifecycle.ExecutorLease` | `LeaseID`, `ExecutorID` | Action-specific |
| `actionlifecycle.LeaseFence` | `LeaseID`, `ExecutorID` | Action-specific |
| `actionlifecycle.Outcome` | `ErrorCode` | Action-specific when present |
| `actionlifecycle.ResumeCondition` | `DependencyActionID`, `Signal` | Action-specific when selected by the condition type |
| `actionlifecycle.Snapshot` | `ActionID`, `OwnerID` | Action-specific |
| `actionlifecycle.TransitionRecord` | `EventID`, `ActorID`, `AuthorizationID`, `ProofID` | Action-specific when present |
| `humanrelay.AuthenticatedRelayIntent` | `ActorID`, `AuthorizationID`, `ProofID`, `VerifierNonce` | General |
| `humanrelay.DispatchRequest` | `IntentID` | General |
| `humanrelay.Event` | `EventID`, `IntentID`, `ProviderAckRef` | Derived relay event ID; other fields general |
| `humanrelay.Intent` | `IntentID`, `GrantID`, `RequesterParticipantID`, `Purpose`, `Capability`, `ActorID`, `AuthorizationID`, `ProofID` | General |
| `humanrelay.ProviderAck` | `IntentID`, `AckRef` | General; `AckRef` becomes `provider_ack_ref` when persisted |
| `humanrelay.Receipt` | `IntentID`, `GrantID` | General |
| `humanrelay.RelayIntentRequest` | `IntentID`, `GrantID`, `RequesterParticipantID`, `Purpose`, `Capability` | General |
| `production.redisTaskEvent` | `AssignmentID` | General; Redis-internal commit marker |
| `production.redisOutboxDelivery` | `DeliveryID`, `LeaseID` | General; Redis/Lua response projection |

## Other bounded strings

These values also use semantic UTF-8 octet limits. The schema's corresponding
`maxLength` remains a code-point precheck.

| Class | Octet limit | Lexical rule |
| --- | ---: | --- |
| TaskCoord and Human-ingress opaque reference | 2048 | exact UTF-8; no `Cc`; no normalization |
| Action reference | 2048 | exact UTF-8; no surrounding `White_Space`, `Cc`, or `<>&"'`; no normalization |
| Relay HTTPS reference | 2048 | absolute `https` URI without userinfo, query, fragment, or `Cc` |
| TaskCoord and Human-ingress detail | 1024 | exact UTF-8; TAB and LF are allowed, other `Cc` values are rejected |
| Action reason detail | 1024 | exact UTF-8; no `Cc` or `<>&"'` |

Cross-language and differential tests must treat schema acceptance followed by
semantic rejection as expected only when an otherwise lexically valid bounded
string exceeds its annotated UTF-8 octet limit, or when a separately documented
cross-field/state rule is being tested. Schema acceptance of surrounding
identifier whitespace or a `Cc` code point is a conformance failure.
