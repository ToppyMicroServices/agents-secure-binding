// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/actionlifecycle"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/humanrelay"
	relayasb "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/humanrelay/asbbinding"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord/actionbinding"
	taskasb "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord/asbbinding"
)

const (
	reportSchema  = "asb.example.human-coordination-e2e-report"
	reportVersion = "v1"

	plannerParticipantID  = "agent:debug-planner"
	executorParticipantID = "agent:debug-executor"
	humanParticipantID    = "human:debug-reviewer"

	plannerActorID  = "runtime:debug-planner"
	executorActorID = "runtime:debug-executor"
	humanGatewayID  = "service:debug-human-gateway"
)

type evidenceReport struct {
	Schema          string              `json:"schema"`
	Version         string              `json:"version"`
	Mode            string              `json:"mode"`
	ProductionClaim bool                `json:"production_claim"`
	Labels          []string            `json:"labels"`
	Runtime         runtimeEvidence     `json:"runtime"`
	Participants    participantEvidence `json:"participants"`
	Actors          actorEvidence       `json:"actors"`
	Boundaries      []boundaryEvidence  `json:"boundaries"`
	Limitations     []string            `json:"limitations"`
	Checks          []evidenceCheck     `json:"checks"`
	Success         bool                `json:"success"`
}

type runtimeEvidence struct {
	SoftwareOnly        bool `json:"software_only"`
	InProcess           bool `json:"in_process"`
	NetworkCalls        bool `json:"network_calls"`
	LiveTLS             bool `json:"live_tls"`
	HardwareAttestation bool `json:"hardware_attestation"`
	ExternalProvider    bool `json:"external_provider"`
}

type participantEvidence struct {
	Planner  string `json:"planner_agent"`
	Executor string `json:"executor_agent"`
	Human    string `json:"human"`
}

type actorEvidence struct {
	Planner      string `json:"planner"`
	Executor     string `json:"executor"`
	HumanGateway string `json:"human_gateway"`
}

type boundaryEvidence struct {
	ID             string `json:"id"`
	Classification string `json:"classification"`
	ProfileID      string `json:"profile_id,omitempty"`
	AssuranceLevel string `json:"assurance_level,omitempty"`
	EvidenceSource string `json:"evidence_source"`
}

type evidenceCheck struct {
	Sequence int    `json:"sequence"`
	Name     string `json:"name"`
	State    string `json:"state"`
	Subject  string `json:"subject,omitempty"`
}

type scenarioRecorder struct {
	checks []evidenceCheck
}

func (r *scenarioRecorder) add(name, state, subject string) {
	r.checks = append(r.checks, evidenceCheck{
		Sequence: len(r.checks) + 1,
		Name:     name,
		State:    state,
		Subject:  subject,
	})
}

func runScenario(ctx context.Context) (evidenceReport, error) {
	if ctx == nil {
		return evidenceReport{}, errorsForStep("initialize", fmt.Errorf("context is required"))
	}

	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	registeredAt := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	planner := localParticipant(plannerParticipantID, taskcoord.ParticipantAgent, registeredAt)
	executor := localParticipant(executorParticipantID, taskcoord.ParticipantAgent, registeredAt)
	human := localParticipant(humanParticipantID, taskcoord.ParticipantHuman, registeredAt)
	taskStore := taskcoord.NewMemoryStore()
	for _, participant := range []taskcoord.Participant{planner, executor, human} {
		if err := taskStore.RegisterParticipant(ctx, participant); err != nil {
			return evidenceReport{}, errorsForStep("register participants", err)
		}
	}
	recorder := scenarioRecorder{}
	recorder.add("participants_registered", "ACTIVE", "three-local-participants")

	assignmentDefinition := taskcoord.AssignmentDefinition{
		EventID:         "event:debug:assignment:offer",
		AssignmentID:    "assignment:debug:human-review",
		TaskID:          "task:debug:human-review",
		ParticipantID:   human.ParticipantID,
		Role:            taskcoord.RoleAssignee,
		AuthorityDigest: digestHex("debug-human-assignment-authority"),
		OfferedAt:       base,
	}
	offerAuthorization := taskcoord.AuthenticatedOperation{
		ActorID:             plannerActorID,
		ParticipantID:       planner.ParticipantID,
		AuthorizationID:     "authorization:debug:assignment:offer",
		ProofID:             "proof:debug:assignment:offer",
		Operation:           taskcoord.OperationOffer,
		TaskID:              assignmentDefinition.TaskID,
		AssignmentID:        assignmentDefinition.AssignmentID,
		TargetParticipantID: human.ParticipantID,
		VerifierNonce:       "nonce:debug:assignment:offer",
		IssuedAt:            base.Add(-time.Minute),
		ExpiresAt:           base.Add(30 * time.Minute),
	}
	offered, err := taskcoord.Offer(assignmentDefinition, human, offerAuthorization)
	if err != nil {
		return evidenceReport{}, errorsForStep("offer Human Assignment", err)
	}
	if err := taskStore.CommitAssignment(ctx, 0, offered.Assignment, offered.Record); err != nil {
		return evidenceReport{}, errorsForStep("commit Human Assignment offer", err)
	}
	recorder.add("human_assignment_offered", string(offered.Assignment.Status), offered.Assignment.AssignmentID)

	humanNow := base.Add(time.Minute)
	humanProfile := taskasb.Profile{Participants: taskStore, Now: func() time.Time { return humanNow }}
	acceptRequest := taskasb.TransitionRequest{
		ParticipantID:    human.ParticipantID,
		EventID:          "event:debug:assignment:accept",
		TaskID:           offered.Assignment.TaskID,
		AssignmentID:     offered.Assignment.AssignmentID,
		Operation:        taskcoord.OperationAccept,
		ExpectedRevision: offered.Assignment.Revision,
		Detail:           "accept local debug review",
		EvidenceRef:      "urn:evidence:debug:human-accept",
	}
	acceptDigest, err := taskasb.TransitionDigest(acceptRequest)
	if err != nil {
		return evidenceReport{}, errorsForStep("digest Human acceptance", err)
	}
	acceptEvidence, err := newHumanEvidence(
		humanNow,
		acceptDigest,
		"authorization:debug:human-accept",
		"proof:debug:human-accept",
		"nonce:debug:human-accept",
	)
	if err != nil {
		return evidenceReport{}, errorsForStep("create Human acceptance evidence", err)
	}
	accepted, err := humanProfile.Apply(ctx, offered.Assignment, acceptRequest, acceptEvidence)
	if err != nil {
		return evidenceReport{}, errorsForStep("verify Human acceptance", err)
	}
	if accepted.Record.ActorID != humanGatewayID || accepted.Record.ParticipantID != human.ParticipantID {
		return evidenceReport{}, errorsForStep("verify Human gateway separation", fmt.Errorf("unexpected participant/actor binding"))
	}
	if err := taskStore.CommitAssignment(
		ctx,
		offered.Assignment.Revision,
		accepted.Assignment,
		accepted.Record,
	); err != nil {
		return evidenceReport{}, errorsForStep("commit Human acceptance", err)
	}
	recorder.add("human_assignment_accepted", string(accepted.Assignment.Status), accepted.Assignment.AssignmentID)

	questionAt := base.Add(2 * time.Minute)
	questionDefinition := taskcoord.InteractionEventDefinition{
		EventID:       "event:debug:interaction:question",
		InteractionID: "interaction:debug:human-review",
		TaskID:        accepted.Assignment.TaskID,
		AssignmentID:  accepted.Assignment.AssignmentID,
		Kind:          taskcoord.InteractionQuestion,
		ContentRef:    "urn:encrypted-content:debug-question",
		ContentDigest: digestHex("debug-agent-question"),
		EvidenceRef:   "urn:evidence:debug:planner-question",
		At:            questionAt,
	}
	questionAuthorization := taskcoord.AuthenticatedInteraction{
		ActorID:         plannerActorID,
		ParticipantID:   planner.ParticipantID,
		AuthorizationID: "authorization:debug:planner-question",
		ProofID:         "proof:debug:planner-question",
		EventID:         questionDefinition.EventID,
		InteractionID:   questionDefinition.InteractionID,
		TaskID:          questionDefinition.TaskID,
		AssignmentID:    questionDefinition.AssignmentID,
		Kind:            questionDefinition.Kind,
		ContentRef:      questionDefinition.ContentRef,
		ContentDigest:   questionDefinition.ContentDigest,
		EvidenceRef:     questionDefinition.EvidenceRef,
		At:              questionDefinition.At,
		VerifierNonce:   "nonce:debug:planner-question",
		IssuedAt:        questionAt.Add(-time.Minute),
		ExpiresAt:       questionAt.Add(30 * time.Minute),
	}
	question, err := taskcoord.NewInteractionEvent(questionDefinition, questionAuthorization)
	if err != nil {
		return evidenceReport{}, errorsForStep("authorize Agent question", err)
	}
	if err := taskStore.AppendInteractionEvent(ctx, question); err != nil {
		return evidenceReport{}, errorsForStep("append Agent question", err)
	}
	recorder.add("agent_question_appended", string(question.Kind), question.EventID)

	reachabilityNow := base.Add(3 * time.Minute)
	directory, err := taskcoord.NewMemoryReachabilityDirectoryWithClock(
		taskStore,
		func() time.Time { return reachabilityNow },
	)
	if err != nil {
		return evidenceReport{}, errorsForStep("create reachability directory", err)
	}
	consentStart := base.Add(2 * time.Minute)
	consentEnd := base.Add(20 * time.Minute)
	consent := taskcoord.HumanMatchConsent{
		Schema:                 taskcoord.HumanMatchConsentSchemaV1,
		ConsentID:              "consent:debug:human-review",
		HumanParticipantID:     human.ParticipantID,
		CandidateID:            "candidate:debug:pairwise-reviewer",
		RequesterParticipantID: planner.ParticipantID,
		Purpose:                "human-review",
		Capability:             "answer-review-question",
		Channel:                taskcoord.ReachabilityEmail,
		ContactRequestRef:      "https://relay.invalid/contact-requests/debug-reviewer",
		ActorID:                humanGatewayID,
		AuthorizationID:        "authorization:debug:reachability-consent",
		ProofID:                "proof:debug:reachability-consent",
		GrantedAt:              consentStart,
		ExpiresAt:              consentEnd,
	}
	if err := directory.RegisterHumanMatchConsent(ctx, consent); err != nil {
		return evidenceReport{}, errorsForStep("register consent-scoped reachability", err)
	}
	matchRequest := taskcoord.AuthenticatedHumanMatchQuery{
		Query: taskcoord.HumanMatchQuery{
			RequesterParticipantID: planner.ParticipantID,
			Purpose:                consent.Purpose,
			Capability:             consent.Capability,
			Channel:                consent.Channel,
			Limit:                  1,
		},
		ActorID:         plannerActorID,
		AuthorizationID: "authorization:debug:reachability-match",
		ProofID:         "proof:debug:reachability-match",
		VerifierNonce:   "nonce:debug:reachability-match",
		IssuedAt:        consentStart,
		ExpiresAt:       consentEnd,
	}
	matches, err := directory.MatchHumans(ctx, matchRequest)
	if err != nil {
		return evidenceReport{}, errorsForStep("match consent-scoped Human", err)
	}
	if len(matches) != 1 || matches[0].CandidateID != consent.CandidateID {
		return evidenceReport{}, errorsForStep("match consent-scoped Human", fmt.Errorf("unexpected pairwise candidate set"))
	}
	grant, err := directory.IssueHumanReachabilityGrant(ctx, taskcoord.HumanReachabilityGrantDefinition{
		GrantID:                 "grant:debug:human-review",
		ConsentID:               consent.ConsentID,
		ApprovedByParticipantID: human.ParticipantID,
		CandidateID:             matches[0].CandidateID,
		RequesterParticipantID:  planner.ParticipantID,
		Purpose:                 consent.Purpose,
		Capability:              consent.Capability,
		Channel:                 consent.Channel,
		RelaySessionRef:         "https://relay.invalid/sessions/opaque-debug-reviewer",
		IssuedAt:                consentStart.Add(30 * time.Second),
		ExpiresAt:               base.Add(15 * time.Minute),
		ApprovalActorID:         humanGatewayID,
		ApprovalAuthorizationID: "authorization:debug:reachability-grant",
		ApprovalProofID:         "proof:debug:reachability-grant",
	})
	if err != nil {
		return evidenceReport{}, errorsForStep("issue consent-scoped reachability grant", err)
	}
	recorder.add("reachability_grant_issued", "ACTIVE", grant.GrantID)

	relayRequest := humanrelay.RelayIntentRequest{
		IntentID:               "intent:debug:agent-question",
		GrantID:                grant.GrantID,
		RequesterParticipantID: planner.ParticipantID,
		Purpose:                grant.Purpose,
		Capability:             grant.Capability,
		Channel:                grant.Channel,
		ContentRef:             "https://relay.invalid/content/debug-agent-question",
		ContentDigest:          question.ContentDigest,
	}
	relayDigest, err := humanrelay.RequestDigest(relayRequest)
	if err != nil {
		return evidenceReport{}, errorsForStep("digest exact Agent relay intent", err)
	}
	relayAt := reachabilityNow
	relayEvidence, err := newRelayEvidence(
		relayAt,
		relayDigest,
		"authorization:debug:agent-relay",
		"proof:debug:agent-relay",
		"nonce:debug:agent-relay",
	)
	if err != nil {
		return evidenceReport{}, errorsForStep("create Agent relay evidence", err)
	}
	relayProfile := relayasb.Profile{Participants: taskStore, Now: func() time.Time { return relayAt }}
	relayAuthorization, err := relayProfile.VerifyAndConsume(ctx, relayRequest, relayEvidence)
	if err != nil {
		return evidenceReport{}, errorsForStep("verify exact Agent relay intent", err)
	}
	relayStore, err := humanrelay.NewMemoryStore(directory)
	if err != nil {
		return evidenceReport{}, errorsForStep("create local relay outbox", err)
	}
	relayService, err := humanrelay.NewService(relayStore, func() time.Time { return relayAt })
	if err != nil {
		return evidenceReport{}, errorsForStep("create relay service", err)
	}
	queued, err := relayService.Queue(ctx, relayRequest, relayAuthorization)
	if err != nil {
		return evidenceReport{}, errorsForStep("queue exact Agent relay intent", err)
	}
	recorder.add("relay_intent_queued", string(queued.Status), queued.IntentID)

	gateway := humanrelay.NewLocalGatewaySink(func() time.Time { return relayAt.Add(1500 * time.Millisecond) })
	dispatchClock := newSequenceClock(
		relayAt.Add(time.Second),
		relayAt.Add(2*time.Second),
	)
	worker, err := humanrelay.NewWorkerWithClock(relayStore, gateway, dispatchClock)
	if err != nil {
		return evidenceReport{}, errorsForStep("create local relay worker", err)
	}
	dispatched, err := worker.Dispatch(ctx, relayRequest.IntentID)
	if err != nil {
		return evidenceReport{}, errorsForStep("dispatch to LocalGatewaySink", err)
	}
	localDelivery, err := gateway.Load(relayRequest.IntentID)
	if err != nil {
		return evidenceReport{}, errorsForStep("inspect LocalGatewaySink", err)
	}
	if localDelivery.IntentID != relayRequest.IntentID || localDelivery.ContentDigest != relayRequest.ContentDigest {
		return evidenceReport{}, errorsForStep("inspect LocalGatewaySink", fmt.Errorf("delivery changed exact relay intent"))
	}
	recorder.add("local_gateway_acknowledged", string(dispatched.Status), dispatched.IntentID)

	humanNow = base.Add(4 * time.Minute)
	responseRequest := taskasb.InteractionRequest{
		ParticipantID: human.ParticipantID,
		EventID:       "event:debug:interaction:response",
		InteractionID: question.InteractionID,
		TaskID:        accepted.Assignment.TaskID,
		AssignmentID:  accepted.Assignment.AssignmentID,
		Kind:          taskcoord.InteractionResponse,
		InReplyTo:     question.EventID,
		Finality:      taskcoord.ResponseFinal,
		ContentRef:    "urn:encrypted-content:debug-human-response",
		ContentDigest: digestHex("debug-human-response"),
		EvidenceRef:   "urn:evidence:debug:human-response",
	}
	responseDigest, err := taskasb.InteractionDigest(responseRequest)
	if err != nil {
		return evidenceReport{}, errorsForStep("digest Human response", err)
	}
	responseEvidence, err := newHumanEvidence(
		humanNow,
		responseDigest,
		"authorization:debug:human-response",
		"proof:debug:human-response",
		"nonce:debug:human-response",
	)
	if err != nil {
		return evidenceReport{}, errorsForStep("create Human response evidence", err)
	}
	response, err := humanProfile.NewInteractionEvent(ctx, responseRequest, responseEvidence)
	if err != nil {
		return evidenceReport{}, errorsForStep("verify Human response", err)
	}
	if response.ActorID != humanGatewayID || response.ParticipantID != human.ParticipantID {
		return evidenceReport{}, errorsForStep("verify Human response gateway separation", fmt.Errorf("unexpected participant/actor binding"))
	}
	if err := taskStore.AppendInteractionEvent(ctx, response); err != nil {
		return evidenceReport{}, errorsForStep("append Human response", err)
	}
	recorder.add("human_response_appended", string(response.Kind), response.EventID)

	actionNow := base.Add(5 * time.Minute)
	actionStore, err := actionbinding.NewMemoryStoreWithClock(
		[]taskcoord.Assignment{accepted.Assignment},
		nil,
		func() time.Time { return actionNow },
	)
	if err != nil {
		return evidenceReport{}, errorsForStep("create Task-Action store", err)
	}
	actionService, err := actionbinding.NewService(actionStore, func() time.Time { return actionNow })
	if err != nil {
		return evidenceReport{}, errorsForStep("create Task-Action service", err)
	}
	actionRequest := actionbinding.AcceptRequest{
		AssignmentID: accepted.Assignment.AssignmentID,
		EventID:      "event:debug:action:accept",
		ActionID:     "action:debug:human-review",
		ActionDigest: "sha256:" + digestHex("debug-human-review-action"),
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{
			Mode:           actionlifecycle.RecoveryRestartIdempotent,
			MaxAttempts:    1,
			IdempotencyKey: "idempotency:debug:human-review-action",
		},
	}
	actionAcceptanceDigest, err := actionbinding.AcceptanceRequestDigest(accepted.Assignment, actionRequest)
	if err != nil {
		return evidenceReport{}, errorsForStep("digest Task-Action acceptance", err)
	}
	actionRequest.Auth = &actionlifecycle.AuthenticatedOperation{
		ActorID:         humanGatewayID,
		AuthorizationID: "authorization:debug:action:accept",
		ProofID:         "proof:debug:action:accept",
		Operation:       actionlifecycle.EventAccept,
		ActionID:        actionRequest.ActionID,
		ActionDigest:    actionRequest.ActionDigest,
		MutationDigest:  actionAcceptanceDigest,
		VerifierNonce:   "nonce:debug:action:accept",
		IssuedAt:        actionNow.Add(-time.Minute),
		ExpiresAt:       actionNow.Add(30 * time.Minute),
	}
	actionView, err := actionService.Accept(ctx, actionRequest)
	if err != nil {
		return evidenceReport{}, errorsForStep("commit exact Task-Action binding", err)
	}
	storedBinding, err := actionStore.LoadBinding(ctx, actionRequest.ActionID)
	if err != nil || storedBinding != actionView.Binding {
		return evidenceReport{}, errorsForStep("verify exact Task-Action binding", errOr(err, "binding changed after commit"))
	}
	recorder.add("task_action_bound", string(actionView.Action.State), actionView.Action.ActionID)

	eligible, err := actionbinding.FulfillmentEligible(actionView.Binding, actionView.Assignment, actionView.Action)
	if err != nil {
		return evidenceReport{}, errorsForStep("check early fulfillment", err)
	}
	if eligible {
		return evidenceReport{}, errorsForStep("check early fulfillment", fmt.Errorf("fulfillment became eligible before Action success"))
	}
	recorder.add("fulfillment_before_action_success", "NOT_ELIGIBLE", actionView.Assignment.AssignmentID)

	actionNow = base.Add(6 * time.Minute)
	start := newActionEvent(actionView.Action, actionlifecycle.EventStart, actionNow, executorActorID)
	start.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonStarted}
	start.Lease = newActionLease(actionView.Action.LeaseGeneration+1, executorActorID, actionNow)
	if err := bindActionMutation(&start); err != nil {
		return evidenceReport{}, errorsForStep("bind Action START", err)
	}
	actionView, err = actionService.Transition(ctx, actionView.Action.ActionID, start)
	if err != nil {
		return evidenceReport{}, errorsForStep("start Action", err)
	}
	recorder.add("action_started", string(actionView.Action.State), actionView.Action.ActionID)

	actionNow = base.Add(7 * time.Minute)
	wait := currentExecutorActionEvent(actionView.Action, actionlifecycle.EventWait, actionNow)
	wait.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonScheduled}
	wait.ResumeCondition = &actionlifecycle.ResumeCondition{Type: actionlifecycle.ResumeManual}
	if err := bindActionMutation(&wait); err != nil {
		return evidenceReport{}, errorsForStep("bind Action WAIT", err)
	}
	actionView, err = actionService.Transition(ctx, actionView.Action.ActionID, wait)
	if err != nil {
		return evidenceReport{}, errorsForStep("wait Action manually", err)
	}
	recorder.add("action_waited", string(actionView.Action.State), string(actionView.Action.ResumeCondition.Type))

	actionNow = base.Add(8 * time.Minute)
	resume := newActionEvent(actionView.Action, actionlifecycle.EventResume, actionNow, executorActorID)
	resume.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonResumed}
	resume.EvidenceRef = "urn:evidence:debug:manual-resume"
	resume.Lease = newActionLease(actionView.Action.LeaseGeneration+1, executorActorID, actionNow)
	if err := bindActionMutation(&resume); err != nil {
		return evidenceReport{}, errorsForStep("bind Action RESUME", err)
	}
	actionView, err = actionService.Transition(ctx, actionView.Action.ActionID, resume)
	if err != nil {
		return evidenceReport{}, errorsForStep("resume Action", err)
	}
	recorder.add("action_resumed", string(actionView.Action.State), actionView.Action.ActionID)

	actionNow = base.Add(9 * time.Minute)
	complete := currentExecutorActionEvent(actionView.Action, actionlifecycle.EventComplete, actionNow)
	complete.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonCompleted}
	complete.ResultRef = "urn:result:debug:human-review"
	if err := bindActionMutation(&complete); err != nil {
		return evidenceReport{}, errorsForStep("bind Action COMPLETE", err)
	}
	actionView, err = actionService.Transition(ctx, actionView.Action.ActionID, complete)
	if err != nil {
		return evidenceReport{}, errorsForStep("complete Action", err)
	}
	recorder.add("action_completed", string(actionView.Action.State), actionView.Action.ActionID)

	eligible, err = actionbinding.FulfillmentEligible(actionView.Binding, actionView.Assignment, actionView.Action)
	if err != nil {
		return evidenceReport{}, errorsForStep("check fulfillment eligibility", err)
	}
	if !eligible {
		return evidenceReport{}, errorsForStep("check fulfillment eligibility", fmt.Errorf("successful Action did not make fulfillment eligible"))
	}
	recorder.add("fulfillment_after_action_success", "ELIGIBLE", actionView.Assignment.AssignmentID)

	humanNow = base.Add(10 * time.Minute)
	fulfillRequest := taskasb.TransitionRequest{
		ParticipantID:    human.ParticipantID,
		EventID:          "event:debug:assignment:fulfill",
		TaskID:           accepted.Assignment.TaskID,
		AssignmentID:     accepted.Assignment.AssignmentID,
		Operation:        taskcoord.OperationFulfill,
		ExpectedRevision: accepted.Assignment.Revision,
		Detail:           "fulfill only after successful Action",
		EvidenceRef:      "urn:evidence:debug:human-fulfill",
	}
	fulfillDigest, err := taskasb.TransitionDigest(fulfillRequest)
	if err != nil {
		return evidenceReport{}, errorsForStep("digest Human fulfillment", err)
	}
	fulfillEvidence, err := newHumanEvidence(
		humanNow,
		fulfillDigest,
		"authorization:debug:human-fulfill",
		"proof:debug:human-fulfill",
		"nonce:debug:human-fulfill",
	)
	if err != nil {
		return evidenceReport{}, errorsForStep("create Human fulfillment evidence", err)
	}
	fulfilled, err := humanProfile.Apply(ctx, accepted.Assignment, fulfillRequest, fulfillEvidence)
	if err != nil {
		return evidenceReport{}, errorsForStep("verify Human fulfillment", err)
	}
	if fulfilled.Record.ActorID != humanGatewayID || fulfilled.Record.ParticipantID != human.ParticipantID {
		return evidenceReport{}, errorsForStep("verify Human fulfillment gateway separation", fmt.Errorf("unexpected participant/actor binding"))
	}
	if err := taskStore.CommitAssignment(
		ctx,
		accepted.Assignment.Revision,
		fulfilled.Assignment,
		fulfilled.Record,
	); err != nil {
		return evidenceReport{}, errorsForStep("commit Human fulfillment", err)
	}
	recorder.add("human_assignment_fulfilled", string(fulfilled.Assignment.Status), fulfilled.Assignment.AssignmentID)

	return evidenceReport{
		Schema:          reportSchema,
		Version:         reportVersion,
		Mode:            "debug-simple",
		ProductionClaim: false,
		Labels: []string{
			"simulated",
			"software-only",
			"in-process",
			"no-network",
			"no-hardware-attestation",
		},
		Runtime: runtimeEvidence{
			SoftwareOnly:        true,
			InProcess:           true,
			NetworkCalls:        false,
			LiveTLS:             false,
			HardwareAttestation: false,
			ExternalProvider:    false,
		},
		Participants: participantEvidence{
			Planner:  planner.ParticipantID,
			Executor: executor.ParticipantID,
			Human:    human.ParticipantID,
		},
		Actors: actorEvidence{
			Planner:      plannerActorID,
			Executor:     executorActorID,
			HumanGateway: humanGatewayID,
		},
		Boundaries: []boundaryEvidence{
			{ID: "human-taskcoord", Classification: "external-asb", ProfileID: taskasb.ProfileID, AssuranceLevel: string(taskasb.CurrentHumanAssuranceLevel), EvidenceSource: "signed-simulated-asb"},
			{ID: "agent-relay-authorization", Classification: "external-asb", ProfileID: relayasb.ProfileID, EvidenceSource: "signed-simulated-asb"},
			{ID: "agent-taskcoord", Classification: "trusted-internal", EvidenceSource: "fixture-projection"},
			{ID: "action-acceptance", Classification: "trusted-internal", EvidenceSource: "fixture-projection"},
			{ID: "action-mutation", Classification: "trusted-internal", EvidenceSource: "fixture-projection"},
			{ID: "human-matching", Classification: "trusted-internal", EvidenceSource: "fixture-projection"},
			{ID: "reachability-administration", Classification: "trusted-internal", EvidenceSource: "fixture-projection"},
			{ID: "relay-queue", Classification: "trusted-internal", EvidenceSource: "asb-derived-projection"},
			{ID: "relay-dispatch", Classification: "trusted-internal", EvidenceSource: "trusted-worker"},
		},
		Limitations: []string{
			"MemoryStores and LocalGatewaySink are in-process reference implementations.",
			"Human TaskCoord and Agent relay operations use signed simulated ASB evidence.",
			"Human TaskCoord evidence is gateway-asserted-for-human; it is not authenticated-Human, Human-held-key, liveness, UI-confirmation, or legal-consent evidence.",
			"No live TLS, hardware attestation, or external provider is used.",
			"Agent TaskCoord, Action acceptance and mutation, Human matching, and reachability administration are explicitly trusted-internal fixture boundaries without external ASB profiles.",
			"TaskCoord and Task-Action use separate reference stores; eligibility and fulfillment are not one durable transaction.",
		},
		Checks:  recorder.checks,
		Success: true,
	}, nil
}

func localParticipant(id string, kind taskcoord.ParticipantKind, registeredAt time.Time) taskcoord.Participant {
	return taskcoord.Participant{
		Schema:        taskcoord.ParticipantSchemaV1,
		ParticipantID: id,
		Kind:          kind,
		IdentityRef:   "urn:identity:debug:" + id,
		Status:        taskcoord.ParticipantActive,
		RegisteredAt:  registeredAt,
	}
}

func digestHex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func newSequenceClock(values ...time.Time) func() time.Time {
	index := 0
	return func() time.Time {
		if len(values) == 0 {
			return time.Time{}
		}
		if index >= len(values) {
			return values[len(values)-1]
		}
		value := values[index]
		index++
		return value
	}
}

func newActionEvent(
	snapshot actionlifecycle.Snapshot,
	kind actionlifecycle.EventKind,
	at time.Time,
	actorID string,
) actionlifecycle.Event {
	suffix := strings.ToLower(string(kind))
	return actionlifecycle.Event{
		ID:               fmt.Sprintf("event:debug:action:%s:%d", suffix, snapshot.Revision),
		Kind:             kind,
		ExpectedRevision: snapshot.Revision,
		At:               at,
		Auth: &actionlifecycle.AuthenticatedOperation{
			ActorID:         actorID,
			AuthorizationID: fmt.Sprintf("authorization:debug:action:%s:%d", suffix, snapshot.Revision),
			ProofID:         fmt.Sprintf("proof:debug:action:%s:%d", suffix, snapshot.Revision),
			Operation:       kind,
			ActionID:        snapshot.ActionID,
			ActionDigest:    snapshot.ActionDigest,
			VerifierNonce:   fmt.Sprintf("nonce:debug:action:%s:%d", suffix, snapshot.Revision),
			IssuedAt:        at.Add(-time.Minute),
			ExpiresAt:       at.Add(30 * time.Minute),
		},
	}
}

func currentExecutorActionEvent(
	snapshot actionlifecycle.Snapshot,
	kind actionlifecycle.EventKind,
	at time.Time,
) actionlifecycle.Event {
	event := newActionEvent(snapshot, kind, at, snapshot.ExecutorLease.ExecutorID)
	event.Fence = &actionlifecycle.LeaseFence{
		LeaseID:    snapshot.ExecutorLease.LeaseID,
		ExecutorID: snapshot.ExecutorLease.ExecutorID,
		Generation: snapshot.ExecutorLease.Generation,
	}
	return event
}

func newActionLease(generation uint64, executorID string, at time.Time) *actionlifecycle.ExecutorLease {
	return &actionlifecycle.ExecutorLease{
		LeaseID:    fmt.Sprintf("lease:debug:action:%d", generation),
		ExecutorID: executorID,
		Generation: generation,
		IssuedAt:   at,
		ExpiresAt:  at.Add(10 * time.Minute),
	}
}

func bindActionMutation(event *actionlifecycle.Event) error {
	digest, err := actionlifecycle.MutationRequestDigest(*event)
	if err != nil {
		return err
	}
	event.Auth.MutationDigest = digest
	return nil
}

func errorsForStep(step string, err error) error {
	return fmt.Errorf("human coordination debug example: %s: %w", step, err)
}

func errOr(err error, message string) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("%s", message)
}
