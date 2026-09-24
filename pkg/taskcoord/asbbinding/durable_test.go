// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

// The Python verifier computes this vector independently from the protocol's
// length-prefixed fields, including the distinct recovery request kind.
func TestRecoveryDigestVector(t *testing.T) {
	request := RecoveryRequest{ParticipantID: "human:alice", OperationID: "event:accept:1", RequestDigest: "88a80a9ce13faca8b0f1aa49484880449228766739439202907a3bf08117723a"}
	digest, err := RecoveryDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	if digest.String() != "fd1ae41106783df5316952a99dce80ee6e5c60def4fab0eac2eccb352c96b6df" {
		t.Fatalf("recovery digest = %s", digest)
	}
	if RequestContextSHA256(digest) != "1feb5e15ed482ccedc812e22015f5b503835314572f1183355a97249dc575b26" {
		t.Fatal("recovery context differs")
	}
	for _, mutate := range []func(*RecoveryRequest){func(r *RecoveryRequest) { r.ParticipantID = "human:bob" }, func(r *RecoveryRequest) { r.OperationID = "event:recovery:other" }, func(r *RecoveryRequest) { r.RequestDigest = repeatedDigest('f') }} {
		changed := request
		mutate(&changed)
		other, err := RecoveryDigest(changed)
		if err != nil || digest == other {
			t.Fatalf("field was not bound: %v", err)
		}
	}
	for _, mutate := range []func(*RecoveryRequest){func(r *RecoveryRequest) { r.ParticipantID = " human:alice" }, func(r *RecoveryRequest) { r.OperationID = "" }, func(r *RecoveryRequest) { r.RequestDigest = "bad-digest" }} {
		invalid := request
		mutate(&invalid)
		if _, err := RecoveryDigest(invalid); err == nil {
			t.Fatal("invalid recovery accepted")
		}
	}
}

func TestHumanOutcomeScopeMatchesOriginalRecord(t *testing.T) {
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	human := testParticipant("human:alice", taskcoord.ParticipantHuman, false, now.Add(-time.Hour))
	assignment := offeredHumanAssignment(t, human, now)
	assignment.LastTransition.Assurance = taskcoord.GatewayAssertedForHumanProvenance()
	record := assignment.LastTransition
	outcome := HumanOutcome{OperationID: record.EventID, RequestDigest: repeatedDigest('a'), ParticipantID: record.ParticipantID, ActorID: record.ActorID, Response: mustJSON(t, ExecuteResponse{Operation: OperationAssignmentOffer, Assignment: &assignment, Record: &record})}
	if err := outcome.Validate(); err != nil {
		t.Fatal(err)
	}
	if outcome.ParticipantID == assignment.ParticipantID {
		t.Fatal("test requires separate requester and assignee")
	}
	for name, mutate := range map[string]func(*HumanOutcome){
		"operation":             func(o *HumanOutcome) { o.OperationID = "event:different" },
		"Actor":                 func(o *HumanOutcome) { o.ActorID = "actor:different" },
		"assignee as requester": func(o *HumanOutcome) { o.ParticipantID = assignment.ParticipantID },
	} {
		t.Run(name, func(t *testing.T) {
			changed := outcome
			mutate(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("mismatched retained scope accepted")
			}
		})
	}
}
