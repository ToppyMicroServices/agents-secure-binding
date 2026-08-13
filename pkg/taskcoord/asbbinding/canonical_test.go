// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"errors"
	"testing"
	"time"

	"github.com/thinksyncs/agents-secure-binding/pkg/taskcoord"
)

const (
	testHumanBob       = "human:bob"
	testTaskTwo        = "task:2"
	testAssignmentTwo  = "assignment:2"
	testChangedDetail  = "changed"
	testEvidenceRefTwo = "urn:evidence:2"
)

func TestCanonicalDigestVectors(t *testing.T) {
	t.Parallel()
	dueAt := time.Date(2026, 8, 14, 9, 30, 15, 123456789, time.FixedZone("EEST", 3*60*60))
	tests := []struct {
		name   string
		want   string
		digest func() (Digest, error)
	}{
		{
			name: "assignment offer",
			want: "35518156006e69c5993b5ea0d4638f84ce081925903f8220a8cfc34701fd10be",
			digest: func() (Digest, error) {
				return OfferDigest(OfferRequest{
					ParticipantID:       "human:alice",
					EventID:             "event:offer:1",
					TaskID:              "task:review:1",
					AssignmentID:        "assignment:reviewer:1",
					TargetParticipantID: "agent:reviewer:1",
					Role:                taskcoord.RoleReviewer,
					AuthorityDigest:     repeatedDigest('a'),
					DueAt:               &dueAt,
				})
			},
		},
		{
			name: "assignment transition",
			want: "88a80a9ce13faca8b0f1aa49484880449228766739439202907a3bf08117723a",
			digest: func() (Digest, error) {
				return TransitionDigest(TransitionRequest{
					ParticipantID:    "human:alice",
					EventID:          "event:accept:1",
					TaskID:           "task:review:1",
					AssignmentID:     "assignment:reviewer:1",
					Operation:        taskcoord.OperationAccept,
					ExpectedRevision: 7,
					Detail:           "accept exact scope",
					EvidenceRef:      "urn:evidence:accept:1",
				})
			},
		},
		{
			name: "assignment delegation",
			want: "c0228acec7b512acc62cc6218558d6ab14c5ad2f8d22d94983a326b1aa3123f2",
			digest: func() (Digest, error) {
				return DelegationDigest(DelegationRequest{
					ParticipantID:       "human:alice",
					EventID:             "event:delegate:1",
					ParentTaskID:        "task:parent:1",
					ParentAssignmentID:  "assignment:parent:1",
					ExpectedRevision:    3,
					Detail:              "delegate review only",
					EvidenceRef:         "urn:evidence:delegate:1",
					DecisionID:          "decision:delegation:1",
					ChildEventID:        "event:child-offer:1",
					ChildTaskID:         "task:child:1",
					ChildAssignmentID:   "assignment:child:1",
					TargetParticipantID: "agent:reviewer:1",
					Role:                taskcoord.RoleReviewer,
					AuthorityDigest:     repeatedDigest('b'),
					DueAt:               &dueAt,
				})
			},
		},
		{
			name: "interaction append",
			want: "86eff5531548ff1b5bf5ebd1dccc3f001f419b0b8dd04926d3c0eb69f8a08aea",
			digest: func() (Digest, error) {
				return InteractionDigest(InteractionRequest{
					ParticipantID: "human:alice",
					EventID:       "event:correction:1",
					InteractionID: "interaction:review:1",
					TaskID:        "task:review:1",
					AssignmentID:  "assignment:reviewer:1",
					Kind:          taskcoord.InteractionCorrection,
					InReplyTo:     "event:question:1",
					Supersedes:    "event:response:1",
					Finality:      taskcoord.ResponseFinal,
					ContentRef:    "urn:content:correction:1",
					ContentDigest: repeatedDigest('c'),
					EvidenceRef:   "urn:evidence:correction:1",
				})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			digest, err := test.digest()
			if err != nil {
				t.Fatal(err)
			}
			if digest.String() != test.want {
				t.Fatalf("digest = %s, want %s", digest.String(), test.want)
			}
		})
	}
}

func TestCanonicalDigestBindsEveryTransitionField(t *testing.T) {
	t.Parallel()
	base := TransitionRequest{
		ParticipantID:    "human:alice",
		EventID:          "event:accept:1",
		TaskID:           "task:1",
		AssignmentID:     "assignment:1",
		Operation:        taskcoord.OperationAccept,
		ExpectedRevision: 1,
		Detail:           "accepted",
		EvidenceRef:      "urn:evidence:1",
	}
	want, err := TransitionDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*TransitionRequest){
		"participant": func(r *TransitionRequest) { r.ParticipantID = testHumanBob },
		"event":       func(r *TransitionRequest) { r.EventID = "event:accept:2" },
		"task":        func(r *TransitionRequest) { r.TaskID = testTaskTwo },
		"assignment":  func(r *TransitionRequest) { r.AssignmentID = testAssignmentTwo },
		"operation":   func(r *TransitionRequest) { r.Operation = taskcoord.OperationDecline },
		"revision":    func(r *TransitionRequest) { r.ExpectedRevision = 2 },
		"detail":      func(r *TransitionRequest) { r.Detail = testChangedDetail },
		"evidence":    func(r *TransitionRequest) { r.EvidenceRef = testEvidenceRefTwo },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			got, err := TransitionDigest(changed)
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatal("mutation did not change request digest")
			}
		})
	}
}

func TestCanonicalDigestBindsEveryOfferField(t *testing.T) {
	t.Parallel()
	dueAt := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	base := OfferRequest{
		ParticipantID: "human:alice", EventID: "event:offer:1", TaskID: "task:1",
		AssignmentID: "assignment:1", TargetParticipantID: "agent:target:1",
		Role: taskcoord.RoleAssignee, AuthorityDigest: repeatedDigest('a'), DueAt: &dueAt,
	}
	want, err := OfferDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*OfferRequest){
		"participant": func(r *OfferRequest) { r.ParticipantID = testHumanBob },
		"event":       func(r *OfferRequest) { r.EventID = "event:offer:2" },
		"task":        func(r *OfferRequest) { r.TaskID = testTaskTwo },
		"assignment":  func(r *OfferRequest) { r.AssignmentID = testAssignmentTwo },
		"target":      func(r *OfferRequest) { r.TargetParticipantID = "agent:target:2" },
		"role":        func(r *OfferRequest) { r.Role = taskcoord.RoleReviewer },
		"authority":   func(r *OfferRequest) { r.AuthorityDigest = repeatedDigest('b') },
		"due": func(r *OfferRequest) {
			changed := dueAt.Add(time.Minute)
			r.DueAt = &changed
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			got, err := OfferDigest(changed)
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatal("mutation did not change request digest")
			}
		})
	}
}

func TestCanonicalDigestBindsEveryDelegationField(t *testing.T) {
	t.Parallel()
	dueAt := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	base := DelegationRequest{
		ParticipantID: "human:alice", EventID: "event:delegate:1",
		ParentTaskID: "task:parent:1", ParentAssignmentID: "assignment:parent:1",
		ExpectedRevision: 2, Detail: "review only", EvidenceRef: "urn:evidence:1",
		DecisionID:   "decision:delegation:1",
		ChildEventID: "event:child:1", ChildTaskID: "task:child:1",
		ChildAssignmentID: "assignment:child:1", TargetParticipantID: "agent:target:1",
		Role: taskcoord.RoleReviewer, AuthorityDigest: repeatedDigest('a'), DueAt: &dueAt,
	}
	want, err := DelegationDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*DelegationRequest){
		"participant":       func(r *DelegationRequest) { r.ParticipantID = testHumanBob },
		"event":             func(r *DelegationRequest) { r.EventID = "event:delegate:2" },
		"parent task":       func(r *DelegationRequest) { r.ParentTaskID = "task:parent:2" },
		"parent assignment": func(r *DelegationRequest) { r.ParentAssignmentID = "assignment:parent:2" },
		"revision":          func(r *DelegationRequest) { r.ExpectedRevision = 3 },
		"detail":            func(r *DelegationRequest) { r.Detail = testChangedDetail },
		"evidence":          func(r *DelegationRequest) { r.EvidenceRef = testEvidenceRefTwo },
		"decision":          func(r *DelegationRequest) { r.DecisionID = "decision:delegation:2" },
		"child event":       func(r *DelegationRequest) { r.ChildEventID = "event:child:2" },
		"child task":        func(r *DelegationRequest) { r.ChildTaskID = "task:child:2" },
		"child assignment":  func(r *DelegationRequest) { r.ChildAssignmentID = "assignment:child:2" },
		"target":            func(r *DelegationRequest) { r.TargetParticipantID = "agent:target:2" },
		"role":              func(r *DelegationRequest) { r.Role = taskcoord.RoleOwner },
		"authority":         func(r *DelegationRequest) { r.AuthorityDigest = repeatedDigest('b') },
		"due": func(r *DelegationRequest) {
			changed := dueAt.Add(time.Minute)
			r.DueAt = &changed
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			got, err := DelegationDigest(changed)
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatal("mutation did not change request digest")
			}
		})
	}
}

func TestCanonicalDigestBindsEveryInteractionField(t *testing.T) {
	t.Parallel()
	base := InteractionRequest{
		ParticipantID: "human:alice", EventID: "event:correction:1",
		InteractionID: "interaction:1", TaskID: "task:1", AssignmentID: "assignment:1",
		Kind: taskcoord.InteractionCorrection, InReplyTo: "event:question:1",
		Supersedes: "event:response:1", Finality: taskcoord.ResponseFinal,
		ContentRef: "urn:content:1", ContentDigest: repeatedDigest('a'), EvidenceRef: "urn:evidence:1",
	}
	want, err := InteractionDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*InteractionRequest){
		"participant": func(r *InteractionRequest) { r.ParticipantID = testHumanBob },
		"event":       func(r *InteractionRequest) { r.EventID = "event:correction:2" },
		"interaction": func(r *InteractionRequest) { r.InteractionID = "interaction:2" },
		"task":        func(r *InteractionRequest) { r.TaskID = testTaskTwo },
		"assignment":  func(r *InteractionRequest) { r.AssignmentID = testAssignmentTwo },
		"reply":       func(r *InteractionRequest) { r.InReplyTo = "event:question:2" },
		"supersedes":  func(r *InteractionRequest) { r.Supersedes = "event:response:2" },
		"finality":    func(r *InteractionRequest) { r.Finality = taskcoord.ResponseInterim },
		"content ref": func(r *InteractionRequest) { r.ContentRef = "urn:content:2" },
		"content digest": func(r *InteractionRequest) {
			r.ContentDigest = repeatedDigest('b')
		},
		"evidence": func(r *InteractionRequest) { r.EvidenceRef = testEvidenceRefTwo },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			got, err := InteractionDigest(changed)
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatal("mutation did not change request digest")
			}
		})
	}
}

func TestRequestKindsAreDomainSeparated(t *testing.T) {
	t.Parallel()
	transition, err := TransitionDigest(TransitionRequest{
		ParticipantID: "human:1", EventID: "event:1", TaskID: "task:1",
		AssignmentID: "assignment:1", Operation: taskcoord.OperationAccept, ExpectedRevision: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	interaction, err := InteractionDigest(InteractionRequest{
		ParticipantID: "human:1", EventID: "event:1", InteractionID: "interaction:1",
		TaskID: "task:1", AssignmentID: "assignment:1", Kind: taskcoord.InteractionQuestion,
		ContentRef: "urn:content:1", ContentDigest: repeatedDigest('d'),
	})
	if err != nil {
		t.Fatal(err)
	}
	if transition == interaction {
		t.Fatal("different request kinds produced the same digest")
	}
}

func TestCanonicalRequestRejectsInvalidSemanticInput(t *testing.T) {
	t.Parallel()
	_, err := TransitionDigest(TransitionRequest{
		ParticipantID: "human:1", EventID: "event:1", TaskID: "task:1",
		AssignmentID: "assignment:1", Operation: taskcoord.OperationDelegate, ExpectedRevision: 1,
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error = %v, want ErrInvalidRequest", err)
	}
}

func repeatedDigest(character byte) string {
	value := make([]byte, 64)
	for index := range value {
		value[index] = character
	}
	return string(value)
}
