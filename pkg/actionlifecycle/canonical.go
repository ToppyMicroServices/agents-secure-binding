// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionlifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/canonicaltranscript"
)

const MutationRequestSchemaV1 = "asb.action-mutation-request/v1"

// MutationRequestTranscript returns the language-independent v1 transcript
// hashed by MutationRequestDigest. Auth is deliberately excluded because it
// carries the resulting digest.
func MutationRequestTranscript(event Event) ([]byte, error) {
	encoder := canonicaltranscript.New(MutationRequestSchemaV1)
	encoder.String(event.ID)
	encoder.String(string(event.Kind))
	encoder.Uint64(event.ExpectedRevision)
	encoder.Time(event.At)
	encoder.String(string(event.Reason.Code))
	encoder.String(event.Reason.Detail)
	encoder.Optional(event.Fence != nil, func(encoder *canonicaltranscript.Encoder) {
		encoder.String(event.Fence.LeaseID)
		encoder.String(event.Fence.ExecutorID)
		encoder.Uint64(event.Fence.Generation)
	})
	encoder.Optional(event.Lease != nil, func(encoder *canonicaltranscript.Encoder) {
		encoder.String(event.Lease.LeaseID)
		encoder.String(event.Lease.ExecutorID)
		encoder.Uint64(event.Lease.Generation)
		encoder.Time(event.Lease.IssuedAt)
		encoder.Time(event.Lease.ExpiresAt)
	})
	encoder.Optional(event.ResumeCondition != nil, func(encoder *canonicaltranscript.Encoder) {
		encoder.String(string(event.ResumeCondition.Type))
		encoder.Optional(event.ResumeCondition.NotBefore != nil, func(encoder *canonicaltranscript.Encoder) {
			encoder.Time(*event.ResumeCondition.NotBefore)
		})
		encoder.Optional(event.ResumeCondition.ProbeAfter != nil, func(encoder *canonicaltranscript.Encoder) {
			encoder.Time(*event.ResumeCondition.ProbeAfter)
		})
		encoder.String(event.ResumeCondition.Target)
		encoder.String(event.ResumeCondition.DependencyActionID)
		encoder.String(event.ResumeCondition.Signal)
	})
	encoder.Optional(event.Checkpoint != nil, func(encoder *canonicaltranscript.Encoder) {
		encoder.Uint64(event.Checkpoint.Sequence)
		encoder.String(event.Checkpoint.PayloadDigest)
		encoder.String(event.Checkpoint.StorageRef)
		encoder.Time(event.Checkpoint.CreatedAt)
	})
	encoder.String(event.EvidenceRef)
	encoder.String(string(event.ReconciliationResult))
	encoder.String(event.ResultRef)
	encoder.String(event.ErrorCode)

	transcript, err := encoder.Bytes()
	if err != nil {
		return nil, fmt.Errorf("action lifecycle: canonicalize mutation request: %w", err)
	}
	return transcript, nil
}

// MutationRequestDigest returns the canonical digest that an ASB verifier must
// place in AuthenticatedOperation. It binds every caller-controlled Event field,
// including the event identifier, expected revision, fence, lease, checkpoint,
// reconciliation result, and outcome references.
func MutationRequestDigest(event Event) (string, error) {
	transcript, err := MutationRequestTranscript(event)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(transcript)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
