// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// authority-quorum-demo creates two trusted authority projections for a
// three-slot, threshold-two policy. It begins after ASB verification and does
// not simulate secret sharing or external release.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/authorityquorum"
)

func main() {
	ctx := context.Background()
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	authorityMapDigest := digest("demo authority map")
	policy, err := authorityquorum.NewVerifiedPolicy(
		"policy:split-knowledge-demo",
		"reveal.example",
		authorityMapDigest,
		1,
		2,
		[]string{"authority:a", "authority:b", "authority:c"},
		now.Add(-time.Minute),
		now.Add(10*time.Minute),
	)
	if err != nil {
		log.Fatal(err)
	}
	service := authorityquorum.Service{
		Store: authorityquorum.NewMemoryStoreWithClock(func() time.Time { return now }),
		Policies: authorityquorum.PolicyResolverFunc(func(context.Context, string) (authorityquorum.VerifiedPolicy, error) {
			return policy, nil
		}),
		Now: func() time.Time { return now },
	}
	request := authorityquorum.ApprovalRequest{
		DecisionID:      "decision:demo:1",
		PolicyDigest:    policy.PolicyDigest,
		OperationDigest: digest("split-knowledge exact reveal request"),
	}
	approvalDigest, err := authorityquorum.ApprovalDigest(request)
	if err != nil {
		log.Fatal(err)
	}
	for _, authorityID := range []string{"authority:a", "authority:b"} {
		_, err := service.Approve(ctx, request, authorityquorum.AcceptedAuthority{
			ApprovalDigest: approvalDigest, AuthorityMapDigest: authorityMapDigest,
			PrincipalDigest:  digest("principal:" + authorityID),
			CredentialDigest: digest("credential:" + authorityID), AuthorityID: authorityID,
			AuthorizationID: "authorization:" + authorityID,
			ProofIssuer:     "demo:issuer", ProofID: "proof:" + authorityID,
			ProofSignerKey: "key:" + authorityID, Audience: policy.Audience,
			IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(2 * time.Minute),
		})
		if err != nil {
			log.Fatal(err)
		}
	}
	quorum, err := service.Consume(ctx, authorityquorum.ConsumeRequest{
		ConsumptionID: "consume:demo:1", Binding: request.Binding(),
	})
	if err != nil {
		log.Fatal(err)
	}
	raw, err := json.MarshalIndent(quorum, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(raw))
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
