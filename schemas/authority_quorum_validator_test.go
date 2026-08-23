// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package schemas

import "testing"

func TestAuthorityQuorumSchemaAcceptsDurableDocuments(t *testing.T) {
	t.Parallel()
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	documents := []string{
		`{
          "schema":"asb.authority-quorum-policy/v1",
          "policy_id":"policy:1",
          "policy_digest":"` + digest + `",
          "authority_map_digest":"` + digest + `",
          "audience":"reveal.example",
          "epoch":1,
          "threshold":2,
          "authority_ids":["authority:a","authority:b","authority:c"],
          "valid_from":"2026-08-22T09:00:00Z",
          "expires_at":"2026-08-22T11:00:00Z"
        }`,
		`{
          "schema":"asb.authority-approval/v1",
          "approval_id":"proof:a",
          "decision_id":"decision:1",
          "policy_digest":"` + digest + `",
          "operation_digest":"` + digest + `",
          "audience":"reveal.example",
          "authority_id":"authority:a",
          "principal_tag":"` + digest + `",
          "credential_tag":"` + digest + `",
          "authorization_tag":"` + digest + `",
          "approved_at":"2026-08-22T10:00:00Z",
          "expires_at":"2026-08-22T10:05:00Z"
        }`,
		`{
          "schema":"asb.authority-decision-revocation/v1",
          "revocation_id":"revocation:1",
          "decision_id":"decision:1",
          "revoked_at":"2026-08-22T10:00:00Z"
        }`,
		`{
          "schema":"asb.verified-authority-quorum/v1",
          "consumption_id":"consume:1",
          "decision_id":"decision:1",
          "policy_digest":"` + digest + `",
          "operation_digest":"` + digest + `",
          "audience":"reveal.example",
          "threshold":2,
          "approval_count":2,
          "consumed_at":"2026-08-22T10:00:00Z",
          "accepted_until":"2026-08-22T10:05:00Z"
        }`,
	}
	for _, document := range documents {
		if err := ValidateAuthorityQuorumJSON([]byte(document)); err != nil {
			t.Fatalf("valid document rejected: %v\n%s", err, document)
		}
	}
}

func TestAuthorityQuorumSchemaRejectsBadShape(t *testing.T) {
	t.Parallel()
	documents := []string{
		`{
          "schema":"asb.authority-decision-revocation/v1",
          "schema":"asb.authority-decision-revocation/v1",
          "revocation_id":"revocation:duplicate",
          "decision_id":"decision:1",
          "revoked_at":"2026-08-22T10:00:00Z"
        }`,
		`{
          "schema":"asb.authority-approval/v1",
          "approval_id":"proof:a",
          "decision_id":"decision:1",
          "policy_digest":"not-a-digest",
          "operation_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "audience":"reveal.example",
          "authority_id":"authority:a",
          "principal_tag":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          "credential_tag":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
          "authorization_tag":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
          "approved_at":"2026-08-22T10:00:00Z",
          "expires_at":"2026-08-22T10:05:00Z"
        }`,
		`{
          "schema":"asb.authority-decision-revocation/v1",
          "revocation_id":"revocation:1",
          "decision_id":"decision:1",
          "revoked_at":"not-a-date"
        }`,
		`{
          "schema":"asb.authority-decision-revocation/v1",
          "revocation_id":"revocation:1",
          "decision_id":"decision:1",
          "revoked_at":"2026-08-22T10:00:00Z",
          "email":"person@example.com"
        }`,
	}
	for _, document := range documents {
		if err := ValidateAuthorityQuorumJSON([]byte(document)); err == nil {
			t.Fatalf("invalid document accepted: %s", document)
		}
	}
}
