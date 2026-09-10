// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package awsiam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
)

const (
	readARN  = "arn:aws:s3:::asb-test-bucket/read.txt"
	extraARN = "arn:aws:s3:::asb-test-bucket/extra.txt"
	testETag = `"0123456789abcdef0123456789abcdef"`
)

func specFixture() Specification {
	return Specification{
		Schema: Schema, RoleARN: "arn:aws:iam::111122223333:role/asb-reader", Region: "eu-west-1", CredentialProfile: "develop", MaxResponseBytes: 1024,
		Objects: []Object{{ARN: readARN, Cost: 1, OwnerAccount: "111122223333"}, {ARN: extraARN, Cost: 5, OwnerAccount: "111122223333"}}, Required: []string{readARN}, Allowed: []string{readARN, extraARN},
		Grants: []GrantPolicy{{ID: "reader", Policy: json.RawMessage(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":[%q]}]}`, readARN))}, {ID: "broad", Policy: json.RawMessage(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":[%q,%q]}]}`, readARN, extraARN))}},
	}
}

func fixture(t *testing.T) (*Profile, lp.Solution, lp.Request) {
	t.Helper()
	raw, err := json.Marshal(specFixture())
	if err != nil {
		t.Fatal(err)
	}
	p, err := Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	s, err := lp.Solve(context.Background(), p.Problem(), 4)
	if err != nil {
		t.Fatal(err)
	}
	args, err := json.Marshal(Arguments{ProfileDigest: p.Digest(), ExpectedBucketOwner: "111122223333", IfMatch: testETag, RangeStart: 0, RangeEnd: 3})
	if err != nil {
		t.Fatal(err)
	}
	return p, s, lp.Request{ActorID: "agent:reader", TaskID: "task:report", Action: lp.Action{Operation: Operation, Resource: readARN, Arguments: args}}
}

func TestCompileSnapshotAndUnsupportedPolicies(t *testing.T) {
	p, solution, _ := fixture(t)
	owned := p.Problem()
	owned.Grants[0].Permissions[0] = "changed"
	if err := lp.Verify(context.Background(), p.Problem(), solution, 4); err != nil {
		t.Fatal("mutable profile", err)
	}
	for name, policy := range map[string]string{
		"deny":              `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":["` + readARN + `"]}]}`,
		"wildcard_action":   `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":["` + readARN + `"]}]}`,
		"wildcard_resource": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":["arn:aws:s3:::asb-test-bucket/*"]}]}`,
		"condition":         `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":["` + readARN + `"],"Condition":{}}]}`,
		"principal":         `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":["` + readARN + `"],"Principal":"*"}]}`,
		"not_action":        `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":"s3:DeleteObject","Resource":["` + readARN + `"]}]}`,
		"not_resource":      `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","NotResource":["` + readARN + `"]}]}`,
		"duplicate_key":     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Effect":"Deny","Action":"s3:GetObject","Resource":["` + readARN + `"]}]}`,
		"case_alias":        `{"Version":"2012-10-17","Statement":[{"effect":"Allow","Action":"s3:GetObject","Resource":["` + readARN + `"]}]}`,
		"unknown":           `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":["` + readARN + `"],"Unknown":null}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			spec := specFixture()
			spec.Grants[0].Policy = json.RawMessage(policy)
			raw, err := json.Marshal(spec)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Compile(raw); err == nil {
				t.Fatal("unsupported policy accepted")
			}
		})
	}
	for _, arn := range []string{"arn:aws:s3:::asb-test-bucket/a/../b", "arn:aws:s3:::asb-test-bucket/a//b", "arn:aws:s3:::asb-test-bucket/a%2Fb", "arn:aws:s3:::asb-test-bucket/a?x=1", "arn:aws:s3:::asb-test-bucket/a#fragment", "arn:aws:s3:::asb-test-bucket/日本語", "arn:aws:s3:::asb.test.bucket/a", "arn:aws:s3:::asb-test-bucket/a*"} {
		if _, _, ok := objectParts(arn); ok {
			t.Fatalf("unsupported ARN accepted: %s", arn)
		}
	}
}

func TestProfileDigestBindsExecutionSpecification(t *testing.T) {
	p, _, _ := fixture(t)
	for _, change := range []func(*Specification){func(s *Specification) { s.Region = "us-east-1" }, func(s *Specification) { s.RoleARN = "arn:aws:iam::111122223333:role/other" }, func(s *Specification) { s.CredentialProfile = "other" }, func(s *Specification) { s.Objects[0].OwnerAccount = "444455556666" }, func(s *Specification) { s.MaxResponseBytes = 1 }, func(s *Specification) { s.Objects[0].Cost = 2 }} {
		s := specFixture()
		change(&s)
		raw, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		next, err := Compile(raw)
		if err != nil {
			t.Fatal(err)
		}
		if next.Digest() == p.Digest() {
			t.Fatal("execution specification not bound")
		}
	}
}

func TestSessionPolicyExplicitDenyEnvelope(t *testing.T) {
	p, s, _ := fixture(t)
	raw, err := p.SessionPolicy(context.Background(), s, 4)
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Version   string
		Statement []struct {
			Effect, Action, NotAction string
			Resource                  json.RawMessage
			NotResource               []string
		}
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Version != policyVersion || len(policy.Statement) != 3 || len(raw) > 2048 {
		t.Fatal("wrong envelope")
	}
	// Model a resource-policy grant directly to the session. It still loses to
	// either generated explicit deny for every unsupported action/resource pair.
	for _, action := range []string{Operation, "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "iam:PassRole", "sts:AssumeRole", "kms:Decrypt"} {
		for _, resource := range []string{readARN, extraARN, "arn:aws:s3:::other-bucket/object"} {
			denied := false
			for _, st := range policy.Statement {
				actionMatches := st.Action == action || (st.NotAction != "" && st.NotAction != action)
				var resources []string
				var scalar string
				if string(st.Resource) != "null" && len(st.Resource) > 0 {
					if err := json.Unmarshal(st.Resource, &resources); err != nil {
						if err := json.Unmarshal(st.Resource, &scalar); err != nil {
							t.Fatal(err)
						}
					}
				}
				resourceMatches := scalar == "*" || slices.Contains(resources, resource) || (len(st.NotResource) > 0 && !slices.Contains(st.NotResource, resource))
				if st.Effect == "Deny" && actionMatches && resourceMatches {
					denied = true
				}
			}
			if denied != (action != Operation || resource != readARN) {
				t.Fatalf("wrong explicit deny for %s %s", action, resource)
			}
		}
	}
	bad := s
	bad.ProblemDigest = "stale"
	if _, err := p.SessionPolicy(context.Background(), bad, 4); !errors.Is(err, lp.ErrInvalidSolution) {
		t.Fatal(err)
	}
	if _, err := p.SessionPolicy(context.Background(), s, 1); !errors.Is(err, lp.ErrLimit) {
		t.Fatal(err)
	}
	if _, err := Compile([]byte(strings.Repeat(" ", MaxInputBytes+1))); err == nil {
		t.Fatal("oversize input accepted")
	}
}
