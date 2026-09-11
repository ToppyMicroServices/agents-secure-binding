//go:build awsiam_live

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package awsiam

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
)

// TestLiveS3Profile performs no resource creation. It requires explicit local
// fixture paths and opt-in, and never discovers roles, buckets or object keys.
func TestLiveS3Profile(t *testing.T) {
	if os.Getenv("ASB_AWS_LIVE_CONFIRM") != "read-explicit-fixture" {
		t.Skip("live AWS gate requires explicit opt-in and fixture")
	}
	path := os.Getenv("ASB_AWS_LIVE_FIXTURE")
	if !filepath.IsAbs(path) {
		t.Fatal("absolute ASB_AWS_LIVE_FIXTURE is required")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal("cannot open live fixture")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		t.Fatal("live fixture must be a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxInputBytes+1))
	if err != nil {
		t.Fatal("cannot read live fixture")
	}
	var fixture struct {
		Specification   json.RawMessage `json:"specification"`
		Resource        string          `json:"resource"`
		DeniedResource  string          `json:"denied_resource"`
		Arguments       Arguments       `json:"arguments"`
		CLIPath         string          `json:"cli_path"`
		CredentialsFile string          `json:"credentials_file"`
	}
	if err := strictJSON(raw, &fixture, MaxInputBytes); err != nil {
		t.Fatal("invalid live fixture")
	}
	p, err := Compile(fixture.Specification)
	if err != nil {
		t.Fatal("invalid live profile")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	solution, err := lp.Solve(ctx, p.Problem(), 1<<lp.MaxGrants)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(solution.Effective, fixture.Resource) || slices.Contains(solution.Effective, fixture.DeniedResource) {
		t.Fatal("fixture must select the read resource and exclude the denied resource")
	}
	bucket, _, ok := objectParts(fixture.Resource)
	deniedBucket, deniedKey, deniedOK := objectParts(fixture.DeniedResource)
	if !ok || !deniedOK || bucket != deniedBucket {
		t.Fatal("denied resource must be an explicit supported object in the same bucket")
	}
	if fixture.Arguments.ProfileDigest == "" {
		fixture.Arguments.ProfileDigest = p.Digest()
	}
	arguments, err := json.Marshal(fixture.Arguments)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := NewExecutor(p, CLIConfig{Path: fixture.CLIPath, CredentialsFile: fixture.CredentialsFile, MaxEvaluations: 1 << lp.MaxGrants})
	if err != nil {
		t.Fatal("invalid local CLI configuration")
	}
	request := lp.Request{ActorID: "live-gate:operator", TaskID: "live-gate:read", Action: lp.Action{Operation: Operation, Resource: fixture.Resource, Arguments: arguments}}
	result, err := executor.Execute(ctx, "live-gate:read", request, solution)
	if err != nil || result.State != lp.ExecutionSucceeded {
		t.Fatalf("allowed live read failed: %v", err)
	}
	// Use the same verified envelope to observe denial of the explicitly supplied
	// outside object. This does not establish the cause of every AWS policy result.
	policy, err := p.SessionPolicy(ctx, solution, 1<<lp.MaxGrants)
	if err != nil {
		t.Fatal(err)
	}
	temporary, err := executor.assume(ctx, "live-gate:denied", policy)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+deniedBucket+".s3."+p.spec.Region+".amazonaws.com/"+deniedKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Amz-Expected-Bucket-Owner", fixture.Arguments.ExpectedBucketOwner)
	req.Header.Set("Range", "bytes=0-0")
	req.Header.Set("If-Match", fixture.Arguments.IfMatch)
	signRequest(req, temporary, p.spec.Region, time.Now())
	response, err := executor.client.Do(req)
	if err != nil {
		t.Fatal("live denial request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected AWS403 for outside object, received %d", response.StatusCode)
	}
	t.Logf("live allowed GET succeeded; outside object returned403; receipt=%s", result.EvidenceDigest)
}
