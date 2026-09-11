// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package awsiam

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
)

type sessionStatement struct {
	Effect      string   `json:"Effect"`
	Action      string   `json:"Action,omitempty"`
	NotAction   string   `json:"NotAction,omitempty"`
	Resource    any      `json:"Resource,omitempty"`
	NotResource []string `json:"NotResource,omitempty"`
}

// SessionPolicy verifies the finite solution and emits explicit denial outside
// its envelope. Allow alone cannot bound a grant directly to a role session.
func (p *Profile) SessionPolicy(ctx context.Context, s lp.Solution, budget uint64) ([]byte, error) {
	if p == nil {
		return nil, ErrProfile
	}
	if err := lp.Verify(ctx, p.problem, s, budget); err != nil {
		return nil, err
	}
	if len(s.Effective) == 0 {
		return nil, lp.ErrBinding
	}
	resources := slices.Clone(s.Effective)
	slices.Sort(resources)
	policy := struct {
		Version   string             `json:"Version"`
		Statement []sessionStatement `json:"Statement"`
	}{policyVersion, []sessionStatement{
		{Effect: "Deny", NotAction: Operation, Resource: "*"},
		{Effect: "Deny", Action: Operation, NotResource: resources},
		{Effect: "Allow", Action: Operation, Resource: resources},
	}}
	raw, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	if len(raw) > 2048 {
		return nil, ErrProfile
	}
	return raw, nil
}

// CLIConfig is local operator configuration. Only explicit static-credential
// profiles are supported. SSO, credential_process, metadata and ambient sources
// are not used. The credential file is read only when execution is invoked.
type CLIConfig struct {
	Path            string
	CredentialsFile string
	MaxEvaluations  uint64
}

type Executor struct {
	profile *Profile
	config  CLIConfig
	client  *http.Client
	clock   func() time.Time
}

func NewExecutor(profile *Profile, config CLIConfig) (*Executor, error) {
	if profile == nil || !filepath.IsAbs(config.Path) || !filepath.IsAbs(config.CredentialsFile) || config.MaxEvaluations == 0 {
		return nil, ErrProfile
	}
	info, err := os.Stat(config.Path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return nil, ErrProfile
	}
	// Fresh HTTP/1 connections avoid Transport's automatic retries on reused
	// connections. A response lost after dispatch must remain UNKNOWN.
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 64 << 10, DisableCompression: true, DisableKeepAlives: true, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Executor{profile: profile, config: config, client: client, clock: time.Now}, nil
}

// Execute has the asbbinding.Executor signature. The service supplies an
// authenticated exact request and accepted-capability deadline. This adapter
// independently validates the finite permission set before acquiring credentials.
// It returns only a content/receipt digest, never object bytes or credentials.
func (e *Executor) Execute(ctx context.Context, id string, request lp.Request, solution lp.Solution) (lp.EffectResult, error) {
	if e == nil || ctx == nil {
		return lp.EffectResult{}, ErrProfile
	}
	if err := ctx.Err(); err != nil {
		return lp.EffectResult{}, err
	}
	request.Action.Arguments = slices.Clone(request.Action.Arguments)
	solution.Grants, solution.Effective = slices.Clone(solution.Grants), slices.Clone(solution.Effective)
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline || !e.clock().Before(deadline) {
		return lp.EffectResult{}, lp.ErrExpired
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if !boundedID(id) || !boundedID(request.ActorID) || !boundedID(request.TaskID) || request.Action.Operation != Operation {
		return lp.EffectResult{}, lp.ErrBinding
	}
	var args Arguments
	if err := strictJSON(request.Action.Arguments, &args, 4096); err != nil {
		return lp.EffectResult{}, err
	}
	object, ok := e.profile.objects[request.Action.Resource]
	if !ok || args.ProfileDigest != e.profile.digest || args.ExpectedBucketOwner != object.OwnerAccount || !etagPattern.MatchString(args.IfMatch) || args.RangeStart < 0 || args.RangeEnd < args.RangeStart || args.RangeEnd-args.RangeStart >= e.profile.spec.MaxResponseBytes {
		return lp.EffectResult{}, lp.ErrBinding
	}
	if !slices.Contains(solution.Effective, object.ARN) {
		return lp.EffectResult{}, lp.ErrBinding
	}
	policy, err := e.profile.SessionPolicy(ctx, solution, e.config.MaxEvaluations)
	if err != nil {
		return lp.EffectResult{}, err
	}
	creds, err := e.assume(ctx, id, policy)
	if err != nil {
		return lp.EffectResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return lp.EffectResult{}, err
	}
	if !e.clock().Before(creds.Expiration) {
		return lp.EffectResult{}, lp.ErrExpired
	}
	bucket, key, _ := objectParts(object.ARN)
	endpoint := "https://" + bucket + ".s3." + e.profile.spec.Region + ".amazonaws.com/" + key
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return lp.EffectResult{}, ErrProfile
	}
	req.Header.Set("If-Match", args.IfMatch)
	req.Close = true
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", args.RangeStart, args.RangeEnd))
	req.Header.Set("X-Amz-Expected-Bucket-Owner", args.ExpectedBucketOwner)
	signRequest(req, creds, e.profile.spec.Region, e.clock())
	response, err := e.client.Do(req)
	if err != nil {
		return lp.EffectResult{}, ErrProvider
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusPreconditionFailed || response.StatusCode == http.StatusRequestedRangeNotSatisfiable {
		return evidence(id, request, solution, e.profile.digest, response.StatusCode, "", 0), nil
	}
	if response.StatusCode != http.StatusPartialContent || response.Header.Get("ETag") != args.IfMatch {
		return lp.EffectResult{}, ErrProvider
	}
	length := args.RangeEnd - args.RangeStart + 1
	if response.ContentLength != length || !validContentRange(response.Header.Get("Content-Range"), args.RangeStart, args.RangeEnd) {
		return lp.EffectResult{}, ErrProvider
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, length+1))
	if err != nil || int64(len(content)) != length {
		return lp.EffectResult{}, ErrProvider
	}
	hash := sha256.Sum256(content)
	clear(content)
	return evidence(id, request, solution, e.profile.digest, response.StatusCode, hex.EncodeToString(hash[:]), length), nil
}

func boundedID(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validContentRange(value string, start, end int64) bool {
	var observedStart, observedEnd, total int64
	_, err := fmt.Sscanf(value, "bytes %d-%d/%d", &observedStart, &observedEnd, &total)
	return err == nil && observedStart == start && observedEnd == end && total > end && value == fmt.Sprintf("bytes %d-%d/%d", start, end, total)
}

func evidence(id string, request lp.Request, solution lp.Solution, profile string, status int, content string, length int64) lp.EffectResult {
	// All fields are bounded, and this string-only map is always JSON encodable.
	action, _ := lp.DigestAction(request.Action)
	raw, err := json.Marshal(map[string]string{"schema": "asb.least-privilege.aws-receipt/v1", "operation_id": id, "actor": request.ActorID, "task": request.TaskID, "action_digest": action, "problem_digest": solution.ProblemDigest, "profile_digest": profile, "http_status": strconv.Itoa(status), "content_sha256": content, "bytes": strconv.FormatInt(length, 10)})
	if err != nil {
		return lp.EffectResult{}
	}
	hash := sha256.Sum256(raw)
	state := lp.ExecutionFailed
	if status == http.StatusPartialContent {
		state = lp.ExecutionSucceeded
	}
	return lp.EffectResult{State: state, EvidenceDigest: "sha256:" + hex.EncodeToString(hash[:])}
}
