// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package awsiam implements an explicit, finite S3 GetObject profile. It is not
// an interpreter for arbitrary AWS IAM policies or a cloud policy inventory.
package awsiam

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"slices"
	"strings"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
)

const (
	Schema        = "asb.least-privilege.aws-s3/v1"
	Operation     = "s3:GetObject"
	MaxInputBytes = 256 << 10
	MaxReadBytes  = 1 << 20
	policyVersion = "2012-10-17"
)

var (
	ErrProfile     = errors.New("unsupported or invalid finite AWS profile")
	ErrProvider    = errors.New("AWS provider operation failed")
	accountPattern = regexp.MustCompile(`^[0-9]{12}$`)
	regionPattern  = regexp.MustCompile(`^(us|eu|ap|sa|ca|me|af|il|mx)-(east|west|north|south|central|northeast|southeast)-[1-9]$`)
	rolePattern    = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,256}$`)
	profilePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	bucketPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	keyPattern     = regexp.MustCompile(`^[A-Za-z0-9._~/-]+$`)
	etagPattern    = regexp.MustCompile(`^"[A-Fa-f0-9]{32}(-[1-9][0-9]{0,5})?"$`)
)

type Object struct {
	ARN          string `json:"arn"`
	Cost         uint64 `json:"cost"`
	OwnerAccount string `json:"owner_account"`
}

type GrantPolicy struct {
	ID     string          `json:"id"`
	Policy json.RawMessage `json:"policy"`
}

// Specification is operator-supplied. Every input policy is an explicit grant
// choice, not an assertion that AWS currently grants those permissions.
type Specification struct {
	Schema            string        `json:"schema"`
	RoleARN           string        `json:"role_arn"`
	Region            string        `json:"region"`
	CredentialProfile string        `json:"credential_profile"`
	Objects           []Object      `json:"objects"`
	Grants            []GrantPolicy `json:"grants"`
	Required          []string      `json:"required"`
	Allowed           []string      `json:"allowed"`
	MaxResponseBytes  int64         `json:"max_response_bytes"`
}

type inputPolicy struct {
	Version   string           `json:"Version"`
	Statement []inputStatement `json:"Statement"`
}

// Narrow input syntax is intentional: scalar Action, array Resource/Statement.
type inputStatement struct {
	Sid      string   `json:"Sid,omitempty"`
	Effect   string   `json:"Effect"`
	Action   string   `json:"Action"`
	Resource []string `json:"Resource"`
}

type Profile struct {
	spec    Specification
	problem lp.Problem
	digest  string
	objects map[string]Object
}

// Compile rejects unsupported policy semantics, ambiguous JSON and wildcards.
// The digest binds every supported specification field, including execution
// role, region, source profile, owner, costs, limits and original grant policies.
func Compile(raw []byte) (*Profile, error) {
	var spec Specification
	if err := strictJSON(raw, &spec, MaxInputBytes); err != nil {
		return nil, err
	}
	if spec.Schema != Schema || !rolePattern.MatchString(spec.RoleARN) || !regionPattern.MatchString(spec.Region) || !profilePattern.MatchString(spec.CredentialProfile) || spec.MaxResponseBytes < 1 || spec.MaxResponseBytes > MaxReadBytes || len(spec.Objects) == 0 || len(spec.Objects) > lp.MaxPermissions || len(spec.Grants) == 0 || len(spec.Grants) > lp.MaxGrants {
		return nil, ErrProfile
	}
	p := &Profile{spec: spec, problem: lp.Problem{Schema: lp.ProblemSchemaV1, Required: slices.Clone(spec.Required), Allowed: slices.Clone(spec.Allowed)}, objects: make(map[string]Object, len(spec.Objects))}
	for _, object := range spec.Objects {
		if _, _, ok := objectParts(object.ARN); !ok || !accountPattern.MatchString(object.OwnerAccount) {
			return nil, ErrProfile
		}
		if _, exists := p.objects[object.ARN]; exists {
			return nil, ErrProfile
		}
		p.objects[object.ARN] = object
		p.problem.Permissions = append(p.problem.Permissions, lp.Permission{ID: object.ARN, Cost: object.Cost})
	}
	for _, grant := range spec.Grants {
		var policy inputPolicy
		if err := strictJSON(grant.Policy, &policy, MaxInputBytes); err != nil {
			return nil, err
		}
		if policy.Version != policyVersion || len(policy.Statement) == 0 || len(policy.Statement) > 32 {
			return nil, ErrProfile
		}
		g := lp.Grant{ID: grant.ID}
		seen := make(map[string]bool)
		for _, statement := range policy.Statement {
			if statement.Effect != "Allow" || statement.Action != Operation || len(statement.Resource) == 0 || len(statement.Resource) > lp.MaxPermissions || len(statement.Sid) > 128 {
				return nil, ErrProfile
			}
			for _, arn := range statement.Resource {
				if _, known := p.objects[arn]; !known || seen[arn] {
					return nil, ErrProfile
				}
				seen[arn] = true
				g.Permissions = append(g.Permissions, arn)
			}
		}
		p.problem.Grants = append(p.problem.Grants, g)
	}
	if _, err := lp.DigestProblem(p.problem); err != nil {
		return nil, err
	}
	normalized, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(normalized)
	p.digest = "sha256:" + hex.EncodeToString(hash[:])
	return p, nil
}

func (p *Profile) Digest() string {
	if p == nil {
		return ""
	}
	return p.digest
}

func (p *Profile) Problem() lp.Problem {
	if p == nil {
		return lp.Problem{}
	}
	out := p.problem
	out.Permissions = slices.Clone(out.Permissions)
	out.Required = slices.Clone(out.Required)
	out.Allowed = slices.Clone(out.Allowed)
	out.Grants = slices.Clone(out.Grants)
	for i := range out.Grants {
		out.Grants[i].Permissions = slices.Clone(out.Grants[i].Permissions)
	}
	return out
}

// Arguments are part of the exact ASB/mandate action. A strong ETag precondition
// and one explicit bounded range are mandatory; versioned reads are unsupported.
type Arguments struct {
	ProfileDigest       string `json:"profile_digest"`
	ExpectedBucketOwner string `json:"expected_bucket_owner"`
	IfMatch             string `json:"if_match"`
	RangeStart          int64  `json:"range_start"`
	RangeEnd            int64  `json:"range_end"`
}

func objectParts(arn string) (string, string, bool) {
	if len(arn) > lp.MaxIDBytes || !strings.HasPrefix(arn, "arn:aws:s3:::") {
		return "", "", false
	}
	bucket, key, found := strings.Cut(strings.TrimPrefix(arn, "arn:aws:s3:::"), "/")
	if !found || !bucketPattern.MatchString(bucket) || strings.Contains(bucket, "--") || strings.HasSuffix(bucket, "-s3alias") || !keyPattern.MatchString(key) || strings.HasSuffix(key, "/") {
		return "", "", false
	}
	for _, part := range strings.Split(key, "/") {
		if part == "" || part == "." || part == ".." {
			return "", "", false
		}
	}
	return bucket, key, true
}

func strictJSON(raw []byte, target any, limit int) error {
	if len(raw) == 0 || len(raw) > limit {
		return ErrProfile
	}
	if err := uniqueKeys(json.NewDecoder(bytes.NewReader(raw)), 0); err != nil {
		return ErrProfile
	}
	if err := exactKeys(raw, reflect.TypeOf(target).Elem()); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrProfile
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrProfile
	}
	return nil
}

// encoding/json accepts case-insensitive aliases; this profile does not.
func exactKeys(raw []byte, t reflect.Type) error {
	if t == reflect.TypeFor[json.RawMessage]() {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || object == nil {
			return ErrProfile
		}
		fields := make(map[string]reflect.Type, t.NumField())
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			fields[name] = f.Type
		}
		for name, value := range object {
			field, ok := fields[name]
			if !ok {
				return ErrProfile
			}
			if err := exactKeys(value, field); err != nil {
				return err
			}
		}
	case reflect.Slice:
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return ErrProfile
		}
		for _, value := range values {
			if err := exactKeys(value, t.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func uniqueKeys(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrProfile
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok || seen[key] {
				return ErrProfile
			}
			seen[key] = true
			if err := uniqueKeys(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := uniqueKeys(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return ErrProfile
	}
	_, err = decoder.Token()
	return err
}
