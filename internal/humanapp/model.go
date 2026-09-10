// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package humanapp is an experimental, single-host approval application. It
// does not implement the generic TaskCoord production storage contract.
package humanapp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	protectedchange "github.com/ToppyMicroServices/agents-secure-binding/v2/examples/protected-change-consumer"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/strictjson"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/production"
)

const (
	ActorAgent       = "agent:local-proposer"
	ActorGateway     = "gateway:local-human"
	HumanParticipant = "human:local-owner"
	Assurance        = "gateway-asserted-for-human"
	KindPropose      = "PROPOSE"
	KindApprove      = "APPROVE"
	KindDecline      = "DECLINE"
	KindStatus       = "STATUS"
	KindInbox        = "INBOX"
	StatePending     = "PENDING_REVIEW"
	StateApplied     = "APPLIED"
	StateDenied      = "DENIED"
	StateStale       = "STALE"
	Tenant           = "local"
	SettingName      = "maintenance_mode"
	ChallengePath    = "/v1/challenge"
	CommandPath      = "/v1/commands"
	MaxRequestBytes  = 16 << 10
)

var (
	ErrInvalid        = errors.New("invalid request")
	ErrConflict       = errors.New("operation conflict")
	ErrNotFound       = errors.New("operation not found")
	ErrUnauthorized   = errors.New("authentication or authorization failed")
	ErrUnavailable    = errors.New("outcome unknown; inspect before retrying")
	identifierPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Command is an application-local protocol, not a stable ASB wire extension.
// Mutation CommandIDs identify an immutable result. STATUS and INBOX are live
// reads and must use fresh authentication; they do not freeze a past view.
type Command struct {
	CommandID        string                         `json:"command_id"`
	Kind             string                         `json:"kind"`
	OperationID      string                         `json:"operation_id,omitempty"`
	Change           *protectedchange.ChangeRequest `json:"change,omitempty"`
	ExpectedRevision uint64                         `json:"expected_revision"`
	ProposalDigest   string                         `json:"proposal_digest,omitempty"`
}

type Setting struct {
	Tenant   string `json:"tenant"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	Revision uint64 `json:"revision"`
}

type Operation struct {
	OperationID      string                        `json:"operation_id"`
	ProposalDigest   string                        `json:"proposal_digest"`
	Change           protectedchange.ChangeRequest `json:"change"`
	Before           Setting                       `json:"before"`
	State            string                        `json:"state"`
	Proposer         string                        `json:"proposer"`
	Reviewer         string                        `json:"reviewer,omitempty"`
	HumanParticipant string                        `json:"human_participant,omitempty"`
	Assurance        string                        `json:"assurance,omitempty"`
	CreatedAt        time.Time                     `json:"created_at"`
	DecidedAt        *time.Time                    `json:"decided_at,omitempty"`
	After            *Setting                      `json:"after,omitempty"`
}

type Response struct {
	CommandID  string        `json:"command_id"`
	Operation  *Operation    `json:"operation,omitempty"`
	Operations []Operation   `json:"operations,omitempty"`
	Setting    *Setting      `json:"setting,omitempty"`
	Inbox      *InboxSummary `json:"inbox,omitempty"`
}

// InboxSummary distinguishes the whole queue from its bounded display window.
// Pending operations take priority, oldest first, so newer history cannot hide
// work still awaiting review. These fields are local application metadata.
type InboxSummary struct {
	Pending int `json:"pending"`
	Total   int `json:"total"`
	Limit   int `json:"limit"`
}

// Authenticator must verify fresh, exact ASB evidence using the supplied
// transaction-local replay cache. Its accepted identity is never peer input.
type Authenticator func(identitypolicy.ReplayCache) (production.AcceptedIdentity, error)

func (c Command) Validate() error {
	if !identifierPattern.MatchString(c.CommandID) {
		return ErrInvalid
	}
	if c.Kind == KindInbox {
		if c.OperationID != "" || c.Change != nil || c.ExpectedRevision != 0 || c.ProposalDigest != "" {
			return ErrInvalid
		}
		return nil
	}
	if !identifierPattern.MatchString(c.OperationID) {
		return ErrInvalid
	}
	switch c.Kind {
	case KindPropose:
		if c.Change == nil || c.Change.ChangeID != c.OperationID || c.Change.Tenant != Tenant || c.Change.Setting != SettingName || c.ProposalDigest != "" {
			return ErrInvalid
		}
		if _, err := protectedchange.CanonicalActionContext(*c.Change); err != nil {
			return ErrInvalid
		}
	case KindApprove, KindDecline:
		if c.Change != nil || !digestPattern.MatchString(c.ProposalDigest) {
			return ErrInvalid
		}
	case KindStatus:
		if c.Change != nil || !digestPattern.MatchString(c.ProposalDigest) || c.ExpectedRevision != 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	// Keep SQLite integers and JavaScript's exact-integer display aligned.
	if c.ExpectedRevision > (1<<53)-1 {
		return ErrInvalid
	}
	return nil
}

func (c Command) Mutation() bool {
	return c.Kind == KindPropose || c.Kind == KindApprove || c.Kind == KindDecline
}

func ActorAllowed(actor, kind string) bool {
	switch actor {
	case ActorAgent:
		return kind == KindPropose || kind == KindStatus || kind == KindInbox
	case ActorGateway:
		return kind == KindApprove || kind == KindDecline || kind == KindStatus || kind == KindInbox
	default:
		return false
	}
}

func CommandContext(c Command) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	var changeContext json.RawMessage
	if c.Change != nil {
		var err error
		changeContext, err = protectedchange.CanonicalActionContext(*c.Change)
		if err != nil {
			return nil, err
		}
	}
	return json.Marshal(struct {
		Profile       string          `json:"profile"`
		Method        string          `json:"method"`
		Resource      string          `json:"resource"`
		Command       Command         `json:"command"`
		ChangeContext json.RawMessage `json:"change_context,omitempty"`
	}{"asb.local-human-change/v1", "POST", CommandPath, c, changeContext})
}

func CommandDigest(c Command) (string, error) {
	raw, err := CommandContext(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func CommandPolicy(c Command, actor string) identitypolicy.Policy {
	taskID := c.OperationID
	if taskID == "" {
		taskID = "local-inbox"
	}
	return identitypolicy.Policy{
		Mode: identitypolicy.ModeRequired, SetMode: identitypolicy.SetModeExact,
		Require: identitypolicy.Requirements{L3: true, L4: true, L5: true, L6: true},
		Expected: identitypolicy.Values{
			Service: "human-approval", Agent: actor, TaskID: taskID,
			IntentRef: "humanapp:intent:" + strings.ToLower(c.Kind), CapabilityRef: "humanapp:capability:" + strings.ToLower(c.Kind),
			Scopes: []string{"humanapp." + strings.ToLower(c.Kind)}, Resources: []string{"humanapp://local/" + taskID},
			AuthorizationDetails: []string{"humanapp:" + c.Kind},
		},
	}
}

func decodeJSON(r io.Reader, out any) error {
	raw, err := strictjson.ReadDocument(r, MaxRequestBytes)
	if err != nil {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return ErrInvalid
	}
	// encoding/json accepts case-insensitive struct names. Require the exact
	// emitted field spellings as well as duplicate-safe input.
	canonical, err := json.Marshal(out)
	if err != nil {
		return ErrInvalid
	}
	var original, expected any
	if json.Unmarshal(raw, &original) != nil || json.Unmarshal(canonical, &expected) != nil {
		return ErrInvalid
	}
	if !exactFieldNames(original, expected) {
		return fmt.Errorf("%w: field name", ErrInvalid)
	}
	return nil
}

func exactFieldNames(original, expected any) bool {
	switch value := original.(type) {
	case map[string]any:
		expectedMap, ok := expected.(map[string]any)
		if !ok {
			return false
		}
		for key, child := range value {
			expectedChild, ok := expectedMap[key]
			if !ok || !exactFieldNames(child, expectedChild) {
				return false
			}
		}
	case []any:
		expectedSlice, ok := expected.([]any)
		if !ok || len(value) != len(expectedSlice) {
			return false
		}
		for i := range value {
			if !exactFieldNames(value[i], expectedSlice[i]) {
				return false
			}
		}
	}
	return true
}
