// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	HumanMatchConsentSchemaV1                  = "asb.human-match-consent/v1"
	HumanMatchConsentRevocationSchemaV1        = "asb.human-match-consent-revocation/v1"
	HumanReachabilityGrantSchemaV1             = "asb.human-reachability-grant/v1"
	HumanReachabilityRevocationSchemaV1        = "asb.human-reachability-revocation/v1"
	MaxHumanMatchResults                uint32 = 20
)

// ReachabilityChannel identifies a brokered channel. It never contains the
// underlying Email address, social account, or telephone number.
type ReachabilityChannel string

const (
	ReachabilityEmail ReachabilityChannel = "EMAIL"
	ReachabilitySNS   ReachabilityChannel = "SNS"
	ReachabilityTEL   ReachabilityChannel = "TEL"
)

// HumanMatchConsent is an internal, immutable opt-in record scoped to one
// requester, purpose, capability, and relay channel. CandidateID must be an
// opaque pairwise identifier and must not equal either Participant identifier.
type HumanMatchConsent struct {
	Schema                 string              `json:"schema"`
	ConsentID              string              `json:"consent_id"`
	HumanParticipantID     string              `json:"human_participant_id"`
	CandidateID            string              `json:"candidate_id"`
	RequesterParticipantID string              `json:"requester_participant_id"`
	Purpose                string              `json:"purpose"`
	Capability             string              `json:"capability"`
	Channel                ReachabilityChannel `json:"channel"`
	ContactRequestRef      string              `json:"contact_request_ref"`
	ActorID                string              `json:"actor_id"`
	AuthorizationID        string              `json:"authorization_id"`
	ProofID                string              `json:"proof_id"`
	GrantedAt              time.Time           `json:"granted_at"`
	ExpiresAt              time.Time           `json:"expires_at"`
}

// HumanMatchQuery is intentionally exact and requester-bound. Limit is
// mandatory and bounded to reduce bulk enumeration.
type HumanMatchQuery struct {
	RequesterParticipantID string
	Purpose                string
	Capability             string
	Channel                ReachabilityChannel
	Limit                  uint32
}

// AuthenticatedHumanMatchQuery is a fresh verifier projection for one exact
// Human matching request. The authorization component must bind the complete
// nested query before this value reaches the directory.
type AuthenticatedHumanMatchQuery struct {
	Query           HumanMatchQuery
	ActorID         string
	AuthorizationID string
	ProofID         string
	VerifierNonce   string
	IssuedAt        time.Time
	ExpiresAt       time.Time
}

// HumanMatchCandidate is the only Human matching projection returned to a
// requester. It deliberately omits HumanParticipantID and all direct contacts.
type HumanMatchCandidate struct {
	CandidateID       string              `json:"candidate_id"`
	Capability        string              `json:"capability"`
	Channel           ReachabilityChannel `json:"channel"`
	ContactRequestRef string              `json:"contact_request_ref"`
	ExpiresAt         time.Time           `json:"expires_at"`
}

// HumanMatchConsentRevocation is an immutable withdrawal of matching consent.
type HumanMatchConsentRevocation struct {
	Schema             string    `json:"schema"`
	EventID            string    `json:"event_id"`
	ConsentID          string    `json:"consent_id"`
	HumanParticipantID string    `json:"human_participant_id"`
	ActorID            string    `json:"actor_id"`
	AuthorizationID    string    `json:"authorization_id"`
	ProofID            string    `json:"proof_id"`
	At                 time.Time `json:"at"`
}

// HumanReachabilityGrantDefinition is submitted by a relay after Human
// approval. ConsentID and ApprovedByParticipantID remain broker-internal and
// are not present in the requester-facing grant.
type HumanReachabilityGrantDefinition struct {
	GrantID                 string
	ConsentID               string
	ApprovedByParticipantID string
	CandidateID             string
	RequesterParticipantID  string
	Purpose                 string
	Capability              string
	Channel                 ReachabilityChannel
	RelaySessionRef         string
	IssuedAt                time.Time
	ExpiresAt               time.Time
	ApprovalActorID         string
	ApprovalAuthorizationID string
	ApprovalProofID         string
}

// HumanReachabilityGrant is a purpose-, requester-, channel-, and time-bound
// relay capability. It contains neither the Human identifier nor a direct
// Email, SNS, or telephone endpoint.
type HumanReachabilityGrant struct {
	Schema                 string              `json:"schema"`
	GrantID                string              `json:"grant_id"`
	CandidateID            string              `json:"candidate_id"`
	RequesterParticipantID string              `json:"requester_participant_id"`
	Purpose                string              `json:"purpose"`
	Capability             string              `json:"capability"`
	Channel                ReachabilityChannel `json:"channel"`
	RelaySessionRef        string              `json:"relay_session_ref"`
	IssuedAt               time.Time           `json:"issued_at"`
	ExpiresAt              time.Time           `json:"expires_at"`
}

// AuthenticatedReachabilityAccess is a fresh verifier projection for loading
// one requester-bound relay grant.
type AuthenticatedReachabilityAccess struct {
	GrantID                string
	RequesterParticipantID string
	Purpose                string
	Capability             string
	Channel                ReachabilityChannel
	ActorID                string
	AuthorizationID        string
	ProofID                string
	VerifierNonce          string
	IssuedAt               time.Time
	ExpiresAt              time.Time
}

// HumanReachabilityRevocation revokes a relay grant. ParticipantID may be the
// consenting Human or the requester; the directory verifies that relationship.
type HumanReachabilityRevocation struct {
	Schema          string    `json:"schema"`
	EventID         string    `json:"event_id"`
	GrantID         string    `json:"grant_id"`
	ParticipantID   string    `json:"participant_id"`
	ActorID         string    `json:"actor_id"`
	AuthorizationID string    `json:"authorization_id"`
	ProofID         string    `json:"proof_id"`
	At              time.Time `json:"at"`
}

// Validate checks an internal Human matching consent record.
func (c HumanMatchConsent) Validate() error {
	if c.Schema != HumanMatchConsentSchemaV1 {
		return invalidReachability("unsupported Human match consent schema")
	}
	for field, value := range map[string]string{
		"consent_id":               c.ConsentID,
		"human_participant_id":     c.HumanParticipantID,
		"candidate_id":             c.CandidateID,
		"requester_participant_id": c.RequesterParticipantID,
		"purpose":                  c.Purpose,
		"capability":               c.Capability,
		"actor_id":                 c.ActorID,
		"authorization_id":         c.AuthorizationID,
		"proof_id":                 c.ProofID,
	} {
		if err := validateID(field, value); err != nil {
			return invalidReachabilityError(err)
		}
	}
	if c.HumanParticipantID == c.RequesterParticipantID {
		return invalidReachability("Human and requester must differ")
	}
	if c.CandidateID == c.HumanParticipantID || c.CandidateID == c.RequesterParticipantID {
		return invalidReachability("candidate_id must be opaque and pairwise")
	}
	if !validReachabilityChannel(c.Channel) {
		return invalidReachability("unsupported relay channel")
	}
	if err := validateHTTPSReference("contact_request_ref", c.ContactRequestRef); err != nil {
		return invalidReachabilityError(err)
	}
	if c.GrantedAt.IsZero() || c.ExpiresAt.IsZero() || !c.ExpiresAt.After(c.GrantedAt) {
		return invalidReachability("invalid consent validity window")
	}
	return nil
}

// Validate checks an exact, bounded Human matching query.
func (q HumanMatchQuery) Validate() error {
	for field, value := range map[string]string{
		"requester_participant_id": q.RequesterParticipantID,
		"purpose":                  q.Purpose,
		"capability":               q.Capability,
	} {
		if err := validateID(field, value); err != nil {
			return invalidReachabilityError(err)
		}
		if strings.ContainsAny(value, "*?") {
			return invalidReachability(field + " must not contain wildcard characters")
		}
	}
	if !validReachabilityChannel(q.Channel) {
		return invalidReachability("unsupported relay channel")
	}
	if q.Limit == 0 || q.Limit > MaxHumanMatchResults {
		return invalidReachability("query limit is outside the allowed range")
	}
	return nil
}

// Validate checks the structural and freshness bindings of an authenticated
// Human matching request. Cryptographic verification remains external.
func (q AuthenticatedHumanMatchQuery) Validate() error {
	if err := q.Query.Validate(); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"actor_id":         q.ActorID,
		"authorization_id": q.AuthorizationID,
		"proof_id":         q.ProofID,
		"verifier_nonce":   q.VerifierNonce,
	} {
		if err := validateID(field, value); err != nil {
			return invalidReachabilityError(err)
		}
	}
	if q.IssuedAt.IsZero() || q.ExpiresAt.IsZero() || !q.ExpiresAt.After(q.IssuedAt) {
		return invalidReachability("invalid match request validity window")
	}
	return nil
}

// Validate checks a privacy-minimized Human match result.
func (c HumanMatchCandidate) Validate() error {
	if err := validateID("candidate_id", c.CandidateID); err != nil {
		return invalidReachabilityError(err)
	}
	if err := validateID("capability", c.Capability); err != nil {
		return invalidReachabilityError(err)
	}
	if !validReachabilityChannel(c.Channel) {
		return invalidReachability("unsupported relay channel")
	}
	if err := validateHTTPSReference("contact_request_ref", c.ContactRequestRef); err != nil {
		return invalidReachabilityError(err)
	}
	if c.ExpiresAt.IsZero() {
		return invalidReachability("candidate expiry is required")
	}
	return nil
}

// Validate checks an immutable Human matching consent revocation.
func (r HumanMatchConsentRevocation) Validate() error {
	if r.Schema != HumanMatchConsentRevocationSchemaV1 {
		return invalidReachability("unsupported consent revocation schema")
	}
	for field, value := range map[string]string{
		"event_id":             r.EventID,
		"consent_id":           r.ConsentID,
		"human_participant_id": r.HumanParticipantID,
		"actor_id":             r.ActorID,
		"authorization_id":     r.AuthorizationID,
		"proof_id":             r.ProofID,
	} {
		if err := validateID(field, value); err != nil {
			return invalidReachabilityError(err)
		}
	}
	if r.At.IsZero() {
		return invalidReachability("revocation time is required")
	}
	return nil
}

// Validate checks a requester-facing relay grant.
func (g HumanReachabilityGrant) Validate() error {
	if g.Schema != HumanReachabilityGrantSchemaV1 {
		return invalidReachability("unsupported reachability grant schema")
	}
	for field, value := range map[string]string{
		"grant_id":                 g.GrantID,
		"candidate_id":             g.CandidateID,
		"requester_participant_id": g.RequesterParticipantID,
		"purpose":                  g.Purpose,
		"capability":               g.Capability,
	} {
		if err := validateID(field, value); err != nil {
			return invalidReachabilityError(err)
		}
	}
	if !validReachabilityChannel(g.Channel) {
		return invalidReachability("unsupported relay channel")
	}
	if err := validateHTTPSReference("relay_session_ref", g.RelaySessionRef); err != nil {
		return invalidReachabilityError(err)
	}
	if g.IssuedAt.IsZero() || g.ExpiresAt.IsZero() || !g.ExpiresAt.After(g.IssuedAt) {
		return invalidReachability("invalid grant validity window")
	}
	return nil
}

// Validate checks an exact authenticated request to load one relay grant.
// Cryptographic verification remains external.
func (a AuthenticatedReachabilityAccess) Validate() error {
	for field, value := range map[string]string{
		"grant_id":                 a.GrantID,
		"requester_participant_id": a.RequesterParticipantID,
		"purpose":                  a.Purpose,
		"capability":               a.Capability,
		"actor_id":                 a.ActorID,
		"authorization_id":         a.AuthorizationID,
		"proof_id":                 a.ProofID,
		"verifier_nonce":           a.VerifierNonce,
	} {
		if err := validateID(field, value); err != nil {
			return invalidReachabilityError(err)
		}
	}
	if strings.ContainsAny(a.Purpose, "*?") || strings.ContainsAny(a.Capability, "*?") {
		return invalidReachability("grant access scope must not contain wildcard characters")
	}
	if !validReachabilityChannel(a.Channel) {
		return invalidReachability("unsupported relay channel")
	}
	if a.IssuedAt.IsZero() || a.ExpiresAt.IsZero() || !a.ExpiresAt.After(a.IssuedAt) {
		return invalidReachability("invalid grant access validity window")
	}
	return nil
}

// Validate checks an immutable reachability grant revocation.
func (r HumanReachabilityRevocation) Validate() error {
	if r.Schema != HumanReachabilityRevocationSchemaV1 {
		return invalidReachability("unsupported reachability revocation schema")
	}
	for field, value := range map[string]string{
		"event_id":         r.EventID,
		"grant_id":         r.GrantID,
		"participant_id":   r.ParticipantID,
		"actor_id":         r.ActorID,
		"authorization_id": r.AuthorizationID,
		"proof_id":         r.ProofID,
	} {
		if err := validateID(field, value); err != nil {
			return invalidReachabilityError(err)
		}
	}
	if r.At.IsZero() {
		return invalidReachability("revocation time is required")
	}
	return nil
}

func validReachabilityChannel(channel ReachabilityChannel) bool {
	return channel == ReachabilityEmail || channel == ReachabilitySNS || channel == ReachabilityTEL
}

func validateHTTPSReference(field, value string) error {
	if err := validateReference(field, value); err != nil {
		return err
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("%s must be an absolute HTTPS relay reference", field)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%s must not contain userinfo, query, or fragment data", field)
	}
	return nil
}

func isDirectContactReference(value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "mailto", "tel", "sms", "sip", "sips":
		return true
	default:
		return false
	}
}

func isPublicOrDirectContactReference(value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	if isDirectContactReference(value) {
		return true
	}
	return parsed.Scheme == "http" || parsed.Scheme == "https"
}

func invalidReachability(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidReachability, message)
}

func invalidReachabilityError(err error) error {
	return fmt.Errorf("%w: %v", ErrInvalidReachability, err)
}
