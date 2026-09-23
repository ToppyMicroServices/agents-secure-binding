// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/schemas"
)

const (
	IngressChallengePath = "/v1/human-operations/challenge"
	IngressExecutePath   = "/v1/human-operations/execute"
	IngressRecoverPath   = "/v1/human-operations/recover"

	OperationAssignmentOffer      = "ASSIGNMENT_OFFER"
	OperationAssignmentTransition = "ASSIGNMENT_TRANSITION"
	OperationAssignmentDelegation = "ASSIGNMENT_DELEGATION"
	OperationInteractionAppend    = "INTERACTION_APPEND"
	OperationRecover              = "OPERATION_RECOVER"

	challengeBytes         = 32
	challengeAttempts      = 3
	defaultMaxPending      = 8
	defaultMaxTotalPending = 256
)

var (
	ErrTLSRequired              = errors.New("asbbinding ingress: verified TLS 1.3 client connection required")
	ErrMissingStore             = errors.New("asbbinding ingress: missing TaskCoord store")
	ErrMissingReplayCache       = errors.New("asbbinding ingress: missing shared replay cache")
	ErrMissingVerifierPolicy    = errors.New("asbbinding ingress: missing verifier policy")
	ErrUnsupportedOperationKind = errors.New("asbbinding ingress: unsupported operation kind")
	ErrUnknownChallenge         = errors.New("asbbinding ingress: unknown or expired challenge")
	ErrChallengeConnection      = errors.New("asbbinding ingress: challenge belongs to another TLS connection")
	ErrChallengeRequest         = errors.New("asbbinding ingress: challenge does not match request")
	ErrChallengeLimit           = errors.New("asbbinding ingress: too many outstanding challenges")
	ErrInvalidChallengeLimits   = errors.New("asbbinding ingress: invalid challenge limits")
	errOperationAuthorization   = errors.New("asbbinding ingress: operation authorization failed")
	errChallengeCollision       = errors.New("asbbinding ingress: challenge identifier collision")
)

// IngressPolicy is verifier-controlled configuration. No field is read from
// the HTTP request.
type IngressPolicy struct {
	Grant          clients.JWTVerifyOptions
	SessionBinding clients.JWTVerifyOptions
	Identity       identitypolicy.Policy
	ReplayCache    identitypolicy.ReplayCache
	// AcceptedUntil may narrow the lifetime of an already verified exact-request
	// ASB proof. Ingress invokes it only after cryptographic proof acceptance and
	// never returns callback errors to the peer.
	AcceptedUntil func(context.Context, RequestKind, Digest) (time.Time, error)
	// DelegationVerifier is required only for ASSIGNMENT_DELEGATION. It is
	// invoked after the exact ASB grant/session proof has been accepted.
	DelegationVerifier DelegationDecisionVerifier
}

// Ingress is the single external boundary for Human TaskCoord operations. It
// terminates TLS, derives the channel binding, verifies the exact-request proof
// before loading Assignment state, and commits through Store CAS.
type Ingress struct {
	Store        taskcoord.Store
	Policy       IngressPolicy
	Now          func() time.Time
	ChallengeTTL time.Duration
	// MaxPending bounds outstanding challenges for both one TLS connection and
	// one verified client public key. Zero selects a finite default.
	MaxPending int
	// MaxTotalPending bounds all outstanding challenges in this verifier,
	// including challenges created through different TLS connections. Zero
	// selects a finite default.
	MaxTotalPending int
	Random          io.Reader
	// RequestIDGenerator may supply server-controlled correlation identifiers
	// for tests or platform integration. It must be safe for concurrent use.
	// Invalid values are ignored and replaced with a generated identifier.
	RequestIDGenerator func() string

	mu          sync.Mutex
	pending     map[string]pendingChallenge
	connections map[string]int
	identities  map[string]int
}

type pendingChallenge struct {
	connectionKey   string
	requestKind     RequestKind
	digest          Digest
	expiresAt       time.Time
	expectedBinding identitypolicy.Binding
}

type ChallengeRequest struct {
	Operation string          `json:"operation"`
	Request   json.RawMessage `json:"request"`
}

type ChallengeResponse struct {
	ChallengeID   string `json:"challenge_id"`
	Nonce         string `json:"nonce"`
	ExpiresAt     string `json:"expires_at"`
	RequestDigest string `json:"request_digest"`
}

type ExecuteRequest struct {
	ChallengeID       string          `json:"challenge_id"`
	Operation         string          `json:"operation"`
	Request           json.RawMessage `json:"request"`
	GrantJWT          string          `json:"grant_jwt"`
	SessionBindingJWT string          `json:"session_binding_jwt"`
}

type ExecuteResponse struct {
	Operation        string                      `json:"operation"`
	Assignment       *taskcoord.Assignment       `json:"assignment,omitempty"`
	Record           *taskcoord.TransitionRecord `json:"record,omitempty"`
	ParentAssignment *taskcoord.Assignment       `json:"parent_assignment,omitempty"`
	ParentRecord     *taskcoord.TransitionRecord `json:"parent_record,omitempty"`
	ChildAssignment  *taskcoord.Assignment       `json:"child_assignment,omitempty"`
	ChildRecord      *taskcoord.TransitionRecord `json:"child_record,omitempty"`
	Delegation       *taskcoord.DelegationRecord `json:"delegation,omitempty"`
	Interaction      *taskcoord.InteractionEvent `json:"interaction,omitempty"`
}

type operationEnvelope struct {
	kind        RequestKind
	digest      Digest
	offer       *OfferRequest
	transition  *TransitionRequest
	delegation  *DelegationRequest
	interaction *InteractionRequest
	recovery    *RecoveryRequest
}

// Handler returns a no-store HTTP API. The enclosing http.Server must use a
// TLSConfig that verifies client certificates.
func (s *Ingress) Handler() (http.Handler, error) {
	if isNilDependency(s.Store) {
		return nil, ErrMissingStore
	}
	if _, durable := s.Store.(HumanTransactionStore); !durable && isNilDependency(s.Policy.ReplayCache) {
		return nil, ErrMissingReplayCache
	}
	if strings.TrimSpace(s.Policy.Grant.ExpectedIssuer) == "" ||
		strings.TrimSpace(s.Policy.Grant.ExpectedAudience) == "" ||
		strings.TrimSpace(s.Policy.SessionBinding.ExpectedIssuer) == "" ||
		strings.TrimSpace(s.Policy.SessionBinding.ExpectedAudience) == "" ||
		s.Policy.Grant.ExpectedAudience != s.Policy.SessionBinding.ExpectedAudience {
		return nil, ErrMissingVerifierPolicy
	}
	if err := clients.ValidateJWTVerifyOptions(s.Policy.Grant); err != nil {
		return nil, fmt.Errorf("asbbinding ingress: invalid grant verifier: %w", err)
	}
	if err := clients.ValidateJWTVerifyOptions(s.Policy.SessionBinding); err != nil {
		return nil, fmt.Errorf("asbbinding ingress: invalid session verifier: %w", err)
	}
	if err := s.Policy.Identity.ValidateMode(); err != nil {
		return nil, fmt.Errorf("asbbinding ingress: invalid identity policy: %w", err)
	}
	if s.Policy.Identity.Mode == identitypolicy.ModeDisabled ||
		s.Policy.Identity.SetMode == identitypolicy.SetModeContainsAll ||
		len(s.Policy.Identity.Expected.AuthorizationDetails) != 0 {
		return nil, ErrMissingVerifierPolicy
	}
	if s.MaxPending < 0 || s.MaxTotalPending < 0 {
		return nil, ErrInvalidChallengeLimits
	}
	if err := schemas.PrepareHumanIngressValidator(); err != nil {
		return nil, fmt.Errorf("asbbinding ingress: prepare JSON validator: %w", err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setIngressResponseHeaders(w)
		w.Header().Set(IngressRequestIDHeader, s.newRequestID())
		switch r.URL.Path {
		case IngressChallengePath:
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", http.MethodPost)
				s.writeIngressError(w, IngressCodeMethodNotAllowed)
				return
			}
			s.handleChallenge(w, r)
		case IngressExecutePath, IngressRecoverPath:
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", http.MethodPost)
				s.writeIngressError(w, IngressCodeMethodNotAllowed)
				return
			}
			s.handleExecute(w, r)
		default:
			s.writeIngressError(w, IngressCodeNotFound)
		}
	}), nil
}

func (s *Ingress) handleChallenge(w http.ResponseWriter, r *http.Request) {
	state, leaf, err := verifiedTLSState(r)
	if err != nil {
		s.writeIngressError(w, IngressCodeAuthenticationRequired)
		return
	}
	if !acceptsIngressJSON(r) {
		s.writeIngressError(w, IngressCodeUnsupportedMediaType)
		return
	}
	var input ChallengeRequest
	if err := decodeIngressEnvelope(r.Body, &input, schemas.ValidateHumanIngressChallengeJSON); err != nil {
		s.writeIngressError(w, IngressCodeInvalidRequest)
		return
	}
	operation, err := decodeOperation(input.Operation, input.Request)
	if err != nil {
		s.writeIngressError(w, IngressCodeInvalidRequest)
		return
	}
	if operation.kind == RequestKindOperationRecover {
		if _, ok := s.Store.(HumanTransactionStore); !ok {
			s.writeIngressError(w, IngressCodeOperationRejected)
			return
		}
	}
	if operation.kind == RequestKindAssignmentDelegation && isNilDelegationVerifier(s.Policy.DelegationVerifier) {
		s.writeIngressError(w, IngressCodeOperationRejected)
		return
	}
	now := s.currentTime()
	var challengeID, nonce string
	var entry pendingChallenge
	for attempt := 0; attempt < challengeAttempts; attempt++ {
		challengeID, nonce, err = s.randomChallengeValues()
		if err != nil {
			s.writeIngressError(w, IngressCodeInternalError)
			return
		}
		binding, bindingErr := BindingFromTLS(state, leaf, operation.digest, nonce)
		if bindingErr != nil {
			s.writeIngressError(w, IngressCodeAuthenticationRequired)
			return
		}
		entry = pendingChallenge{
			connectionKey: connectionKey(state), requestKind: operation.kind,
			digest: operation.digest, expiresAt: now.Add(s.challengeTTL()),
			expectedBinding: binding,
		}
		err = s.putChallenge(challengeID, entry, now)
		if err == nil {
			break
		}
		if !errors.Is(err, errChallengeCollision) {
			s.writeIngressError(w, ingressCodeForError(err))
			return
		}
	}
	if err != nil {
		s.writeIngressError(w, IngressCodeInternalError)
		return
	}
	writeIngressJSON(w, http.StatusCreated, ChallengeResponse{
		ChallengeID: challengeID, Nonce: nonce, ExpiresAt: entry.expiresAt.Format(time.RFC3339Nano),
		RequestDigest: operation.digest.String(),
	})
}

func (s *Ingress) handleExecute(w http.ResponseWriter, r *http.Request) {
	state, _, err := verifiedTLSState(r)
	if err != nil {
		s.writeIngressError(w, IngressCodeAuthenticationRequired)
		return
	}
	if !acceptsIngressJSON(r) {
		s.writeIngressError(w, IngressCodeUnsupportedMediaType)
		return
	}
	var input ExecuteRequest
	validator := schemas.ValidateHumanIngressExecuteJSON
	if r.URL.Path == IngressRecoverPath {
		validator = schemas.ValidateHumanIngressRecoverJSON
	}
	if err := decodeIngressEnvelope(r.Body, &input, validator); err != nil {
		s.writeIngressError(w, IngressCodeInvalidRequest)
		return
	}
	operation, err := decodeOperation(input.Operation, input.Request)
	if err != nil {
		s.writeIngressError(w, IngressCodeInvalidRequest)
		return
	}
	if (operation.kind == RequestKindOperationRecover) != (r.URL.Path == IngressRecoverPath) {
		s.writeIngressError(w, IngressCodeInvalidRequest)
		return
	}
	challenge, err := s.takeChallenge(input.ChallengeID, connectionKey(state), operation.kind, operation.digest, s.currentTime())
	if err != nil {
		s.writeIngressError(w, IngressCodeChallengeRejected)
		return
	}
	evidence := Evidence{
		GrantJWT: input.GrantJWT, SessionBindingJWT: input.SessionBindingJWT,
		AcceptedUntil: challenge.expiresAt,
		Options: clients.SessionIdentityJWTOptions{
			Grant: s.Policy.Grant, SessionBinding: s.Policy.SessionBinding,
			Policy: s.Policy.Identity, ExpectedBinding: challenge.expectedBinding,
			ReplayCache: s.Policy.ReplayCache,
		},
	}
	ctx := r.Context()
	var response []byte
	if durable, ok := s.Store.(HumanTransactionStore); ok {
		err = durable.RunHumanTransaction(ctx, func(tx HumanTransaction) error {
			var executeErr error
			response, executeErr = s.executeDurable(ctx, tx, operation, evidence)
			return executeErr
		})
	} else if operation.kind == RequestKindOperationRecover {
		err = errOperationAuthorization
	} else {
		var result ExecuteResponse
		result, err = s.executeVerified(ctx, s.Store, operation, evidence)
		if err == nil {
			response, err = json.Marshal(result)
		}
	}
	if err != nil {
		s.writeIngressError(w, ingressCodeForError(err))
		return
	}
	// These are exactly the bytes retained by the transaction, not a new
	// response reconstructed from subsequently changed Assignment state.
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(response, '\n'))
}

func (s *Ingress) acceptOperation(ctx context.Context, store taskcoord.Store, operation operationEnvelope, evidence Evidence) (Profile, acceptance, time.Time, error) {
	// Read the clock and current Participant inside the transaction, after any
	// lock wait. An expired proof cannot acquire validity by waiting for a lock.
	now := s.currentTime()
	profile := Profile{Participants: store, Now: func() time.Time { return now }}
	accepted, err := profile.accept(ctx, operation.participantID(), operation.digest, evidence, now)
	if err != nil {
		return profile, acceptance{}, now, errOperationAuthorization
	}
	if s.Policy.AcceptedUntil != nil {
		policyExpiry, err := s.Policy.AcceptedUntil(ctx, operation.kind, operation.digest)
		if err != nil {
			return profile, acceptance{}, now, errOperationAuthorization
		}
		if !policyExpiry.IsZero() && policyExpiry.Before(accepted.expiresAt) {
			accepted.expiresAt = policyExpiry
		}
		if !now.Before(accepted.expiresAt) {
			return profile, acceptance{}, now, errOperationAuthorization
		}
	}
	return profile, accepted, now, nil
}

func (s *Ingress) executeVerified(ctx context.Context, store taskcoord.Store, operation operationEnvelope, evidence Evidence) (ExecuteResponse, error) {
	profile, accepted, now, err := s.acceptOperation(ctx, store, operation, evidence)
	if err != nil {
		return ExecuteResponse{}, err
	}
	return s.applyOperation(ctx, store, profile, operation, accepted, now)
}

func (s *Ingress) executeDurable(ctx context.Context, tx HumanTransaction, operation operationEnvelope, evidence Evidence) ([]byte, error) {
	evidence.Options.ReplayCache = tx
	profile, accepted, now, err := s.acceptOperation(ctx, tx, operation, evidence)
	if err != nil {
		return nil, err
	}
	if operation.recovery != nil {
		request := *operation.recovery
		outcome, err := tx.LookupHumanOutcome(ctx, request.OperationID)
		if err != nil {
			return nil, err
		}
		if outcome.ParticipantID != accepted.human.ParticipantID || outcome.ActorID != accepted.actorID || outcome.RequestDigest != request.RequestDigest {
			return nil, errOperationAuthorization
		}
		if err := outcome.Validate(); err != nil {
			return nil, err
		}
		if err := accepted.commitReplay(); err != nil {
			return nil, err
		}
		if !s.currentTime().Before(accepted.expiresAt) {
			return nil, errOperationAuthorization
		}
		return append([]byte(nil), outcome.Response...), nil
	}
	if _, err := tx.LookupHumanOutcome(ctx, operation.eventID()); err == nil {
		// Re-execution, even with a fresh proof, must use the explicit recovery
		// mode. It must not create new provenance or reapply an earlier event.
		return nil, ErrHumanOutcomeConflict
	} else if !errors.Is(err, ErrHumanOutcomeNotFound) {
		return nil, err
	}
	result, err := s.applyOperation(ctx, tx, profile, operation, accepted, now)
	if err != nil {
		return nil, err
	}
	response, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	outcome := HumanOutcome{OperationID: operation.eventID(), RequestDigest: operation.digest.String(), ParticipantID: accepted.human.ParticipantID, ActorID: accepted.actorID, Response: response}
	if err := outcome.Validate(); err != nil {
		return nil, err
	}
	if err := tx.PutHumanOutcome(ctx, outcome); err != nil {
		return nil, err
	}
	// Trusted policy/delegation callbacks may have taken time after proof
	// verification. Expiry here rolls back mutation, replay, outbox and outcome.
	if !s.currentTime().Before(accepted.expiresAt) {
		return nil, errOperationAuthorization
	}
	return response, nil
}

func (s *Ingress) applyOperation(ctx context.Context, store taskcoord.Store, profile Profile, operation operationEnvelope, accepted acceptance, now time.Time) (ExecuteResponse, error) {
	switch operation.kind {
	case RequestKindAssignmentOffer:
		transition, err := profile.offerAccepted(ctx, *operation.offer, accepted, now)
		if err != nil {
			return ExecuteResponse{}, err
		}
		if err := store.CommitAssignment(ctx, 0, transition.Assignment, transition.Record); err != nil {
			return ExecuteResponse{}, err
		}
		return ExecuteResponse{Operation: OperationAssignmentOffer, Assignment: &transition.Assignment, Record: &transition.Record}, nil
	case RequestKindAssignmentTransition:
		request := *operation.transition
		current, err := store.LoadAssignment(ctx, request.AssignmentID)
		if err != nil {
			return ExecuteResponse{}, err
		}
		if current.TaskID != request.TaskID || current.Revision != request.ExpectedRevision {
			return ExecuteResponse{}, taskcoord.ErrRevisionConflict
		}
		transition, err := profile.applyAccepted(current, request, accepted, now)
		if err != nil {
			return ExecuteResponse{}, err
		}
		if err := store.CommitAssignment(ctx, request.ExpectedRevision, transition.Assignment, transition.Record); err != nil {
			return ExecuteResponse{}, err
		}
		return ExecuteResponse{Operation: OperationAssignmentTransition, Assignment: &transition.Assignment, Record: &transition.Record}, nil
	case RequestKindInteractionAppend:
		request := *operation.interaction
		current, err := store.LoadAssignment(ctx, request.AssignmentID)
		if err != nil {
			return ExecuteResponse{}, err
		}
		if current.TaskID != request.TaskID {
			return ExecuteResponse{}, taskcoord.ErrRevisionConflict
		}
		event, err := profile.newInteractionEventAccepted(request, accepted, now)
		if err != nil {
			return ExecuteResponse{}, err
		}
		if err := store.AppendInteractionEvent(ctx, event); err != nil {
			return ExecuteResponse{}, err
		}
		return ExecuteResponse{Operation: OperationInteractionAppend, Interaction: &event}, nil
	case RequestKindAssignmentDelegation:
		request := *operation.delegation
		if isNilDelegationVerifier(s.Policy.DelegationVerifier) {
			return ExecuteResponse{}, errOperationAuthorization
		}
		parent, err := store.LoadAssignment(ctx, request.ParentAssignmentID)
		if err != nil {
			return ExecuteResponse{}, err
		}
		if parent.TaskID != request.ParentTaskID || parent.Revision != request.ExpectedRevision {
			return ExecuteResponse{}, taskcoord.ErrRevisionConflict
		}
		verifyDelegation := func(ctx context.Context, current taskcoord.Assignment, request DelegationRequest, at time.Time) (taskcoord.VerifiedDelegation, error) {
			verified, err := s.Policy.DelegationVerifier.VerifyDelegation(ctx, current, request, at)
			if err != nil || verified.Validate() != nil ||
				verified.DecisionID != request.DecisionID || verified.ParentAssignmentID != current.AssignmentID ||
				verified.ChildAssignmentID != request.ChildAssignmentID || verified.FromParticipantID != current.ParticipantID ||
				verified.ToParticipantID != request.TargetParticipantID || verified.ParentAuthorityDigest != current.AuthorityDigest ||
				verified.ChildAuthorityDigest != request.AuthorityDigest || verified.VerifiedAt.After(at) {
				return taskcoord.VerifiedDelegation{}, errOperationAuthorization
			}
			return verified, nil
		}
		transition, err := profile.delegateAccepted(ctx, parent, request, accepted, now, verifyDelegation)
		if err != nil {
			return ExecuteResponse{}, err
		}
		if err := store.CommitDelegation(ctx, request.ExpectedRevision, transition); err != nil {
			return ExecuteResponse{}, err
		}
		return ExecuteResponse{Operation: OperationAssignmentDelegation, ParentAssignment: &transition.Parent, ParentRecord: &transition.ParentRecord, ChildAssignment: &transition.Child, ChildRecord: &transition.ChildRecord, Delegation: &transition.Delegation}, nil
	default:
		return ExecuteResponse{}, ErrUnsupportedOperationKind
	}
}

func (o operationEnvelope) eventID() string {
	switch o.kind {
	case RequestKindAssignmentOffer:
		return o.offer.EventID
	case RequestKindAssignmentTransition:
		return o.transition.EventID
	case RequestKindAssignmentDelegation:
		return o.delegation.EventID
	case RequestKindInteractionAppend:
		return o.interaction.EventID
	default:
		return ""
	}
}

func (o operationEnvelope) participantID() string {
	switch o.kind {
	case RequestKindAssignmentOffer:
		return o.offer.ParticipantID
	case RequestKindAssignmentTransition:
		return o.transition.ParticipantID
	case RequestKindAssignmentDelegation:
		return o.delegation.ParticipantID
	case RequestKindInteractionAppend:
		return o.interaction.ParticipantID
	case RequestKindOperationRecover:
		return o.recovery.ParticipantID
	default:
		return ""
	}
}

func decodeOperation(kind string, raw json.RawMessage) (operationEnvelope, error) {
	if len(raw) == 0 {
		return operationEnvelope{}, errors.New("asbbinding ingress: missing operation request")
	}
	switch kind {
	case OperationAssignmentOffer:
		var request OfferRequest
		if err := decodeIngressJSON(bytes.NewReader(raw), &request); err != nil {
			return operationEnvelope{}, err
		}
		digest, err := OfferDigest(request)
		return operationEnvelope{kind: RequestKindAssignmentOffer, digest: digest, offer: &request}, err
	case OperationAssignmentTransition:
		var request TransitionRequest
		if err := decodeIngressJSON(bytes.NewReader(raw), &request); err != nil {
			return operationEnvelope{}, err
		}
		digest, err := TransitionDigest(request)
		return operationEnvelope{kind: RequestKindAssignmentTransition, digest: digest, transition: &request}, err
	case OperationAssignmentDelegation:
		var request DelegationRequest
		if err := decodeIngressJSON(bytes.NewReader(raw), &request); err != nil {
			return operationEnvelope{}, err
		}
		digest, err := DelegationDigest(request)
		return operationEnvelope{kind: RequestKindAssignmentDelegation, digest: digest, delegation: &request}, err
	case OperationInteractionAppend:
		var request InteractionRequest
		if err := decodeIngressJSON(bytes.NewReader(raw), &request); err != nil {
			return operationEnvelope{}, err
		}
		digest, err := InteractionDigest(request)
		return operationEnvelope{kind: RequestKindInteractionAppend, digest: digest, interaction: &request}, err
	case OperationRecover:
		var request RecoveryRequest
		if err := decodeIngressJSON(bytes.NewReader(raw), &request); err != nil {
			return operationEnvelope{}, err
		}
		digest, err := RecoveryDigest(request)
		return operationEnvelope{kind: RequestKindOperationRecover, digest: digest, recovery: &request}, err
	default:
		return operationEnvelope{}, ErrUnsupportedOperationKind
	}
}

func verifiedTLSState(r *http.Request) (*tls.ConnectionState, *x509.Certificate, error) {
	if r == nil || r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.Version != tls.VersionTLS13 {
		return nil, nil, ErrTLSRequired
	}
	if len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 ||
		len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0] == nil {
		return nil, nil, ErrTLSRequired
	}
	return r.TLS, r.TLS.PeerCertificates[0], nil
}

// BindingFromTLS derives the expected binding from a verified mTLS client and
// the current TLS 1.3 connection. It never accepts peer-provided hash values.
func BindingFromTLS(state *tls.ConnectionState, leaf *x509.Certificate, digest Digest, nonce string) (identitypolicy.Binding, error) {
	if state == nil || leaf == nil || strings.TrimSpace(nonce) == "" {
		return identitypolicy.Binding{}, ErrTLSRequired
	}
	contextBytes := RequestContext(digest)
	exported, err := state.ExportKeyingMaterial(
		eaattestation.ExporterLabelAttestation,
		contextBytes,
		eaattestation.ExportedAttestationValueLen,
	)
	if err != nil {
		return identitypolicy.Binding{}, fmt.Errorf("asbbinding ingress: derive TLS exporter: %w", err)
	}
	leafBytes, err := eaattestation.PublicKeyBytes(leaf)
	if err != nil {
		return identitypolicy.Binding{}, fmt.Errorf("asbbinding ingress: encode client public key: %w", err)
	}
	leafHash := sha256.Sum256(leafBytes)
	exporterHash := sha256.Sum256(exported)
	return identitypolicy.Binding{
		LeafPublicKeySHA256:  hex.EncodeToString(leafHash[:]),
		TLSExporterSHA256:    hex.EncodeToString(exporterHash[:]),
		RequestContextSHA256: RequestContextSHA256(digest),
		Nonce:                nonce,
	}, nil
}

func connectionKey(state *tls.ConnectionState) string {
	if state == nil {
		return ""
	}
	exported, err := state.ExportKeyingMaterial("EXPORTER-ASB-TaskCoord-connection-v1", nil, 32)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(exported)
	return hex.EncodeToString(sum[:])
}

func (s *Ingress) putChallenge(id string, entry pendingChallenge, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		s.pending = make(map[string]pendingChallenge)
	}
	if s.connections == nil {
		s.connections = make(map[string]int)
	}
	if s.identities == nil {
		s.identities = make(map[string]int)
	}
	s.pruneLocked(now)
	identityKey := strings.TrimSpace(entry.expectedBinding.LeafPublicKeySHA256)
	if entry.connectionKey == "" || identityKey == "" {
		return ErrTLSRequired
	}
	if _, exists := s.pending[id]; exists {
		return errChallengeCollision
	}
	if len(s.pending) >= s.maxTotalPending() {
		return ErrChallengeLimit
	}
	if s.connections[entry.connectionKey] >= s.maxPending() {
		return ErrChallengeLimit
	}
	if s.identities[identityKey] >= s.maxPending() {
		return ErrChallengeLimit
	}
	s.pending[id] = entry
	s.connections[entry.connectionKey]++
	s.identities[identityKey]++
	return nil
}

func (s *Ingress) takeChallenge(id, connection string, kind RequestKind, digest Digest, now time.Time) (pendingChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	entry, ok := s.pending[id]
	if !ok {
		return pendingChallenge{}, ErrUnknownChallenge
	}
	delete(s.pending, id)
	s.releaseChallengeLocked(entry)
	if entry.connectionKey != connection || connection == "" {
		return pendingChallenge{}, ErrChallengeConnection
	}
	if entry.requestKind != kind || entry.digest != digest {
		return pendingChallenge{}, ErrChallengeRequest
	}
	if !now.Before(entry.expiresAt) {
		return pendingChallenge{}, ErrUnknownChallenge
	}
	return entry, nil
}

func (s *Ingress) pruneLocked(now time.Time) {
	for id, entry := range s.pending {
		if !now.Before(entry.expiresAt) {
			delete(s.pending, id)
			s.releaseChallengeLocked(entry)
		}
	}
}

func (s *Ingress) releaseChallengeLocked(entry pendingChallenge) {
	s.decrementConnectionLocked(entry.connectionKey)
	s.decrementIdentityLocked(strings.TrimSpace(entry.expectedBinding.LeafPublicKeySHA256))
}

func (s *Ingress) decrementConnectionLocked(connection string) {
	if s.connections[connection] <= 1 {
		delete(s.connections, connection)
		return
	}
	s.connections[connection]--
}

func (s *Ingress) decrementIdentityLocked(identity string) {
	if s.identities[identity] <= 1 {
		delete(s.identities, identity)
		return
	}
	s.identities[identity]--
}

func (s *Ingress) randomChallengeValues() (string, string, error) {
	source := s.Random
	if isNilDependency(source) {
		source = rand.Reader
	}
	var challenge [challengeBytes]byte
	var nonce [challengeBytes]byte
	if _, err := io.ReadFull(source, challenge[:]); err != nil {
		return "", "", fmt.Errorf("asbbinding ingress: generate challenge ID: %w", err)
	}
	if _, err := io.ReadFull(source, nonce[:]); err != nil {
		return "", "", fmt.Errorf("asbbinding ingress: generate nonce: %w", err)
	}
	return hex.EncodeToString(challenge[:]), hex.EncodeToString(nonce[:]), nil
}

func (s *Ingress) currentTime() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Ingress) challengeTTL() time.Duration {
	if s.ChallengeTTL > 0 {
		return s.ChallengeTTL
	}
	return 2 * time.Minute
}

func (s *Ingress) maxPending() int {
	if s.MaxPending > 0 {
		return s.MaxPending
	}
	return defaultMaxPending
}

func (s *Ingress) maxTotalPending() int {
	if s.MaxTotalPending > 0 {
		return s.MaxTotalPending
	}
	return defaultMaxTotalPending
}

func decodeIngressJSON(reader io.Reader, target any) error {
	raw, err := readIngressJSON(reader)
	if err != nil {
		return err
	}
	return decodeIngressJSONBytes(raw, target)
}

func decodeIngressEnvelope(reader io.Reader, target any, validate func([]byte) error) error {
	raw, err := readIngressJSON(reader)
	if err != nil {
		return err
	}
	if err := rejectDuplicateJSONMembers(raw); err != nil {
		return err
	}
	if validate == nil {
		return errors.New("asbbinding ingress: missing endpoint JSON validator")
	}
	if err := validate(raw); err != nil {
		return fmt.Errorf("asbbinding ingress: %w", err)
	}
	return decodeIngressJSONBytes(raw, target)
}

func readIngressJSON(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("asbbinding ingress: missing JSON input")
	}
	raw, err := io.ReadAll(io.LimitReader(reader, taskcoord.MaxDocumentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("asbbinding ingress: read JSON: %w", err)
	}
	if len(raw) > taskcoord.MaxDocumentBytes {
		return nil, fmt.Errorf("asbbinding ingress: JSON exceeds %d bytes", taskcoord.MaxDocumentBytes)
	}
	if !utf8.Valid(raw) {
		return nil, errors.New("asbbinding ingress: JSON is not valid UTF-8")
	}
	return raw, nil
}

func decodeIngressJSONBytes(raw []byte, target any) error {
	if err := rejectDuplicateJSONMembers(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("asbbinding ingress: decode JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("asbbinding ingress: trailing JSON value")
	}
	return nil
}

func writeIngressJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		return
	}
}
