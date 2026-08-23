// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// AuthorityCredential maps one accepted actor credential to one logical
// authority slot. Several credentials may map to one slot during rotation.
type AuthorityCredential struct {
	AuthorityID      string
	GrantIssuer      string
	ActorID          string
	ProofIssuer      string
	SignerKey        string
	CredentialDigest string
}

// StaticAuthorityResolver is a fail-closed resolver for deployments with a
// local authority map. SignerKey is only a label within ProofIssuer; the
// credential digest identifies the actual verification key.
type StaticAuthorityResolver struct {
	byActorAndKey map[string]staticAuthorityEntry
	mapDigest     string
}

type staticAuthorityEntry struct {
	authorityID      string
	credentialDigest string
}

func NewStaticAuthorityResolver(credentials []AuthorityCredential) (*StaticAuthorityResolver, error) {
	if len(credentials) == 0 {
		return nil, errors.New("authorityquorum asbbinding: empty authority credential map")
	}
	resolver := &StaticAuthorityResolver{byActorAndKey: make(map[string]staticAuthorityEntry, len(credentials))}
	actorOwners := make(map[string]string, len(credentials))
	credentialOwners := make(map[string]string, len(credentials))
	for _, credential := range credentials {
		if !validCredentialComponent(credential.AuthorityID) || !validCredentialComponent(credential.GrantIssuer) ||
			!validCredentialComponent(credential.ActorID) || !validCredentialComponent(credential.ProofIssuer) ||
			!validCredentialComponent(credential.SignerKey) || !validCredentialDigest(credential.CredentialDigest) {
			return nil, errors.New("authorityquorum asbbinding: incomplete authority credential")
		}
		if owner, ok := credentialOwners[credential.CredentialDigest]; ok && owner != credential.AuthorityID {
			return nil, fmt.Errorf("authorityquorum asbbinding: credential assigned to %s and %s", owner, credential.AuthorityID)
		}
		credentialOwners[credential.CredentialDigest] = credential.AuthorityID
		actor := credential.GrantIssuer + "\x00" + credential.ActorID
		if owner, ok := actorOwners[actor]; ok && owner != credential.AuthorityID {
			return nil, fmt.Errorf("authorityquorum asbbinding: actor assigned to %s and %s", owner, credential.AuthorityID)
		}
		actorOwners[actor] = credential.AuthorityID
		lookup := authorityLookupKey(
			credential.GrantIssuer, credential.ActorID, credential.ProofIssuer, credential.SignerKey,
		)
		if _, ok := resolver.byActorAndKey[lookup]; ok {
			return nil, errors.New("authorityquorum asbbinding: duplicate actor credential tuple")
		}
		resolver.byActorAndKey[lookup] = staticAuthorityEntry{
			authorityID: credential.AuthorityID, credentialDigest: credential.CredentialDigest,
		}
	}
	resolver.mapDigest = computeAuthorityMapDigest(credentials)
	return resolver, nil
}

func (r *StaticAuthorityResolver) ResolveAuthority(_ context.Context, actor VerifiedActor) (ResolvedAuthority, error) {
	if r == nil {
		return ResolvedAuthority{}, ErrMissingAuthorityResolver
	}
	entry, ok := r.byActorAndKey[authorityLookupKey(
		actor.GrantIssuer, actor.ActorID, actor.ProofIssuer, actor.SignerKey,
	)]
	if !ok || entry.credentialDigest != actor.CredentialDigest {
		return ResolvedAuthority{}, ErrUnknownAuthority
	}
	return ResolvedAuthority{AuthorityID: entry.authorityID, AuthorityMapDigest: r.mapDigest}, nil
}

func (r *StaticAuthorityResolver) AuthorityMapDigest() string {
	if r == nil {
		return ""
	}
	return r.mapDigest
}

func authorityLookupKey(grantIssuer, actorID, proofIssuer, signerKey string) string {
	return grantIssuer + "\x00" + actorID + "\x00" + proofIssuer + "\x00" + signerKey
}

func computeAuthorityMapDigest(credentials []AuthorityCredential) string {
	ordered := append([]AuthorityCredential(nil), credentials...)
	sort.Slice(ordered, func(i, j int) bool {
		left := [...]string{
			ordered[i].AuthorityID, ordered[i].GrantIssuer, ordered[i].ActorID,
			ordered[i].ProofIssuer, ordered[i].SignerKey, ordered[i].CredentialDigest,
		}
		right := [...]string{
			ordered[j].AuthorityID, ordered[j].GrantIssuer, ordered[j].ActorID,
			ordered[j].ProofIssuer, ordered[j].SignerKey, ordered[j].CredentialDigest,
		}
		for index := range left {
			if left[index] != right[index] {
				return left[index] < right[index]
			}
		}
		return false
	})
	fields := make([][]byte, 0, len(ordered)*6)
	for _, credential := range ordered {
		fields = append(fields, []byte(credential.AuthorityID), []byte(credential.GrantIssuer),
			[]byte(credential.ActorID), []byte(credential.ProofIssuer), []byte(credential.SignerKey),
			[]byte(credential.CredentialDigest))
	}
	return stableDigest("ASB-AUTHORITY-QUORUM-AUTHORITY-MAP-v1", fields...)
}

func validCredentialComponent(value string) bool {
	if value == "" || len(value) > 512 || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func validCredentialDigest(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	hexValue := strings.TrimPrefix(value, prefix)
	if len(hexValue) != 64 || hexValue != strings.ToLower(hexValue) {
		return false
	}
	decoded, err := hex.DecodeString(hexValue)
	return err == nil && len(decoded) == 32
}
