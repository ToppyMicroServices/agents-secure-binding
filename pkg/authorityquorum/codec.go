// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package authorityquorum

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

func DecodeVerifiedPolicy(r io.Reader) (VerifiedPolicy, error) {
	var policy VerifiedPolicy
	if err := decodeStrict(r, &policy); err != nil {
		return VerifiedPolicy{}, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	if err := policy.Validate(); err != nil {
		return VerifiedPolicy{}, err
	}
	return policy, nil
}

func DecodeApproval(r io.Reader) (Approval, error) {
	var approval Approval
	if err := decodeStrict(r, &approval); err != nil {
		return Approval{}, fmt.Errorf("%w: %v", ErrInvalidApproval, err)
	}
	if err := approval.Validate(); err != nil {
		return Approval{}, err
	}
	return approval, nil
}

func DecodeDecisionRevocation(r io.Reader) (DecisionRevocation, error) {
	var revocation DecisionRevocation
	if err := decodeStrict(r, &revocation); err != nil {
		return DecisionRevocation{}, fmt.Errorf("%w: %v", ErrInvalidRevocation, err)
	}
	if err := revocation.Validate(); err != nil {
		return DecisionRevocation{}, err
	}
	return revocation, nil
}

func DecodeVerifiedQuorum(r io.Reader) (VerifiedQuorum, error) {
	var quorum VerifiedQuorum
	if err := decodeStrict(r, &quorum); err != nil {
		return VerifiedQuorum{}, fmt.Errorf("%w: %v", ErrInvalidQuorum, err)
	}
	if err := quorum.Validate(); err != nil {
		return VerifiedQuorum{}, err
	}
	return quorum, nil
}

func decodeStrict(r io.Reader, target any) error {
	if r == nil {
		return fmt.Errorf("missing JSON input")
	}
	raw, err := io.ReadAll(io.LimitReader(r, MaxDocumentBytes+1))
	if err != nil {
		return fmt.Errorf("read JSON: %v", err)
	}
	if len(raw) > MaxDocumentBytes {
		return fmt.Errorf("JSON exceeds %d bytes", MaxDocumentBytes)
	}
	if !utf8.Valid(raw) {
		return fmt.Errorf("JSON is not valid UTF-8")
	}
	if err := rejectDuplicateJSONMembers(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode JSON: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}

func rejectDuplicateJSONMembers(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return fmt.Errorf("invalid JSON: %v", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("invalid JSON: %v", err)
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object member name is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate object member %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("array is not closed")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
