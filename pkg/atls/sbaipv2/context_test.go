// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package sbaipv2

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestAppendixBContextAndHashes(t *testing.T) {
	var grantHash [32]byte
	for i := range grantHash {
		grantHash[i] = byte(i)
	}

	context, err := EncodeContext(ContextInputs{
		EndpointRole:    "client-tls-endpoint",
		InteractionType: "agent-to-tool",
		ProtocolID:      "https-jws-direct-v2",
		Audience:        "https://verifier.example/api",
		GrantHash:       grantHash,
		TaskContext:     []byte("task:v2:transfer#123"),
		TargetContext:   []byte("tool:v1:payments-api/transfer"),
		VerifierNonce:   mustHex(t, "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
		AttemptID:       []byte("attempt-123"),
	})
	if err != nil {
		t.Fatalf("EncodeContext() error = %v", err)
	}

	wantContext := mustHex(t, ""+
		"53424149502d434f4e544558542d763200000d656e64706f696e745f726f6c65"+
		"00000013636c69656e742d746c732d656e64706f696e740010696e7465726163"+
		"74696f6e5f747970650000000d6167656e742d746f2d746f6f6c000b70726f74"+
		"6f636f6c5f69640000001368747470732d6a77732d6469726563742d76320003"+
		"6175640000001c68747470733a2f2f76657269666965722e6578616d706c652f"+
		"617069000a6772616e745f6861736800000020000102030405060708090a0b0c"+
		"0d0e0f101112131415161718191a1b1c1d1e1f000c7461736b5f636f6e746578"+
		"74000000147461736b3a76323a7472616e7366657223313233000e7461726765"+
		"745f636f6e746578740000001d746f6f6c3a76313a7061796d656e74732d6170"+
		"692f7472616e73666572000e76657269666965725f6e6f6e636500000010a0a1"+
		"a2a3a4a5a6a7a8a9aaabacadaeaf000a617474656d70745f69640000000b6174"+
		"74656d70742d313233")
	if !bytes.Equal(context, wantContext) {
		t.Fatalf("EncodeContext() = %x, want %x", context, wantContext)
	}

	hashes, err := DeriveHashes(
		context,
		[]byte("SPKI"),
		mustHex(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
	)
	if err != nil {
		t.Fatalf("DeriveHashes() error = %v", err)
	}

	assertHash(t, "binding_context_sha256", hashes.BindingContextSHA256,
		"5e667cbd7d74e96d89a0cb346a68e4879da4d0335ae9a751fbb5ce9f8df1e1df")
	assertHash(t, "accepted_endpoint_spki_sha256", hashes.AcceptedEndpointSPKISHA256,
		"0eabce0bf771c5036457802bab1dded04e5668664206847f7ce0375a476c7972")
	assertHash(t, "tls_exporter_sha256", hashes.TLSExporterSHA256,
		"72dbb7336c76780023f83da4c355f2eeea85733b13d3477697917790c1229084")
	assertHash(t, "attestation_binder_sha256", hashes.AttestationBinderSHA256,
		"c266f31e94ec89b0f5a96b34f236aa6c463f6dfcf1d81976f2acbef2a9d77fc2")
}

func TestEncodeContextIncludesEmptyAttemptID(t *testing.T) {
	context, err := EncodeContext(ContextInputs{
		EndpointRole:    "client-tls-endpoint",
		InteractionType: "agent-to-agent",
		ProtocolID:      "test-v2",
		Audience:        "verifier",
		TaskContext:     []byte("task"),
		TargetContext:   []byte("target"),
		VerifierNonce:   make([]byte, MinVerifierNonceLength),
	})
	if err != nil {
		t.Fatalf("EncodeContext() error = %v", err)
	}
	wantSuffix := mustHex(t, "000a617474656d70745f696400000000")
	if !bytes.HasSuffix(context, wantSuffix) {
		t.Fatalf("EncodeContext() suffix = %x, want %x", context[len(context)-len(wantSuffix):], wantSuffix)
	}
}

func TestEncodeContextRejectsShortVerifierNonce(t *testing.T) {
	_, err := EncodeContext(ContextInputs{
		EndpointRole:    "client-tls-endpoint",
		InteractionType: "agent-to-agent",
		ProtocolID:      "test-v2",
		Audience:        "verifier",
		TaskContext:     []byte("task"),
		TargetContext:   []byte("target"),
		VerifierNonce:   make([]byte, MinVerifierNonceLength-1),
	})
	if !errors.Is(err, ErrVerifierNonceShort) {
		t.Fatalf("EncodeContext() error = %v, want %v", err, ErrVerifierNonceShort)
	}
}

func TestAttestationBinderChangesWithEndpointOrExporter(t *testing.T) {
	context := []byte("context")
	ekms := [][]byte{bytes.Repeat([]byte{1}, ExporterLength), bytes.Repeat([]byte{2}, ExporterLength)}
	first, err := DeriveHashes(context, []byte("spki-a"), ekms[0])
	if err != nil {
		t.Fatalf("DeriveHashes() error = %v", err)
	}
	endpointChanged, err := DeriveHashes(context, []byte("spki-b"), ekms[0])
	if err != nil {
		t.Fatalf("DeriveHashes() endpoint change error = %v", err)
	}
	exporterChanged, err := DeriveHashes(context, []byte("spki-a"), ekms[1])
	if err != nil {
		t.Fatalf("DeriveHashes() exporter change error = %v", err)
	}
	if first.AttestationBinderSHA256 == endpointChanged.AttestationBinderSHA256 {
		t.Fatal("attestation binder did not change with leaf SPKI")
	}
	if first.AttestationBinderSHA256 == exporterChanged.AttestationBinderSHA256 {
		t.Fatal("attestation binder did not change with EKM")
	}
}

func TestAttestationBindingInputRejectsWrongExporterLength(t *testing.T) {
	_, err := AttestationBindingInput([]byte("SPKI"), make([]byte, ExporterLength-1))
	if !errors.Is(err, ErrExporterLength) {
		t.Fatalf("AttestationBindingInput() error = %v, want %v", err, ErrExporterLength)
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) error = %v", value, err)
	}
	return decoded
}

func assertHash(t *testing.T, name string, got [32]byte, want string) {
	t.Helper()
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("%s = %x, want %s", name, got, want)
	}
}
