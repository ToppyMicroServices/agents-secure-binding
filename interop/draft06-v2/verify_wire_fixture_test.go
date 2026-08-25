// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package draft06v2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFullWireFixtureWithIndependentPython(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not available")
	}
	script, fixture := wireVerifierPaths(t)
	args := []string{script}
	if openssl, lookupErr := exec.LookPath("openssl"); lookupErr == nil {
		args = append(args, "--openssl", openssl)
	} else {
		args = append(args, "--skip-signatures")
	}
	args = append(args, fixture)
	runWireVerifier(t, python, args, true, "verified draft06-v2 full-wire fixture")
}

func TestFullWireFixturePythonRejectsContextTamper(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not available")
	}
	script, fixture := wireVerifierPaths(t)
	document := readJSONObject(t, fixture)
	expected := childObject(t, document, "expected")
	expected["task_context_sha256"] = "sha256:" + strings.Repeat("0", 64)
	tampered := writeJSONDocument(t, document)
	runWireVerifier(
		t,
		python,
		[]string{script, "--skip-signatures", tampered},
		false,
		"task context SHA-256 mismatch",
	)
}

func TestFullWireFixturePythonRejectsES256Tamper(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not available")
	}
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not available")
	}
	script, fixture := wireVerifierPaths(t)
	document := readJSONObject(t, fixture)
	httpRequest := childObject(t, document, "http_request")
	bodyRaw := decodeRawBase64URL(t, stringValue(t, httpRequest, "body_base64url"))
	var body map[string]any
	if err := json.Unmarshal(bodyRaw, &body); err != nil {
		t.Fatalf("decode fixture body: %v", err)
	}
	message := childObject(t, body, "message")
	metadata := childObject(t, message, "metadata")
	sbo := childObject(t, metadata, "urn:agents-secure-binding:security-binding:v2")
	token := stringValue(t, sbo, "session_binding")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("fixture session binding has %d compact parts", len(parts))
	}
	signature := decodeRawBase64URL(t, parts[2])
	if len(signature) != 64 {
		t.Fatalf("fixture ES256 signature has %d bytes", len(signature))
	}
	signature[len(signature)-1] ^= 1
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	tamperedToken := strings.Join(parts, ".")
	sbo["session_binding"] = tamperedToken
	tamperedTokenHash := sha256String([]byte(tamperedToken))
	sbo["session_binding_sha256"] = tamperedTokenHash
	childObject(t, document, "expected")["session_binding_sha256"] = tamperedTokenHash

	encodedBody, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode tampered body: %v", err)
	}
	httpRequest["body_base64url"] = base64.RawURLEncoding.EncodeToString(encodedBody)
	httpRequest["body_sha256"] = sha256String(encodedBody)
	tampered := writeJSONDocument(t, document)
	runWireVerifier(
		t,
		python,
		[]string{script, "--openssl", openssl, tampered},
		false,
		"session binding JWS signature verification failed",
	)
}

func wireVerifierPaths(t *testing.T) (string, string) {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	directory := filepath.Dir(sourceFile)
	repositoryRoot := filepath.Clean(filepath.Join(directory, "..", ".."))
	return filepath.Join(directory, "verify_wire_fixture.py"), filepath.Join(repositoryRoot, "examples", "a2a-multiprocess", "testdata", "draft06-v2-wire.json")
}

func runWireVerifier(t *testing.T, python string, args []string, wantSuccess bool, outputFragment string) {
	t.Helper()
	command := exec.Command(python, args...)
	output, err := command.CombinedOutput()
	if wantSuccess && err != nil {
		t.Fatalf("independent Python wire verifier failed: %v\n%s", err, output)
	}
	if !wantSuccess && err == nil {
		t.Fatalf("independent Python wire verifier accepted tampering:\n%s", output)
	}
	if !strings.Contains(string(output), outputFragment) {
		t.Fatalf("wire verifier output %q does not contain %q", output, outputFragment)
	}
}

func readJSONObject(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func childObject(t *testing.T, parent map[string]any, name string) map[string]any {
	t.Helper()
	value, ok := parent[name].(map[string]any)
	if !ok {
		t.Fatalf("%s is not an object", name)
	}
	return value
}

func stringValue(t *testing.T, parent map[string]any, name string) string {
	t.Helper()
	value, ok := parent[name].(string)
	if !ok {
		t.Fatalf("%s is not a string", name)
	}
	return value
}

func decodeRawBase64URL(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func sha256String(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func writeJSONDocument(t *testing.T, value map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tampered-wire.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
