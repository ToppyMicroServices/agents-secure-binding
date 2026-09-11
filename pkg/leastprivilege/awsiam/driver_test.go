// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package awsiam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fakeExecutor(t *testing.T) (*Executor, lp.Solution, lp.Request, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("local fake CLI fixture requires POSIX shell")
	}
	p, s, r := fixture(t)
	dir := t.TempDir()
	cli := filepath.Join(dir, "fake-aws")
	source := filepath.Join(dir, "source.ini")
	response, err := json.Marshal(map[string]string{"AccessKeyId": "ASIA1111222233334444", "SecretAccessKey": "fabricated-session-secret-key", "SessionToken": "fabricated-session-token", "Expiration": time.Now().UTC().Add(15 * time.Minute).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nset -eu\numask 077\n/usr/bin/env > \"$0.env\"\n/usr/bin/printf '%s\\n' \"$@\" > \"$0.args\"\n/bin/cat \"$AWS_SHARED_CREDENTIALS_FILE\" > \"$0.creds\"\n/usr/bin/printf '%s' '" + string(response) + "'\n"
	if err := os.WriteFile(cli, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("[develop]\naws_access_key_id=AKIA1111222233334444\naws_secret_access_key=fabricated-source-secret\n[other]\naws_access_key_id=AKIA9999888877776666\naws_secret_access_key=unrelated-source-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := NewExecutor(p, CLIConfig{Path: cli, CredentialsFile: source, MaxEvaluations: 4})
	if err != nil {
		t.Fatal(err)
	}
	return e, s, r, cli
}

func goodResponse() *http.Response {
	return &http.Response{StatusCode: http.StatusPartialContent, Header: http.Header{"Etag": []string{testETag}, "Content-Range": []string{"bytes 0-3/10"}}, ContentLength: 4, Body: io.NopCloser(strings.NewReader("data"))}
}

func TestExecutorCredentialIsolationAndExactGet(t *testing.T) {
	e, s, r, cli := fakeExecutor(t)
	transport, ok := e.client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || !transport.DisableKeepAlives || transport.ForceAttemptHTTP2 || transport.TLSNextProto == nil || len(transport.TLSNextProto) != 0 {
		t.Fatal("production transport permits ambient proxy, connection reuse or HTTP/2")
	}
	for key, value := range map[string]string{"AWS_ACCESS_KEY_ID": "ambient-key", "AWS_SECRET_ACCESS_KEY": "ambient-secret", "AWS_SESSION_TOKEN": "ambient-token", "AWS_ENDPOINT_URL": "http://untrusted.invalid", "HTTPS_PROXY": "http://untrusted.invalid", "AWS_CONFIG_FILE": "/untrusted/config"} {
		t.Setenv(key, value)
	}
	calls := 0
	e.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Method != http.MethodGet || !req.Close || req.URL.String() != "https://asb-test-bucket.s3.eu-west-1.amazonaws.com/read.txt" || req.Header.Get("If-Match") != testETag || req.Header.Get("Range") != "bytes=0-3" || req.Header.Get("X-Amz-Expected-Bucket-Owner") != "111122223333" {
			t.Fatal("wrong bound GET")
		}
		if !strings.Contains(req.Header.Get("Authorization"), "Credential=ASIA1111222233334444/") || req.Header.Get("X-Amz-Security-Token") != "fabricated-session-token" {
			t.Fatal("did not use isolated assumed-role credentials")
		}
		return goodResponse(), nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := e.Execute(ctx, "operation:one", r, s)
	if err != nil || result.State != lp.ExecutionSucceeded || !strings.HasPrefix(result.EvidenceDigest, "sha256:") || calls != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	env, err := os.ReadFile(cli + ".env")
	if err != nil {
		t.Fatal(err)
	}
	for _, disallowed := range []string{"ambient-key", "ambient-secret", "ambient-token", "untrusted.invalid", "/untrusted/config"} {
		if strings.Contains(string(env), disallowed) {
			t.Fatal("ambient credentials/endpoint/proxy leaked into CLI")
		}
	}
	for _, line := range strings.Split(string(env), "\n") {
		if path, ok := strings.CutPrefix(line, "AWS_SHARED_CREDENTIALS_FILE="); ok {
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("temporary credentials retained")
			}
		}
	}
	captured, err := os.ReadFile(cli + ".creds")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(captured), "unrelated") || !strings.Contains(string(captured), "[develop]") {
		t.Fatal("credential profile was not isolated")
	}
	args, err := os.ReadFile(cli + ".args")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"https://sts.eu-west-1.amazonaws.com", "arn:aws:iam::111122223333:role/asb-reader", "900", "assume-role", "NotAction", "NotResource"} {
		if !strings.Contains(string(args), expected) {
			t.Fatalf("missing bounded CLI parameter %s", expected)
		}
	}
}

func TestExecutorCredentialFilePermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0o400, 0o600, 0o640, 0o604, 0o620, 0o602} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			e, s, r, cli := fakeExecutor(t)
			// Permissions are checked at execution, including changes after construction.
			if err := os.Chmod(e.config.CredentialsFile, mode); err != nil {
				t.Fatal(err)
			}
			calls := 0
			e.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return goodResponse(), nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := e.Execute(ctx, "operation", r, s)
			if mode == 0o400 || mode == 0o600 {
				if err != nil || result.State != lp.ExecutionSucceeded || calls != 1 {
					t.Fatalf("private credentials rejected: %+v %v", result, err)
				}
				return
			}
			if !errors.Is(err, ErrProvider) || calls != 0 {
				t.Fatalf("shared credentials used: calls=%d err=%v", calls, err)
			}
			if _, err := os.Stat(cli + ".args"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("CLI invoked with shared credentials")
			}
		})
	}
}

func TestExecutorRejectsSubstitutionBeforeCredentialAcquisition(t *testing.T) {
	for name, change := range map[string]func(*lp.Request, *lp.Solution){"resource": func(r *lp.Request, _ *lp.Solution) { r.Action.Resource = extraARN }, "operation": func(r *lp.Request, _ *lp.Solution) { r.Action.Operation = "s3:PutObject" }, "profile": func(r *lp.Request, _ *lp.Solution) {
		r.Action.Arguments = []byte(strings.ReplaceAll(string(r.Action.Arguments), "sha256:", "stale:"))
	}, "owner": func(r *lp.Request, _ *lp.Solution) {
		r.Action.Arguments = []byte(strings.ReplaceAll(string(r.Action.Arguments), "111122223333", "999988887777"))
	}, "etag": func(r *lp.Request, _ *lp.Solution) {
		r.Action.Arguments = []byte(strings.ReplaceAll(string(r.Action.Arguments), "0123456789abcdef0123456789abcdef", "*"))
	}, "range": func(r *lp.Request, _ *lp.Solution) {
		r.Action.Arguments = []byte(strings.ReplaceAll(string(r.Action.Arguments), `"range_end":3`, `"range_end":1024`))
	}, "model": func(_ *lp.Request, s *lp.Solution) { s.ProblemDigest = "stale" }} {
		t.Run(name, func(t *testing.T) {
			e, s, r, cli := fakeExecutor(t)
			change(&r, &s)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := e.Execute(ctx, "operation", r, s); err == nil {
				t.Fatal("accepted substitution")
			}
			if _, err := os.Stat(cli + ".args"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("credentials acquired for rejected request")
			}
		})
	}
}

func TestResponseBoundsRedirectAndProviderFailure(t *testing.T) {
	for _, mode := range []string{"redirect", "too_large", "wrong_etag", "wrong_range", "truncated", "denied", "transport_error"} {
		t.Run(mode, func(t *testing.T) {
			e, s, r, _ := fakeExecutor(t)
			calls := 0
			e.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				response := goodResponse()
				switch mode {
				case "redirect":
					response.StatusCode = 307
					response.Header.Set("Location", "https://untrusted.invalid/object")
				case "too_large":
					response.Body = io.NopCloser(strings.NewReader("oversize"))
				case "wrong_etag":
					response.Header.Set("ETag", `"other"`)
				case "wrong_range":
					response.Header.Set("Content-Range", "bytes 1-4/10")
				case "truncated":
					response.Body = io.NopCloser(strings.NewReader("da"))
				case "denied":
					response.StatusCode = 403
				case "transport_error":
					return nil, errors.New("sensitive-provider-diagnostic")
				}
				return response, nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result, err := e.Execute(ctx, "operation", r, s)
			if mode == "denied" {
				if err != nil || result.State != lp.ExecutionFailed {
					t.Fatalf("%+v %v", result, err)
				}
			} else if !errors.Is(err, ErrProvider) || strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("provider failure did not remain bounded/redacted: %v", err)
			}
			if calls != 1 {
				t.Fatal("redirect followed or implicit retry")
			}
		})
	}
}

func TestStaticProfileAndCredentialResponseBounds(t *testing.T) {
	for _, raw := range []string{"[develop]\ncredential_process=evil", "[develop]\nrole_arn=other", "[develop]\naws_access_key_id=AKIA1111222233334444\naws_secret_access_key=x\naws_secret_access_key=y", strings.Repeat("x", (64<<10)+1)} {
		if _, err := staticProfile([]byte(raw), "develop"); err == nil {
			t.Fatal("unsupported source credentials accepted")
		}
	}
	e, s, r, cli := fakeExecutor(t)
	if err := os.WriteFile(cli, []byte("#!/bin/sh\n/usr/bin/printf '%s' 'private-diagnostic' >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := e.Execute(ctx, "operation", r, s); !errors.Is(err, ErrProvider) || strings.Contains(err.Error(), "private") {
		t.Fatal("CLI diagnostic not redacted")
	}
	var out boundedOutput
	out.limit = 8
	if _, err := out.Write([]byte("123456789")); err == nil || len(out.data) != 0 {
		t.Fatal("unbounded credential output")
	}
}

func TestPublishedS3SignatureVector(t *testing.T) {
	// AWS's public test vector, not usable credentials:
	// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html
	req, err := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Range", "bytes=0-9")
	now := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	signRequest(req, credentials{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}, "us-east-1", now)
	if !strings.HasSuffix(req.Header.Get("Authorization"), "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41") {
		t.Fatal("AWS published SigV4 vector mismatch")
	}
	for _, key := range []string{"nested/a-b_c.~txt", "a/b/c.txt"} {
		arn := "arn:aws:s3:::asb-test-bucket/" + key
		_, actual, ok := objectParts(arn)
		if !ok || actual != key {
			t.Fatal("key canonicalization changed exact object")
		}
	}
	if validContentRange("bytes 0-3/10 trailing", 0, 3) || validContentRange("bytes 0-3/*", 0, 3) {
		t.Fatal("ambiguous range response")
	}
}

func TestExpiredContextNeverAcquiresCredentials(t *testing.T) {
	e, s, r, cli := fakeExecutor(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Execute(ctx, "operation", r, s); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := e.Execute(context.Background(), "operation", r, s); !errors.Is(err, lp.ErrExpired) {
		t.Fatal(err)
	}
	if _, err := os.Stat(cli + ".args"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expired operation called CLI")
	}
}

func ExampleArguments() {
	raw, err := json.Marshal(Arguments{ProfileDigest: "sha256:trusted-profile-digest", ExpectedBucketOwner: "111122223333", IfMatch: testETag, RangeStart: 0, RangeEnd: 3})
	if err != nil {
		panic(err)
	}
	fmt.Println(string(raw))
	// Output: {"profile_digest":"sha256:trusted-profile-digest","expected_bucket_owner":"111122223333","if_match":"\"0123456789abcdef0123456789abcdef\"","range_start":0,"range_end":3}
}
