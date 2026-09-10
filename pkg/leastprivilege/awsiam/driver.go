// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package awsiam

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

type credentials struct {
	AccessKey, SecretKey, Token string
	Expiration                  time.Time
}

var keyPatternAWS = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)

func safeCredential(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

// staticProfile extracts only three static keys from the explicitly named
// profile. Nothing here discovers ~/.aws, source_profile or credential_process.
func staticProfile(raw []byte, profile string) ([]byte, error) {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return nil, ErrProvider
	}
	section := ""
	found := false
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, ErrProvider
			}
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section == profile {
				if found {
					return nil, ErrProvider
				}
				found = true
			}
			continue
		}
		if section != profile {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || (key != "aws_access_key_id" && key != "aws_secret_access_key" && key != "aws_session_token") || values[key] != "" || !safeCredential(value, 16384) {
			return nil, ErrProvider
		}
		values[key] = value
	}
	if !found || !keyPatternAWS.MatchString(values["aws_access_key_id"]) || !safeCredential(values["aws_secret_access_key"], 128) {
		return nil, ErrProvider
	}
	text := "[" + profile + "]\naws_access_key_id=" + values["aws_access_key_id"] + "\naws_secret_access_key=" + values["aws_secret_access_key"] + "\n"
	if token := values["aws_session_token"]; token != "" {
		text += "aws_session_token=" + token + "\n"
	}
	return []byte(text), nil
}

type boundedOutput struct {
	data  []byte
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-len(b.data) {
		return 0, ErrProvider
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func (e *Executor) assume(ctx context.Context, id string, policy []byte) (credentials, error) {
	f, err := os.Open(e.config.CredentialsFile)
	if err != nil {
		return credentials{}, ErrProvider
	}
	info, statErr := f.Stat()
	if statErr != nil || !info.Mode().IsRegular() {
		f.Close()
		return credentials{}, ErrProvider
	}
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	f.Close()
	if err != nil {
		return credentials{}, ErrProvider
	}
	defer clear(raw)
	static, err := staticProfile(raw, e.profile.spec.CredentialProfile)
	if err != nil {
		return credentials{}, err
	}
	defer clear(static)
	dir, err := os.MkdirTemp("", "asb-aws-session-")
	if err != nil {
		return credentials{}, ErrProvider
	}
	defer os.RemoveAll(dir)
	credentialFile := filepath.Join(dir, "credentials")
	configFile := filepath.Join(dir, "config")
	if err := os.WriteFile(credentialFile, static, 0o600); err != nil {
		return credentials{}, ErrProvider
	}
	if err := os.WriteFile(configFile, []byte{}, 0o600); err != nil {
		return credentials{}, ErrProvider
	}
	hash := sha256.Sum256([]byte(id))
	name := "asb-" + hex.EncodeToString(hash[:16])
	args := []string{"--profile", e.profile.spec.CredentialProfile, "--region", e.profile.spec.Region, "--endpoint-url", "https://sts." + e.profile.spec.Region + ".amazonaws.com", "--output", "json", "--no-cli-pager", "--no-cli-auto-prompt", "sts", "assume-role", "--role-arn", e.profile.spec.RoleARN, "--role-session-name", name, "--duration-seconds", "900", "--policy", string(policy), "--query", "Credentials"}
	cmd := exec.CommandContext(ctx, e.config.Path, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "AWS_CONFIG_FILE=" + configFile, "AWS_SHARED_CREDENTIALS_FILE=" + credentialFile, "AWS_EC2_METADATA_DISABLED=true", "AWS_STS_REGIONAL_ENDPOINTS=regional", "AWS_MAX_ATTEMPTS=1", "AWS_PAGER=", "AWS_CLI_AUTO_PROMPT=off"}
	cmd.Dir = dir
	cmd.WaitDelay = time.Second
	output := &boundedOutput{limit: 64 << 10}
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		clear(output.data)
		if ctx.Err() != nil {
			return credentials{}, ctx.Err()
		}
		return credentials{}, ErrProvider
	}
	defer clear(output.data)
	var response struct {
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		SessionToken    string `json:"SessionToken"`
		Expiration      string `json:"Expiration"`
	}
	if err := strictJSON(output.data, &response, 64<<10); err != nil {
		return credentials{}, ErrProvider
	}
	expiry, err := time.Parse(time.RFC3339, response.Expiration)
	if err != nil || !e.clock().Before(expiry) || expiry.After(e.clock().Add(17*time.Minute)) || !strings.HasPrefix(response.AccessKeyID, "ASIA") || !keyPatternAWS.MatchString(response.AccessKeyID) || !safeCredential(response.SecretAccessKey, 128) || !safeCredential(response.SessionToken, 16384) {
		return credentials{}, ErrProvider
	}
	return credentials{response.AccessKeyID, response.SecretAccessKey, response.SessionToken, expiry}, nil
}

// signRequest implements only the no-query S3 GET used by this profile. Keys
// are already restricted to unreserved ASCII and slash, so escaping is exact.
func signRequest(req *http.Request, c credentials, region string, now time.Time) {
	payload := sha256.Sum256(nil)
	req.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(payload[:]))
	req.Header.Set("X-Amz-Date", now.UTC().Format("20060102T150405Z"))
	if c.Token != "" {
		req.Header.Set("X-Amz-Security-Token", c.Token)
	}
	names := []string{"host"}
	for name := range req.Header {
		names = append(names, strings.ToLower(name))
	}
	slices.Sort(names)
	var headers strings.Builder
	for _, name := range names {
		value := req.Header.Get(name)
		if name == "host" {
			value = req.URL.Host
		}
		headers.WriteString(name + ":" + strings.Join(strings.Fields(value), " ") + "\n")
	}
	signed := strings.Join(names, ";")
	canonical := strings.Join([]string{http.MethodGet, req.URL.EscapedPath(), "", headers.String(), signed, hex.EncodeToString(payload[:])}, "\n")
	hash := sha256.Sum256([]byte(canonical))
	day := now.UTC().Format("20060102")
	scope := day + "/" + region + "/s3/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + now.UTC().Format("20060102T150405Z") + "\n" + scope + "\n" + hex.EncodeToString(hash[:])
	key := mac([]byte("AWS4"+c.SecretKey), day)
	key = mac(key, region)
	key = mac(key, "s3")
	key = mac(key, "aws4_request")
	signature := hex.EncodeToString(mac(key, toSign))
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", c.AccessKey, scope, signed, signature))
}

func mac(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = io.Copy(h, bytes.NewBufferString(value))
	return h.Sum(nil)
}
