//go:build linux && awsiam_live

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package s3product

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
)

// The real issuer's original token is first accepted, then allowed to expire.
// Its unverified exp claim schedules the wait; AWS's diagnostic proves denial.
func TestLiveSystemdIdentityRecovery(t *testing.T) {
	if os.Getenv("ASB_AWS_LIVE_CONFIRM") != liveAWSConfirmation || os.Getenv("ASB_S3_SYSTEMD_LIVE") != "1" {
		t.Skip("explicit live fixture and disposable systemd runner required")
	}
	if os.Geteuid() != 0 || os.Getenv("TMPDIR") != "/var/lib/asb-s3/qa" {
		t.Fatal("isolated root harness and private state fixtures required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 16*time.Minute)
	defer cancel()
	fixture, solution, action := loadLiveProductFixture(t, ctx)
	token, err := privateFile(fixture.WebIdentityTokenFile, 64<<10)
	if err != nil {
		t.Fatal("projected identity unavailable")
	}
	parts := strings.Split(strings.TrimSpace(string(token)), ".")
	var claims struct {
		Expires int64 `json:"exp"`
	}
	if len(parts) != 3 {
		t.Fatal("identity format unavailable")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(raw, &claims) != nil {
		t.Fatal("identity expiry unavailable")
	}
	expires := time.Unix(claims.Expires, 0)
	if time.Until(expires) < time.Minute || time.Until(expires) > 12*time.Minute {
		t.Fatal("identity lifetime is outside this bounded qualification window")
	}
	h := newLiveProduct(t, ctx, os.Getenv("ASB_S3_LIVE_BINARY"))
	h.config.ProfileFile = h.write(t, "profile.json", fixture.Specification)
	h.config.AWSCLI, h.config.WebIdentityTokenFile = fixture.CLIPath, fixture.WebIdentityTokenFile
	var initial lp.SQLiteStatus
	h.admin(t, &initial, "init-store", "--directory", h.config.StoreDirectory)
	h.configure(t, initial.Namespace, action, solution.ProblemDigest)
	mandates := []lp.Mandate{h.mandate, h.mandate, h.mandate}
	for i := range mandates {
		mandates[i].ID += "-" + strconv.Itoa(i)
		mandates[i].ExpiresAt = time.Now().Add(20 * time.Minute).UTC().Truncate(time.Second)
	}
	h.config.MandatesFile = h.write(t, "mandates.json", liveJSON(t, mandates))
	if err := os.WriteFile("/etc/asb-s3/config.json", liveJSON(t, h.config), 0o600); err != nil {
		t.Fatal("cannot install private service configuration")
	}
	if err := exec.CommandContext(ctx, "chown", "-R", "asb-s3:asb-s3", "/var/lib/asb-s3", "/etc/asb-s3").Run(); err != nil {
		t.Fatal("cannot set dedicated service ownership")
	}
	h.transport = &http.Transport{TLSClientConfig: h.clientTLS.Clone(), MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, ForceAttemptHTTP2: false}
	h.client = &http.Client{Transport: h.transport, Timeout: 40 * time.Second}
	t.Cleanup(h.transport.CloseIdleConnections)
	systemctl(t, "daemon-reload")
	cleanupSystemdUnit(t, "asb-s3.service")
	systemctl(t, "enable", "--now", "asb-s3.service")
	waitProduct(t, h)
	pid := systemctl(t, "show", "asb-s3.service", "--property=MainPID", "--value")
	if pid == "0" || systemctl(t, "is-enabled", "asb-s3.service") != "enabled" {
		t.Fatal("installed service is not enabled and running")
	}
	assertLiveServiceIdentity(t, pid)
	selectOperation := func(i int) {
		h.mandate = mandates[i]
		h.operation.ID = initial.Namespace + "/read-" + strconv.Itoa(i)
		h.operation.MandateID = mandates[i].ID
	}
	selectOperation(0)
	first := h.execute(t, h.authorize(t, solution))
	t.Log("installed systemd service completed its first authorized AWS read")
	timer := time.NewTimer(time.Until(expires.Add(90 * time.Second)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal("identity expiry deadline exceeded")
	case <-timer.C:
	}
	selectOperation(1)
	capability := h.authorize(t, solution)
	if status := <-executeAsync(t, h, capability); status != http.StatusConflict {
		t.Fatal("expired identity did not leave an uncertain operation")
	}
	code := liveExpiryDiagnostic(t, ctx, h.operation.ID)
	var before lp.SQLiteStatus
	h.admin(t, &before, "status", "--directory", h.config.StoreDirectory)
	if before.Operations != 2 || before.Uncertain != 1 || before.Accepted != 0 {
		t.Fatal("expired identity did not preserve consumed authority")
	}
	// This marker contains no identity material. The trusted runner projects a
	// fresh token atomically, then acknowledges via a separate private marker.
	if err := os.WriteFile("/var/lib/asb-s3/renew-request", []byte("renew\n"), 0o600); err != nil {
		t.Fatal("cannot request runner identity renewal")
	}
	deadline := time.Now().Add(time.Minute)
	for {
		if _, err := os.Stat("/var/lib/asb-s3/renew-ready"); err == nil {
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			t.Fatal("runner identity renewal deadline exceeded")
		}
		time.Sleep(100 * time.Millisecond)
	}
	renewed, err := privateFile(fixture.WebIdentityTokenFile, 64<<10)
	if err != nil || sha256.Sum256(renewed) == sha256.Sum256(token) {
		t.Fatal("runner did not replace the projected identity")
	}
	// Renewal never clears UNKNOWN or permits replay of its consumed authority.
	if status := <-executeAsync(t, h, capability); status != http.StatusConflict {
		t.Fatal("renewal changed the old operation's uncertainty")
	}
	selectOperation(2)
	h.execute(t, h.authorize(t, solution))
	if systemctl(t, "show", "asb-s3.service", "--property=MainPID", "--value") != pid {
		t.Fatal("identity recovery restarted the service")
	}
	assertLiveServiceIdentity(t, pid)
	var final lp.SQLiteStatus
	h.admin(t, &final, "status", "--directory", h.config.StoreDirectory)
	if final.Operations != 3 || final.Uncertain != 1 || final.Accepted != 0 {
		t.Fatal("recovered service lost execution history")
	}
	var retained lp.ExecutionRecord
	h.admin(t, &retained, "inspect", "--directory", h.config.StoreDirectory, "--operation", first.OperationID, "--request-digest", first.RequestDigest)
	if retained != first {
		t.Fatal("first receipt changed across identity expiry")
	}
	systemctl(t, "stop", "asb-s3.service")
	if systemctl(t, "show", "asb-s3.service", "--property=MainPID", "--value") != "0" {
		t.Fatal("installed service did not stop")
	}
	report := map[string]any{
		"schema": "asb.s3-systemd-live-evidence/v1", "os": "Linux", "installed_unit": true,
		"nonroot": true, "no_new_privileges": true, "effective_capabilities_zero": true,
		"initial_authorized_read": true, "aws_expiry_code": code, "natural_expiry_denied": true,
		"atomic_identity_renewal": true, "same_process_recovered": true, "renewed_authorized_read": true,
		"old_operation_conflict": true, "uncertain_records": final.Uncertain, "completed_reads": 2,
		"first_receipt_retained": true, "service_stopped": true,
		"organization_deployment_qualified": false, "physical_power_loss_tested": false,
	}
	if err := os.WriteFile("/var/lib/asb-s3/systemd-result.json", liveJSON(t, report), 0o600); err != nil {
		t.Fatal("cannot save bounded systemd evidence")
	}
	t.Log("real AWS expiry denied; renewed identity enabled a new read without restart; UNKNOWN and prior receipt retained")
}

func assertLiveServiceIdentity(t *testing.T, pid string) {
	t.Helper()
	if _, err := strconv.Atoi(pid); err != nil {
		t.Fatal("invalid service PID")
	}
	identity, err := user.Lookup("asb-s3")
	if err != nil || identity.Uid == "" || identity.Uid == "0" {
		t.Fatal("dedicated service UID unavailable")
	}
	uid := identity.Uid
	raw, err := os.ReadFile(filepath.Join("/proc", pid, "status"))
	if err != nil {
		t.Fatal("service identity unavailable")
	}
	fields := make(map[string][]string)
	for line := range strings.SplitSeq(string(raw), "\n") {
		parts := strings.Fields(line)
		if len(parts) > 1 {
			fields[parts[0]] = parts[1:]
		}
	}
	if strings.Join(fields["Uid:"], ",") != strings.Join([]string{uid, uid, uid, uid}, ",") ||
		strings.Join(fields["NoNewPrivs:"], "") != "1" || strings.Join(fields["CapEff:"], "") != "0000000000000000" {
		t.Fatal("service did not retain its unprivileged identity")
	}
}

func liveExpiryDiagnostic(t *testing.T, ctx context.Context, operation string) string {
	t.Helper()
	hash := sha256.Sum256([]byte(operation))
	correlation := hex.EncodeToString(hash[:16])
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for deadline.Err() == nil {
		raw, err := exec.CommandContext(deadline, "journalctl", "--namespace=asb-s3", "--unit=asb-s3.service", "--no-pager", "--output=cat", "--lines=32").Output()
		if err != nil || len(raw) > 64<<10 {
			t.Fatal("bounded service diagnostics unavailable")
		}
		for _, line := range strings.Split(string(raw), "\n") {
			var event diagnosticEvent
			if json.Unmarshal([]byte(line), &event) == nil && event.Stage == "sts" && event.Correlation == correlation &&
				(event.Code == "ExpiredToken" || event.Code == "InvalidIdentityToken (token_expired)") {
				return event.Code
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("AWS did not confirm identity expiry with a recognized diagnostic")
	return ""
}
