//go:build linux && awsiam_live

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package s3product

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege/asbbinding"
)

// This wall-clock lab kills an idle process after a confirmed read. It does not
// simulate loss of storage power or certify recovery of an interrupted effect.
func TestLiveProductOperations(t *testing.T) {
	if os.Getenv("ASB_AWS_LIVE_CONFIRM") != liveAWSConfirmation || os.Getenv("ASB_S3_OPERATIONS_MINUTES") == "" {
		t.Skip("operations gate requires explicit live opt-in and duration")
	}
	minutes, err := strconv.Atoi(os.Getenv("ASB_S3_OPERATIONS_MINUTES"))
	if err != nil || (minutes != 15 && minutes != 45) {
		t.Fatal("operations duration must be 15 or 45 minutes")
	}
	identity, err := user.Current()
	if err != nil || identity.Username != "asb-s3" || os.Geteuid() == 0 {
		t.Fatal("operations gate requires the dedicated unprivileged service user")
	}
	binary, reportPath := os.Getenv("ASB_S3_LIVE_BINARY"), os.Getenv("ASB_S3_OPERATIONS_REPORT")
	if !filepath.IsAbs(binary) || !filepath.IsAbs(reportPath) {
		t.Fatal("absolute binary and report paths are required")
	}
	duration := time.Duration(minutes) * time.Minute
	ctx, cancel := context.WithTimeout(t.Context(), duration+3*time.Minute)
	defer cancel()
	fixture, solution, action := loadLiveProductFixture(t, ctx)
	h := newLiveProduct(t, ctx, binary)
	h.config.ProfileFile = h.write(t, "profile.json", fixture.Specification)
	h.config.AWSCLI = fixture.CLIPath
	h.config.WebIdentityTokenFile = fixture.WebIdentityTokenFile
	var initialized lp.SQLiteStatus
	h.admin(t, &initialized, "init-store", "--directory", h.config.StoreDirectory)
	h.configure(t, initialized.Namespace, action, solution.ProblemDigest)

	const interval = 30 * time.Second
	count := int(duration/interval) + 1
	mandates := make([]lp.Mandate, count)
	operations := make([]asbbinding.Operation, count)
	for i := range count {
		mandates[i] = h.mandate
		mandates[i].ID = fmt.Sprintf("%s/mandate-%03d", initialized.Namespace, i)
		mandates[i].ExpiresAt = time.Now().Add(duration + 3*time.Minute).UTC().Truncate(time.Second)
		operations[i] = asbbinding.Operation{ID: fmt.Sprintf("%s/read-%03d", initialized.Namespace, i), MandateID: mandates[i].ID, Action: action}
	}
	h.config.MandatesFile = h.write(t, "mandates.json", liveJSON(t, mandates))
	blockedCLI := h.write(t, "disabled-aws", []byte("#!/bin/sh\nexit 91\n"))
	if err := os.Chmod(blockedCLI, 0o700); err != nil {
		t.Fatal("cannot prepare the offline receipt check")
	}
	stop := h.start(t)
	started := time.Now()
	var first, last lp.ExecutionRecord
	var capability lp.Capability
	var previousToken [32]byte
	var tokenChanges, kills int
	var maxJournalBytes, maxRSSKB int64
	var maxFDs int
	for i := range count {
		if delay := time.Until(started.Add(time.Duration(i) * interval)); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				t.Fatal("operations deadline reached")
			}
		}
		h.mandate, h.operation = mandates[i], operations[i]
		capability = h.authorize(t, solution)
		last = h.execute(t, capability)
		if i == 0 {
			first = last
		}
		// The projector atomically replaces this private token. Only changes are
		// counted; token material and its digest never enter public evidence.
		token, err := privateFile(fixture.WebIdentityTokenFile, 64<<10)
		if err != nil {
			t.Fatal("projected identity unavailable after a read")
		}
		digest := sha256.Sum256(token)
		if i > 0 && digest != previousToken {
			tokenChanges++
		}
		previousToken = digest
		var status lp.SQLiteStatus
		h.admin(t, &status, "status", "--directory", h.config.StoreDirectory)
		if status.Operations != int64(i+1) || status.Accepted != 0 || status.Uncertain != 0 {
			t.Fatal("operation history did not retain every completed read")
		}
		maxJournalBytes = max(maxJournalBytes, status.Bytes)
		rss, fds := h.checkUnprivilegedProcess(t)
		maxRSSKB, maxFDs = max(maxRSSKB, rss), max(maxFDs, fds)
		if i == 0 || i == count/2 || i == count-1 {
			h.kill()
			kills++
			h.config.AWSCLI = blockedCLI
			stop = h.start(t)
			h.checkUnprivilegedProcess(t)
			if h.execute(t, capability) != last {
				t.Fatal("forced restart changed the receipt or required AWS redispatch")
			}
			stop()
			h.config.AWSCLI = fixture.CLIPath
			stop = h.start(t)
		}
		if i%10 == 0 {
			t.Logf("completed reads=%d elapsed_seconds=%d forced_restarts=%d", i+1, int(time.Since(started).Seconds()), kills)
		}
	}
	if time.Since(started) < duration || kills != 3 || tokenChanges < 2 {
		t.Fatal("duration, forced-restart or identity-renewal coverage incomplete")
	}
	var inspected lp.ExecutionRecord
	h.admin(t, &inspected, "inspect", "--directory", h.config.StoreDirectory, "--operation", first.OperationID, "--request-digest", first.RequestDigest)
	if inspected != first {
		t.Fatal("oldest completed outcome changed during the operations run")
	}
	backupDirectory := filepath.Join(h.directory, "backups")
	if err := os.Mkdir(backupDirectory, 0o700); err != nil {
		t.Fatal("cannot prepare private backup directory")
	}
	backupPath := filepath.Join(backupDirectory, "snapshot.sqlite")
	var backup lp.SQLiteBackup
	h.admin(t, &backup, "backup", "--directory", h.config.StoreDirectory, "--output", backupPath)
	stop()
	restoredDirectory := filepath.Join(h.directory, "restored")
	var restored lp.SQLiteStatus
	h.admin(t, &restored, "restore", "--input", backupPath, "--sha256", backup.SHA256, "--directory", restoredDirectory)
	if restored.Namespace == initialized.Namespace || restored.Operations != int64(count) {
		t.Fatal("restore did not retain history and rotate authority")
	}
	for _, record := range []lp.ExecutionRecord{first, last} {
		h.admin(t, &inspected, "inspect", "--directory", restoredDirectory, "--operation", record.OperationID, "--request-digest", record.RequestDigest)
		if inspected != record {
			t.Fatal("restored history changed a retained outcome")
		}
	}
	oldOperation := h.operation
	h.config.StoreDirectory = restoredDirectory
	h.configure(t, restored.Namespace, action, solution.ProblemDigest)
	stop = h.start(t)
	h.checkUnprivilegedProcess(t)
	c := h.challenge(t, "execute", oldOperation)
	status, body, _ := h.post(t, "/execute", asbbinding.HTTPExecuteRequest{ChallengeID: c.ChallengeID, Operation: oldOperation, Proof: h.proof(t, c, oldOperation), Capability: capability})
	var denied asbbinding.HTTPResponse
	if status != http.StatusForbidden || json.Unmarshal(body, &denied) != nil || denied.Error != "authorization_denied" {
		t.Fatal("restored authority accepted the retired operation")
	}
	h.execute(t, h.authorize(t, solution))
	var finalStatus lp.SQLiteStatus
	h.admin(t, &finalStatus, "status", "--directory", restoredDirectory)
	if finalStatus.Operations != int64(count+1) || finalStatus.Accepted != 0 || finalStatus.Uncertain != 0 {
		t.Fatal("unexpected final operations history")
	}
	stop()
	report := map[string]any{
		"schema": "asb.s3-operations-evidence/v1", "os": "Linux", "dedicated_user": "asb-s3", "nonroot": true, "no_new_privileges": true, "effective_capabilities_zero": true,
		"requested_minutes": minutes, "elapsed_seconds": time.Since(started).Seconds(), "interval_seconds": int(interval.Seconds()),
		"completed_reads": count + 1, "forced_process_restarts": kills, "observed_token_changes": tokenChanges,
		"max_journal_bytes": maxJournalBytes, "max_sampled_rss_kb": maxRSSKB, "max_sampled_fds": maxFDs,
		"oldest_receipt_retained": true, "restart_receipt_without_sts": true, "sealed_backup_restore": true, "retired_authority_denied": true, "restored_authorized_read": true,
		"physical_power_loss_tested": false, "interrupted_aws_effect_tested": false, "organization_deployment_qualified": false, "long_term_qualified": false,
	}
	f, err := os.OpenFile(reportPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("cannot create operations evidence")
	}
	if _, err = f.Write(liveJSON(t, report)); err != nil {
		_ = f.Close()
		t.Fatal("cannot save operations evidence")
	}
	if err = f.Close(); err != nil {
		t.Fatal("cannot close operations evidence")
	}
	t.Logf("operations gate passed: reads=%d forced_restarts=%d identity_changes=%d", count+1, kills, tokenChanges)
}

func (h *liveProduct) checkUnprivilegedProcess(t *testing.T) (int64, int) {
	t.Helper()
	directory := fmt.Sprintf("/proc/%d", h.pid)
	raw, err := os.ReadFile(filepath.Join(directory, "status"))
	if err != nil {
		t.Fatal("cannot inspect service identity")
	}
	fields := make(map[string][]string)
	for line := range strings.SplitSeq(string(raw), "\n") {
		parts := strings.Fields(line)
		if len(parts) > 1 {
			fields[parts[0]] = parts[1:]
		}
	}
	uid, caps, privileges, rss := fields["Uid:"], fields["CapEff:"], fields["NoNewPrivs:"], fields["VmRSS:"]
	if len(uid) != 4 || len(caps) != 1 || caps[0] != "0000000000000000" || len(privileges) != 1 || privileges[0] != "1" || len(rss) != 2 || rss[1] != "kB" {
		t.Fatal("service privilege or memory evidence unavailable")
	}
	for _, value := range uid {
		if value != strconv.Itoa(os.Geteuid()) || value == "0" {
			t.Fatal("service did not retain the dedicated unprivileged identity")
		}
	}
	resident, err := strconv.ParseInt(rss[0], 10, 64)
	if err != nil || resident <= 0 {
		t.Fatal("invalid resident memory sample")
	}
	fds, err := os.ReadDir(filepath.Join(directory, "fd"))
	if err != nil {
		t.Fatal("cannot sample service descriptors")
	}
	return resident, len(fds)
}
