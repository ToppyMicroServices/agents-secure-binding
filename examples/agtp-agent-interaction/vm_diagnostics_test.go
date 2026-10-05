// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/production"
)

func TestVMFailureDiagnosticsExcludeErrorPayloads(t *testing.T) {
	for _, fixture := range []struct {
		err      error
		category string
	}{
		{syscall.EADDRNOTAVAIL, "address-not-available"},
		{syscall.EADDRINUSE, "address-in-use"},
		{os.ErrPermission, "permission"},
		{production.ErrInvalidAuthority, "invalid-authority"},
		{errors.New("private-unreported-token"), "other"},
	} {
		err := fmt.Errorf("private-unreported-token: %w", fixture.err)
		record := vmStopped(roleAgentB, vmStageTaskServer, err)
		if record.Passed || record.Category != fixture.category || record.Stage != vmStageTaskServer {
			t.Fatal("failure diagnostic lost its fixed stage or category")
		}
		raw, marshalErr := json.Marshal(record)
		if marshalErr != nil || strings.Contains(string(raw), "private-unreported-token") {
			t.Fatal("failure diagnostic exposed private error text")
		}
	}
	passed := vmStopped(roleAgentB, vmStageControl, nil)
	if !passed.Passed || passed.Category != "none" {
		t.Fatal("successful service drain did not retain its status")
	}
}
