// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/thinksyncs/agents-secure-binding/pkg/clients"
)

func runManager(ctx context.Context, opts options, out outputWriter) error {
	key, err := loadPrivateKey(filepath.Join(roleDirectory(opts.stateDir, "manager"), signingKeyFile))
	if err != nil {
		return fmt.Errorf("load Manager signing key: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, "application/json", map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /grants", func(w http.ResponseWriter, r *http.Request) {
		if err := requirePeer(r, demoAgentIssuer); err != nil {
			writeProblem(w, http.StatusForbidden, "client-identity", "Client identity rejected", err.Error())
			return
		}
		var request grantRequest
		if !decodeJSON(w, r, &request) {
			return
		}
		if request.TaskID != demoTaskID || request.ContextID != demoContextID {
			writeProblem(w, http.StatusForbidden, "policy-mismatch", "Grant policy rejected", "task or context is outside Manager policy")
			return
		}
		now := time.Now().UTC().Truncate(time.Second)
		id, err := randomID("grant-")
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal", "Grant issuance failed", "identifier generation failed")
			return
		}
		token, err := signJWT(demoManagerKeyID, key, jwt.MapClaims{
			"iss": demoManagerIssuer, "sub": demoAgentIssuer, "aud": demoAudience,
			"jti": id, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
			"profile_type": clients.TokenTypeIdentityGrant, "profile_version": clients.ProfileVersion,
			"cnf":     map[string]any{"kid": demoAgentKeyID},
			"service": demoService, "deployment": demoDeployment, "workload": demoWorkload,
			"agent": demoAgentIssuer, "task_id": demoTaskID, "intent_ref": demoIntent,
			"capability_ref": demoCapability, "scope": demoReadScope, "resource": demoResource,
		})
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal", "Grant issuance failed", "signing failed")
			return
		}
		writeJSON(w, http.StatusOK, "application/json", grantResponse{IdentityGrant: token})
	})
	return serveTLS(ctx, opts, "manager", tls.RequireAndVerifyClientCert, mux, out)
}
