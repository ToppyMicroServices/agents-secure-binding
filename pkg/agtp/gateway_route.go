// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package agtp

import (
	"fmt"
	"strings"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/gatewayroute"
)

func validateGatewayRouteCore(a gatewayroute.Assertion) error {
	if a.Type != gatewayroute.AssertionType {
		return ErrInvalidTokenType
	}
	if a.Version != gatewayroute.AssertionVersion {
		return ErrUnsupportedVersion
	}
	if strings.TrimSpace(a.ID) == "" {
		return ErrMissingJWTID
	}
	return nil
}

func validateGatewayRouteAcceptance(a gatewayroute.Assertion, grantHash, gatewaySessionBindingSHA256, holderProofSHA256 string, requireHolderProof bool) error {
	for _, f := range []struct {
		name string
		want string
		got  string
	}{
		{gatewayroute.FieldGrantHash, grantHash, a.GrantHash},
		{gatewayroute.FieldGatewaySessionBindingSHA256, gatewaySessionBindingSHA256, a.GatewaySessionBindingSHA256},
	} {
		if strings.TrimSpace(f.want) == "" {
			return fmt.Errorf("%s: %w", f.name, gatewayroute.ErrMissingExpected)
		}
		if f.want != f.got {
			return fmt.Errorf("%s: %w", f.name, gatewayroute.ErrMismatch)
		}
	}
	if requireHolderProof {
		if strings.TrimSpace(holderProofSHA256) == "" {
			return fmt.Errorf("%s: %w", gatewayroute.FieldAgentHOKProofSHA256, gatewayroute.ErrMissingExpected)
		}
		if holderProofSHA256 != a.AgentHolderOfKeyProofSHA256 {
			return fmt.Errorf("%s: %w", gatewayroute.FieldAgentHOKProofSHA256, gatewayroute.ErrMismatch)
		}
	}
	return nil
}

func routeOptionsWithNow(routeOpts gatewayroute.Options, now time.Time) gatewayroute.Options {
	if routeOpts.Now.IsZero() {
		routeOpts.Now = now
	}
	return routeOpts
}
