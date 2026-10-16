// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAzureTokenCollectionRejectsEmptySuccess(t *testing.T) {
	originalClient := DefaultMaaClient
	t.Cleanup(func() { DefaultMaaClient = originalClient })
	providerError := errors.New("MAA unavailable")
	collectors := []struct {
		name  string
		fetch func([]byte) ([]byte, error)
	}{
		{name: "provider", fetch: NewProvider().AzureAttestationToken},
		{name: "helper", fetch: func(nonce []byte) ([]byte, error) {
			return FetchAzureAttestationToken(nonce, "https://example.invalid")
		}},
	}
	cases := []struct {
		name  string
		token string
		err   error
	}{
		{name: "empty success"},
		{name: "nonempty token", token: "unchanged-token"},
		{name: "provider error", err: providerError},
		{name: "partial token with error", token: "partial-token", err: providerError},
	}
	for _, collector := range collectors {
		t.Run(collector.name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					DefaultMaaClient = &mockMaaClient{attestFunc: func(context.Context, []byte, string, *http.Client) (string, error) {
						return tc.token, tc.err
					}}
					token, err := collector.fetch(testNonce)
					switch {
					case tc.err != nil:
						require.ErrorIs(t, err, tc.err)
						require.Nil(t, token)
					case tc.token == "":
						require.ErrorContains(t, err, "empty token")
						require.Nil(t, token)
					default:
						require.NoError(t, err)
						require.Equal(t, []byte(tc.token), token)
					}
				})
			}
		})
	}
}
