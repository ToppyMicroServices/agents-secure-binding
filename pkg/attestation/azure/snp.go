// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/errors"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/vtpm"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"google.golang.org/protobuf/proto"
)

// TokenValidator defines the interface for Azure token validation.
type TokenValidator interface {
	Validate(token string) (map[string]any, error)
}

type azureTokenValidator struct{}

func (v *azureTokenValidator) Validate(token string) (map[string]any, error) {
	return validateToken(token)
}

var (
	MaaURL              = "https://sharedeus2.eus2.attest.azure.net"
	ErrFetchAzureToken  = errors.New("failed to fetch Azure token")
	ErrAzureMAADisabled = errors.New("Azure MAA runtime fetch is disabled")
)

var DefaultValidator TokenValidator = &azureTokenValidator{}

var (
	_ attestation.Provider = (*provider)(nil)
	_ attestation.Verifier = (*verifier)(nil)
)

type provider struct{}

func NewProvider() attestation.Provider {
	return provider{}
}

func (a provider) Attestation(teeNonce []byte, vTpmNonce []byte) ([]byte, error) {
	return nil, ErrAzureMAADisabled
}

func (a provider) TeeAttestation(teeNonce []byte) ([]byte, error) {
	return nil, ErrAzureMAADisabled
}

func (a provider) VTpmAttestation(vTpmNonce []byte) ([]byte, error) {
	quote, err := vtpm.FetchQuote(vTpmNonce)
	if err != nil {
		return []byte{}, errors.Wrap(vtpm.ErrFetchQuote, err)
	}

	return proto.Marshal(quote)
}

type MaaClient interface {
	Attest(ctx context.Context, nonce []byte, maaURL string, client *http.Client) (string, error)
}

type defaultMaaClient struct{}

func (c *defaultMaaClient) Attest(ctx context.Context, nonce []byte, maaURL string, client *http.Client) (string, error) {
	return "", ErrAzureMAADisabled
}

var DefaultMaaClient MaaClient = &defaultMaaClient{}

func (a provider) AzureAttestationToken(tokenNonce []byte) ([]byte, error) {
	token, err := DefaultMaaClient.Attest(context.Background(), tokenNonce, MaaURL, http.DefaultClient)
	if err != nil {
		return nil, errors.Wrap(ErrFetchAzureToken, err)
	}

	return []byte(token), nil
}

type verifier struct {
	writer io.Writer
}

func NewVerifier(writer io.Writer) attestation.Verifier {
	return verifier{
		writer: writer,
	}
}

func (v verifier) VerifyWithCoRIM(report []byte, manifest *corim.UnsignedCorim) error {
	attestation := &attest.Attestation{}
	if err := proto.Unmarshal(report, attestation); err != nil {
		return fmt.Errorf("failed to unmarshal attestation report: %w", err)
	}

	// Extract measurement from SEV-SNP report if present
	snpRep := attestation.GetSevSnpAttestation()
	if snpRep == nil {
		return fmt.Errorf("no SEV-SNP attestation found in report")
	}

	measurement := snpRep.GetReport().GetMeasurement()
	if len(measurement) == 0 {
		return fmt.Errorf("no measurement in SEV-SNP report")
	}

	// Parse CoMID from CoRIM
	if len(manifest.Tags) == 0 {
		return fmt.Errorf("no tags in CoRIM")
	}

	for _, tag := range manifest.Tags {
		if !bytes.HasPrefix(tag, corim.ComidTag) {
			continue
		}

		tagValue := tag[len(corim.ComidTag):]

		var c comid.Comid
		if err := c.FromCBOR(tagValue); err != nil {
			return fmt.Errorf("failed to parse CoMID: %w", err)
		}

		// Match measurements
		if c.Triples.ReferenceValues != nil {
			for _, rv := range *c.Triples.ReferenceValues {
				if err := rv.Valid(); err != nil {
					continue
				}
				for _, m := range rv.Measurements {
					if m.Val.Digests == nil {
						continue
					}
					for _, digest := range *m.Val.Digests {
						if string(digest.HashValue) == string(measurement) {
							return nil // Match found
						}
					}
				}
			}
		}
	}

	return fmt.Errorf("no matching reference value found in CoRIM for Azure SEV-SNP")
}

func FetchAzureAttestationToken(tokenNonce []byte, maaURL string) ([]byte, error) {
	token, err := DefaultMaaClient.Attest(context.Background(), tokenNonce, maaURL, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("error fetching azure token: %w", err)
	}
	return []byte(token), nil
}

// AzureMeasurementData contains the exact fields extracted from an Azure attestation token
// needed to construct a CoRIM policy for the SNP platform.
type AzureMeasurementData struct {
	Measurement string
	HostData    string
	Policy      uint64
	SVN         uint64
}

// ExtractAzureMeasurement extracts the core SNP measurements from an Azure Attestation Token.
func ExtractAzureMeasurement(token string) (*AzureMeasurementData, error) {
	claims, err := DefaultValidator.Validate(token)
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	tee, ok := claims["x-ms-isolation-tee"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("failed to get tee from claims")
	}

	measurementString, ok := tee["x-ms-sevsnpvm-launchmeasurement"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to get measurement from claims")
	}

	hostDataString, ok := tee["x-ms-sevsnpvm-hostdata"].(string)
	if !ok {
		// Host data is optional
		hostDataString = ""
	}

	guestSVNFloat, ok := tee["x-ms-sevsnpvm-guestsvn"].(float64)
	if !ok {
		return nil, fmt.Errorf("failed to get guest SVN from claims")
	}

	// We default the SNP policy to 0 if not provided, though typically Azure sets this
	// in x-ms-sevsnpvm-policy based on the guest. For now, we will return 0 and rely on
	// callers to provide the policy if they want to override.

	return &AzureMeasurementData{
		Measurement: measurementString,
		HostData:    hostDataString,
		SVN:         uint64(guestSVNFloat),
		Policy:      0, // The policy is usually passed externally in Azure's case, or decoded separately
	}, nil
}

func validateToken(token string) (map[string]any, error) {
	unverifiedToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	jku, jkuOk := unverifiedToken.Header["jku"].(string)
	if !jkuOk {
		return nil, fmt.Errorf("token is missing jku or kid in header")
	}
	if _, kidOk := unverifiedToken.Header["kid"].(string); !kidOk {
		return nil, fmt.Errorf("token is missing jku or kid in header")
	}
	if _, err := validateJKU(jku, MaaURL); err != nil {
		return nil, err
	}

	keySet, err := fetchJWKSet(context.Background(), jku, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get key set: %w", err)
	}

	claims := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	parsed, err := parser.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("token is missing kid in header")
		}
		keys := keySet.Key(kid)
		if len(keys) == 0 {
			return nil, fmt.Errorf("no key found for kid %q", kid)
		}
		return keys[0].Key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}
	if !parsed.Valid {
		return nil, fmt.Errorf("failed to validate token")
	}

	return claims, nil
}

func fetchJWKSet(ctx context.Context, jku string, client *http.Client) (*jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jku, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected key set status: %s", resp.Status)
	}

	var keySet jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&keySet); err != nil {
		return nil, err
	}
	return &keySet, nil
}

func validateJKU(jku, configuredMaaURL string) (string, error) {
	jkuURL, err := url.Parse(jku)
	if err != nil {
		return "", fmt.Errorf("invalid jku URL: %w", err)
	}
	if jkuURL.Scheme != "https" {
		return "", fmt.Errorf("jku must use https")
	}
	if jkuURL.Hostname() == "" || jkuURL.User != nil || jkuURL.RawQuery != "" || jkuURL.Fragment != "" {
		return "", fmt.Errorf("jku must be a clean absolute https URL without userinfo, query, or fragment")
	}
	if jkuURL.Path != "/certs" {
		return "", fmt.Errorf("jku path must be /certs")
	}

	// If MaaURL is explicitly configured, require host pinning to the same endpoint.
	if configuredMaaURL != "" {
		maaURL, err := url.Parse(configuredMaaURL)
		if err != nil {
			return "", fmt.Errorf("invalid configured MAA URL: %w", err)
		}
		if maaURL.Scheme != "https" || maaURL.Hostname() == "" {
			return "", fmt.Errorf("configured MAA URL must be an absolute https URL")
		}
		if !strings.EqualFold(jkuURL.Hostname(), maaURL.Hostname()) || jkuURL.Port() != maaURL.Port() {
			return "", fmt.Errorf("jku host %q does not match configured MAA host %q", jkuURL.Host, maaURL.Host)
		}
		return configuredMaaURL, nil
	}

	// When MaaURL is not configured, accept only official Azure attestation hosts.
	if !strings.HasSuffix(strings.ToLower(jkuURL.Hostname()), ".attest.azure.net") {
		return "", fmt.Errorf("jku host is not an allowed Azure attestation domain")
	}

	return (&url.URL{Scheme: jkuURL.Scheme, Host: jkuURL.Host}).String(), nil
}
