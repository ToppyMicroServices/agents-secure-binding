// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/integrations/cocos/platformmodule"
	qemu "github.com/ToppyMicroServices/agents-secure-binding/v2/manager/qemu"
	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/eat"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/tdx"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/vtpm"
	sevsnppb "github.com/google/go-sev-guest/proto/sevsnp"
	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	"google.golang.org/protobuf/proto"
)

const (
	platformSNP    = "snp"
	platformTDX    = "tdx"
	reportDataSize = 64
)

var errChallengeMismatch = errors.New("attestation evidence is not bound to verifier challenge")

type runOptions struct {
	Platform                string
	VMPL                    uint
	ExpectedHostDataHex     string
	RequireKernelHashes     bool
	KernelHashesEvidence    bool
	EvidenceDir             string
	CoRIMPolicyPath         string
	PlatformPolicyPath      string
	CoRIMPublicKeyPath      string
	EATIssuer               string
	RequireFullVerification bool
}

type extractedEvidence struct {
	ReportData []byte
	HostData   []byte
}

type runSummary struct {
	TimestampUTC           string `json:"timestamp_utc"`
	Platform               string `json:"platform"`
	EvidenceASHA256        string `json:"evidence_a_sha256"`
	EvidenceBSHA256        string `json:"evidence_b_sha256"`
	ChallengeASHA256       string `json:"challenge_a_sha256"`
	ChallengeBSHA256       string `json:"challenge_b_sha256"`
	HostDataSHA256         string `json:"host_data_sha256,omitempty"`
	AppraisalContractCheck bool   `json:"appraisal_contract_check"`
	FullModuleVerification bool   `json:"full_module_verification"`
	EATPublicKeySHA256     string `json:"eat_public_key_sha256,omitempty"`
}

func main() {
	opts := runOptions{}
	flag.StringVar(&opts.Platform, "platform", platformSNP, "attestation platform: snp or tdx")
	flag.UintVar(&opts.VMPL, "vmpl", 0, "SEV-SNP VM privilege level")
	flag.StringVar(&opts.ExpectedHostDataHex, "expected-host-data-hex", "", "expected SEV-SNP HostData as hex")
	flag.BoolVar(&opts.RequireKernelHashes, "require-kernel-hashes", false, "require external evidence that kernel-hashes=on was used")
	flag.BoolVar(&opts.KernelHashesEvidence, "kernel-hashes-evidence", false, "runner-provided evidence that kernel-hashes=on was used")
	flag.StringVar(&opts.EvidenceDir, "evidence-dir", "", "directory for non-sensitive evidence fingerprints")
	flag.StringVar(&opts.CoRIMPolicyPath, "corim-policy", "", "path to the local CoRIM reference-value policy")
	flag.StringVar(&opts.PlatformPolicyPath, "platform-policy", "", "path to the go-sev/go-tdx verification policy JSON")
	flag.StringVar(&opts.CoRIMPublicKeyPath, "corim-public-key", "", "optional P-256 public key for a signed CoRIM")
	flag.StringVar(&opts.EATIssuer, "eat-issuer", "hardware-attestation-qualification", "expected issuer for the in-process signed EAT fixture")
	flag.BoolVar(&opts.RequireFullVerification, "require-full-verification", false, "fail unless the complete signed-EAT and platform verifier path succeeds")
	flag.Parse()

	summary, err := run(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hardware attestation red-team failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf(
		"hardware attestation red-team passed: platform=%s evidence_a_sha256=%s evidence_b_sha256=%s\n",
		summary.Platform,
		summary.EvidenceASHA256,
		summary.EvidenceBSHA256,
	)
}

func run(opts runOptions) (*runSummary, error) {
	platform, err := resolvePlatform(opts.Platform)
	if err != nil {
		return nil, err
	}

	switch platform {
	case platformSNP:
		return runSEVSNP(platform, opts)
	case platformTDX:
		if opts.ExpectedHostDataHex != "" || opts.RequireKernelHashes {
			return nil, fmt.Errorf("HostData and kernel-hashes appraisal is only defined for SEV-SNP")
		}
		return exerciseTEE(platform, tdx.NewProvider().TeeAttestation, extractTDXEvidence, opts)
	default:
		return nil, fmt.Errorf("unsupported attestation platform %q", platform)
	}
}

func resolvePlatform(requested string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(requested))
	switch normalized {
	case platformSNP, platformTDX:
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported attestation platform %q", requested)
	}
}

func runSEVSNP(platform string, opts runOptions) (*runSummary, error) {
	if err := prepareSEVSNPCertificateCache(opts.VMPL, vtpm.FetchSEVCertificates); err != nil {
		return nil, err
	}
	provider := vtpm.NewProvider(false, opts.VMPL)
	return exerciseTEE(platform, provider.TeeAttestation, extractSEVSNPEvidence, opts)
}

func prepareSEVSNPCertificateCache(vmpl uint, fetch func(uint) error) error {
	if fetch == nil {
		return fmt.Errorf("bootstrap SEV-SNP certificate cache: fetch function is nil")
	}
	if err := fetch(vmpl); err != nil {
		return fmt.Errorf("bootstrap SEV-SNP certificate cache from AMD KDS: %w", err)
	}
	return nil
}

func exerciseTEE(
	platform string,
	collect func([]byte) ([]byte, error),
	extract func([]byte) (*extractedEvidence, error),
	opts runOptions,
) (*runSummary, error) {
	challengeA, err := newReportData("agents-secure-binding/hardware-red-team/session-A")
	if err != nil {
		return nil, err
	}
	challengeB, err := newReportData("agents-secure-binding/hardware-red-team/session-B")
	if err != nil {
		return nil, err
	}

	evidenceA, err := collect(challengeA)
	if err != nil {
		return nil, fmt.Errorf("collect %s evidence for session A: %w", platform, err)
	}
	evidenceB, err := collect(challengeB)
	if err != nil {
		return nil, fmt.Errorf("collect %s evidence for session B: %w", platform, err)
	}
	if len(evidenceA) == 0 || len(evidenceB) == 0 {
		return nil, fmt.Errorf("%s provider returned empty evidence", platform)
	}
	if bytes.Equal(evidenceA, evidenceB) {
		return nil, fmt.Errorf("%s provider returned identical evidence for distinct challenges", platform)
	}

	parsedA, err := extract(evidenceA)
	if err != nil {
		return nil, fmt.Errorf("extract %s session A report data: %w", platform, err)
	}
	parsedB, err := extract(evidenceB)
	if err != nil {
		return nil, fmt.Errorf("extract %s session B report data: %w", platform, err)
	}

	if err := validateChallengeBinding(parsedA.ReportData, challengeA); err != nil {
		return nil, fmt.Errorf("session A evidence rejected for its own challenge: %w", err)
	}
	if err := validateChallengeBinding(parsedB.ReportData, challengeB); err != nil {
		return nil, fmt.Errorf("session B evidence rejected for its own challenge: %w", err)
	}
	if err := validateChallengeBinding(parsedA.ReportData, challengeB); !errors.Is(err, errChallengeMismatch) {
		return nil, fmt.Errorf("stale session A evidence was not rejected for session B challenge")
	}
	if err := validateChallengeBinding(parsedB.ReportData, challengeA); !errors.Is(err, errChallengeMismatch) {
		return nil, fmt.Errorf("stale session B evidence was not rejected for session A challenge")
	}

	appraisalChecked := false
	fullModuleVerified := false
	eatPublicKeySHA256 := ""
	hostDataHash := ""
	if opts.ExpectedHostDataHex != "" || opts.RequireKernelHashes {
		if platform != platformSNP {
			return nil, fmt.Errorf("SEV-SNP appraisal contract requested for non-SNP platform %q", platform)
		}
		if opts.ExpectedHostDataHex != "" && len(parsedA.HostData) == 0 {
			return nil, fmt.Errorf("SEV-SNP evidence does not contain HostData")
		}
		expectedHostData := strings.TrimSpace(opts.ExpectedHostDataHex)
		if expectedHostData != "" {
			var err error
			expectedHostData, err = qemu.NormalizeSEVSNPHostData(expectedHostData)
			if err != nil {
				return nil, fmt.Errorf("decode expected HostData: %w", err)
			}
		}
		contract := qemu.SEVSNPAppraisalContract{
			RequireHostData:     expectedHostData != "",
			ExpectedHostData:    expectedHostData,
			RequireKernelHashes: opts.RequireKernelHashes,
		}
		evidence := qemu.SEVSNPAppraisalEvidence{
			HostData:            hex.EncodeToString(parsedA.HostData),
			KernelHashesEnabled: opts.KernelHashesEvidence,
		}
		if err := contract.Validate(evidence); err != nil {
			return nil, fmt.Errorf("SEV-SNP appraisal contract rejected evidence: %w", err)
		}
		appraisalChecked = true
		if len(parsedA.HostData) > 0 {
			hostDataHash = sha256Hex(parsedA.HostData)
		}
	}
	if opts.RequireFullVerification || opts.CoRIMPolicyPath != "" || opts.PlatformPolicyPath != "" {
		fingerprint, err := verifyFullModulePath(platform, evidenceA, evidenceB, challengeA, challengeB, opts)
		if err != nil {
			return nil, err
		}
		fullModuleVerified = true
		eatPublicKeySHA256 = fingerprint
	}

	summary := &runSummary{
		TimestampUTC:           time.Now().UTC().Format(time.RFC3339),
		Platform:               platform,
		EvidenceASHA256:        sha256Hex(evidenceA),
		EvidenceBSHA256:        sha256Hex(evidenceB),
		ChallengeASHA256:       sha256Hex(challengeA),
		ChallengeBSHA256:       sha256Hex(challengeB),
		HostDataSHA256:         hostDataHash,
		AppraisalContractCheck: appraisalChecked,
		FullModuleVerification: fullModuleVerified,
		EATPublicKeySHA256:     eatPublicKeySHA256,
	}
	if err := writeSummary(opts.EvidenceDir, summary); err != nil {
		return nil, err
	}
	return summary, nil
}

func verifyFullModulePath(platform string, evidenceA, evidenceB, challengeA, challengeB []byte, opts runOptions) (string, error) {
	if strings.TrimSpace(opts.CoRIMPolicyPath) == "" || strings.TrimSpace(opts.PlatformPolicyPath) == "" {
		return "", fmt.Errorf("full module verification requires --corim-policy and --platform-policy")
	}
	issuer := strings.TrimSpace(opts.EATIssuer)
	if issuer == "" {
		return "", fmt.Errorf("full module verification requires a non-empty --eat-issuer")
	}
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate qualification EAT key: %w", err)
	}
	config := platformmodule.VerifierConfig{
		Platform:           platformmodule.Platform(platform),
		PolicyPath:         opts.CoRIMPolicyPath,
		EATVerificationKey: &signingKey.PublicKey,
		ExpectedIssuer:     issuer,
	}
	if path := strings.TrimSpace(opts.CoRIMPublicKeyPath); path != "" {
		config.CoRIMVerificationKey, err = eat.LoadVerificationKey(path)
		if err != nil {
			return "", fmt.Errorf("load CoRIM verification key: %w", err)
		}
	}
	platformType := attestation.NoCC
	switch platform {
	case platformSNP:
		platformType = attestation.SNP
		config.SNPVerificationOptions, config.SNPValidationOptions, err = platformmodule.LoadSNPPlatformPolicy(opts.PlatformPolicyPath)
	case platformTDX:
		platformType = attestation.TDX
		config.TDXPolicy, err = platformmodule.LoadTDXPlatformPolicy(opts.PlatformPolicyPath)
	default:
		return "", fmt.Errorf("full module verification is available only for direct SNP or TDX")
	}
	if err != nil {
		return "", err
	}
	verifier, err := platformmodule.NewEvidenceVerifier(config)
	if err != nil {
		return "", fmt.Errorf("construct %s verifier: %w", platform, err)
	}

	bindingA, nonceA, err := qualificationBinding(challengeA)
	if err != nil {
		return "", err
	}
	bindingB, nonceB, err := qualificationBinding(challengeB)
	if err != nil {
		return "", err
	}
	tokenA, err := qualificationEAT(evidenceA, nonceA, platformType, signingKey, issuer)
	if err != nil {
		return "", err
	}
	tokenB, err := qualificationEAT(evidenceB, nonceB, platformType, signingKey, issuer)
	if err != nil {
		return "", err
	}
	if err := verifier.VerifyEvidence(tokenA, bindingA); err != nil {
		return "", fmt.Errorf("verify %s module evidence A: %w", platform, err)
	}
	if err := verifier.VerifyEvidence(tokenB, bindingB); err != nil {
		return "", fmt.Errorf("verify %s module evidence B: %w", platform, err)
	}
	if err := verifier.VerifyEvidence(tokenA, bindingB); err == nil {
		return "", fmt.Errorf("%s module accepted session A EAT for session B binding", platform)
	}
	fingerprint, err := eat.VerificationKeyFingerprint(&signingKey.PublicKey)
	if err != nil {
		return "", err
	}
	return fingerprint, nil
}

func qualificationBinding(reportData []byte) (eaattestation.EvidenceBinding, []byte, error) {
	var binding eaattestation.EvidenceBinding
	if len(reportData) != len(binding.ReportData) {
		return binding, nil, fmt.Errorf("qualification REPORT_DATA length is %d, expected %d", len(reportData), len(binding.ReportData))
	}
	copy(binding.ReportData[:], reportData)
	if _, err := rand.Read(binding.Nonce[:]); err != nil {
		return binding, nil, fmt.Errorf("generate qualification EAT nonce: %w", err)
	}
	return binding, append([]byte(nil), binding.Nonce[:]...), nil
}

func qualificationEAT(evidence, nonce []byte, platformType attestation.PlatformType, signingKey *ecdsa.PrivateKey, issuer string) ([]byte, error) {
	claims, err := eat.NewEATClaims(evidence, nonce, platformType)
	if err != nil {
		return nil, fmt.Errorf("create qualification EAT claims: %w", err)
	}
	token, err := eat.EncodeToCBOR(claims, signingKey, issuer)
	if err != nil {
		return nil, fmt.Errorf("sign qualification EAT: %w", err)
	}
	return token, nil
}

func newReportData(context string) ([]byte, error) {
	reportData := make([]byte, reportDataSize)
	if _, err := rand.Read(reportData[:32]); err != nil {
		return nil, fmt.Errorf("generate verifier challenge entropy: %w", err)
	}
	contextHash := sha256.Sum256([]byte(context))
	copy(reportData[32:], contextHash[:])
	return reportData, nil
}

func validateChallengeBinding(reportData []byte, challenge []byte) error {
	if len(reportData) != reportDataSize {
		return fmt.Errorf("attestation report_data length is %d, expected %d", len(reportData), reportDataSize)
	}
	if len(challenge) != reportDataSize {
		return fmt.Errorf("verifier challenge length is %d, expected %d", len(challenge), reportDataSize)
	}
	if !bytes.Equal(reportData, challenge) {
		return fmt.Errorf(
			"%w: report_data_sha256=%s verifier_challenge_sha256=%s",
			errChallengeMismatch,
			sha256Hex(reportData),
			sha256Hex(challenge),
		)
	}
	return nil
}

func extractSEVSNPEvidence(evidence []byte) (*extractedEvidence, error) {
	attestation := &sevsnppb.Attestation{}
	if err := proto.Unmarshal(evidence, attestation); err != nil {
		return nil, err
	}
	report := attestation.GetReport()
	if report == nil {
		return nil, fmt.Errorf("missing SEV-SNP report")
	}
	return &extractedEvidence{
		ReportData: append([]byte(nil), report.GetReportData()...),
		HostData:   append([]byte(nil), report.GetHostData()...),
	}, nil
}

func extractTDXEvidence(evidence []byte) (*extractedEvidence, error) {
	quoteAny, err := tdxabi.QuoteToProto(evidence)
	if err != nil {
		return nil, err
	}
	quote, ok := quoteAny.(*tdxpb.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("unexpected TDX quote type %T", quoteAny)
	}
	body := quote.GetTdQuoteBody()
	if body == nil {
		return nil, fmt.Errorf("missing TDX quote body")
	}
	return &extractedEvidence{
		ReportData: append([]byte(nil), body.GetReportData()...),
	}, nil
}

func writeSummary(dir string, summary *runSummary) error {
	if strings.TrimSpace(dir) == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create evidence directory: %w", err)
	}
	payload, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal evidence summary: %w", err)
	}
	path := filepath.Join(dir, "summary.json")
	if err := os.WriteFile(path, append(payload, '\n'), 0o644); err != nil {
		return fmt.Errorf("write evidence summary: %w", err)
	}
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
