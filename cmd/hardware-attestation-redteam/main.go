// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
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

	qemu "github.com/ToppyMicroServices/agents-secure-binding/v2/manager/qemu"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/tdx"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/vtpm"
	sevsnppb "github.com/google/go-sev-guest/proto/sevsnp"
	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	"google.golang.org/protobuf/proto"
)

const (
	platformAuto    = "auto"
	platformSNP     = "snp"
	platformSNPvTPM = "snp-vtpm"
	platformTDX     = "tdx"
	reportDataSize  = 64
)

var errChallengeMismatch = errors.New("attestation evidence is not bound to verifier challenge")

type runOptions struct {
	Platform             string
	VMPL                 uint
	ExpectedHostDataHex  string
	RequireKernelHashes  bool
	KernelHashesEvidence bool
	EvidenceDir          string
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
}

func main() {
	opts := runOptions{}
	flag.StringVar(&opts.Platform, "platform", platformAuto, "attestation platform: auto, snp, snp-vtpm, or tdx")
	flag.UintVar(&opts.VMPL, "vmpl", 0, "SEV-SNP VM privilege level")
	flag.StringVar(&opts.ExpectedHostDataHex, "expected-host-data-hex", "", "expected SEV-SNP HostData as hex")
	flag.BoolVar(&opts.RequireKernelHashes, "require-kernel-hashes", false, "require external evidence that kernel-hashes=on was used")
	flag.BoolVar(&opts.KernelHashesEvidence, "kernel-hashes-evidence", false, "runner-provided evidence that kernel-hashes=on was used")
	flag.StringVar(&opts.EvidenceDir, "evidence-dir", "", "directory for non-sensitive evidence fingerprints")
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
	case platformSNP, platformSNPvTPM:
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
	case "", platformAuto:
		switch attestation.CCPlatform() {
		case attestation.SNP:
			return platformSNP, nil
		case attestation.SNPvTPM:
			return platformSNPvTPM, nil
		case attestation.TDX:
			return platformTDX, nil
		case attestation.Azure:
			return "", fmt.Errorf("Azure MAA runtime fetch is disabled in this repository; use a direct SEV-SNP or TDX runner")
		case attestation.NoCC:
			return "", fmt.Errorf("no confidential-computing attestation device detected")
		default:
			return "", fmt.Errorf("detected confidential-computing platform is not supported by this gate")
		}
	case platformSNP, platformSNPvTPM, platformTDX:
		return normalized, nil
	default:
		return "", fmt.Errorf("unsupported attestation platform %q", requested)
	}
}

func runSEVSNP(platform string, opts runOptions) (*runSummary, error) {
	provider := vtpm.NewProvider(false, opts.VMPL)
	return exerciseTEE(platform, provider.TeeAttestation, extractSEVSNPEvidence, opts)
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
	hostDataHash := ""
	if opts.ExpectedHostDataHex != "" || opts.RequireKernelHashes {
		if platform != platformSNP && platform != platformSNPvTPM {
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

	summary := &runSummary{
		TimestampUTC:           time.Now().UTC().Format(time.RFC3339),
		Platform:               platform,
		EvidenceASHA256:        sha256Hex(evidenceA),
		EvidenceBSHA256:        sha256Hex(evidenceB),
		ChallengeASHA256:       sha256Hex(challengeA),
		ChallengeBSHA256:       sha256Hex(challengeB),
		HostDataSHA256:         hostDataHash,
		AppraisalContractCheck: appraisalChecked,
	}
	if err := writeSummary(opts.EvidenceDir, summary); err != nil {
		return nil, err
	}
	return summary, nil
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
