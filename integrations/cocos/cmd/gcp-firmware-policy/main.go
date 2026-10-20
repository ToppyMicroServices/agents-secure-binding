// Prepare paired GCP firmware policies; no raw report input or cloud calls.
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	snp "github.com/ToppyMicroServices/agents-secure-binding/modules/attestation/snp"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/corimgen"
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	gceverify "github.com/google/gce-tcb-verifier/verify"
	"github.com/google/go-sev-guest/abi"
	checkpb "github.com/google/go-sev-guest/proto/check"
	sevp "github.com/google/go-sev-guest/proto/sevsnp"
	sevvalidate "github.com/google/go-sev-guest/validate"
	sevverify "github.com/google/go-sev-guest/verify"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Independently fetched on 2026-10-18 over HTTPS from
// https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt .
// This DER pin is fixed in production; no flag can replace the trust anchor.
const productionRootSHA256 = "e876bc6978bf4f3da445f98a0a82363c8c0bae5a1fc033c6df65846a6cb0f18c"

const maxInputBytes = 4 << 20

type options struct {
	rootPath, endorsementPath, measurementHex, outputDir string
	launchVMSAs, vmpl                                    uint
}

type result struct {
	Status                string `json:"status"`
	TimestampUTC          string `json:"timestamp_utc"`
	GoogleRootSHA256      string `json:"google_root_sha256"`
	EndorsementSHA256     string `json:"endorsement_sha256"`
	CoRIMSHA256           string `json:"corim_sha256"`
	PlatformPolicySHA256  string `json:"platform_policy_sha256"`
	ExpectedLaunchVMSAs   uint   `json:"expected_launch_vmsas"`
	VMPL                  uint   `json:"vmpl"`
	LiveHardwareTested    bool   `json:"live_hardware_tested"`
	TCBFloorEnforced      bool   `json:"tcb_floor_enforced"`
	GuestSVNFloorEnforced bool   `json:"guest_svn_floor_enforced"`
}

func main() {
	var opts options
	flag.StringVar(&opts.rootPath, "google-root", "", "independently fetched Google production root DER certificate")
	flag.StringVar(&opts.endorsementPath, "endorsement", "", "Google VMLaunchEndorsement binarypb file")
	flag.StringVar(&opts.measurementHex, "measurement", "", "candidate 48-byte measurement in hex; not trusted until matched to signed endorsement")
	flag.StringVar(&opts.outputDir, "out-dir", "", "new output directory; existing directories are refused")
	flag.UintVar(&opts.launchVMSAs, "launch-vmsas", 0, "required expected launch VMSAs (1 selects the signed SVSM measurement)")
	flag.UintVar(&opts.vmpl, "vmpl", 4, "required expected VMPL, 0 through 3")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(1)
	}
	res, err := run(opts, time.Now().UTC(), productionRootSHA256)
	if err != nil {
		fmt.Fprintf(os.Stderr, "policy preparation rejected: %v\n", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(res); err != nil {
		fmt.Fprintln(os.Stderr, "could not write preparation summary")
		os.Exit(1)
	}
}

func run(opts options, now time.Time, rootPin string) (*result, error) {
	if opts.rootPath == "" || opts.endorsementPath == "" || opts.outputDir == "" {
		return nil, errors.New("google-root, endorsement, and out-dir are required")
	}
	if opts.launchVMSAs == 0 || uint64(opts.launchVMSAs) > uint64(^uint32(0)) || opts.vmpl > 3 {
		return nil, errors.New("explicit launch-vmsas > 0 and vmpl 0 through 3 are required")
	}
	measurement, err := hex.DecodeString(opts.measurementHex)
	if err != nil || len(measurement) != abi.MeasurementSize {
		return nil, errors.New("measurement must be exactly 48 bytes of hex")
	}
	rootDER, err := readBounded(opts.rootPath)
	if err != nil {
		return nil, fmt.Errorf("read root: %w", err)
	}
	if digest(rootDER) != rootPin {
		return nil, errors.New("Google production root fingerprint mismatch")
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, errors.New("invalid DER root certificate")
	}
	if !root.IsCA || now.Before(root.NotBefore) || now.After(root.NotAfter) || root.CheckSignatureFrom(root) != nil {
		return nil, errors.New("root is not a current self-signed CA certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	serialized, err := readBounded(opts.endorsementPath)
	if err != nil {
		return nil, fmt.Errorf("read endorsement: %w", err)
	}
	// Reject malformed structure before the upstream verifier dereferences the
	// timestamp. These parsed fields remain untrusted until signature verification.
	var endorsement epb.VMLaunchEndorsement
	if err := proto.Unmarshal(serialized, &endorsement); err != nil {
		return nil, errors.New("could not decode endorsement")
	}
	var golden epb.VMGoldenMeasurement
	if err := proto.Unmarshal(endorsement.SerializedUefiGolden, &golden); err != nil {
		return nil, errors.New("could not decode golden values")
	}
	if golden.Timestamp == nil || golden.Timestamp.CheckValid() != nil || golden.Timestamp.AsTime().After(now) {
		return nil, errors.New("endorsement has a missing, invalid, or future timestamp")
	}
	if err := gceverify.Endorsement(serialized, &gceverify.Options{
		RootsOfTrust: roots,
		Now:          now,
		SNP: &gceverify.SNPOptions{
			Measurement: measurement, ExpectedLaunchVMSAs: uint32(opts.launchVMSAs),
		},
	}); err != nil {
		return nil, fmt.Errorf("Google endorsement verification failed: %w", err)
	}
	if len(golden.Digest) != abi.MeasurementSize || golden.SevSnp == nil {
		return nil, errors.New("verified endorsement lacks expected firmware digest or SNP values")
	}
	guestPolicy, err := abi.ParseSnpPolicy(golden.SevSnp.Policy)
	if err != nil || guestPolicy.Debug {
		return nil, errors.New("signed SNP policy is malformed or permits debug")
	}

	// Only the independently authenticated measurement and guest policy are
	// used. There is no report input from which to copy a TCB or SVN floor.
	policy := &checkpb.Config{
		RootOfTrust: &checkpb.RootOfTrust{ProductLine: "Milan", CheckCrl: true},
		Policy: &checkpb.Policy{
			Policy: golden.SevSnp.Policy, Measurement: measurement,
			Vmpl:    wrapperspb.UInt32(uint32(opts.vmpl)),
			Product: &sevp.SevProduct{Name: sevp.SevProduct_SEV_PRODUCT_MILAN},
		},
	}
	verification, err := sevverify.RootOfTrustToOptions(policy.RootOfTrust)
	if err != nil {
		return nil, fmt.Errorf("build AMD trust policy: %w", err)
	}
	verification.Product = policy.Policy.Product
	verification.Getter = snp.NewKDSGetter()
	validation, err := sevvalidate.PolicyToOptions(policy.Policy)
	if err != nil {
		return nil, fmt.Errorf("build SNP validation policy: %w", err)
	}
	if err := snp.ValidateConfig(verification, validation); err != nil {
		return nil, fmt.Errorf("ASB strict policy baseline: %w", err)
	}
	policyJSON, err := (protojson.MarshalOptions{Multiline: true, Indent: "  ", UseProtoNames: true}).Marshal(policy)
	if err != nil {
		return nil, err
	}
	policyJSON = append(policyJSON, '\n')
	// The signed policy is an allowance/minimum policy in go-sev-guest, not
	// an exact report value. For example, a report that disables an allowed
	// migration agent is valid. Keep these checks in platform-policy.json;
	// the CoRIM policy key deliberately means exact equality and must not
	// encode this allowance as an exact value. Both outputs are required.
	corim, err := corimgen.GenerateCoRIM(corimgen.Options{
		Platform: "snp", Measurement: hex.EncodeToString(measurement),
		Product: "Milan",
	})
	if err != nil {
		return nil, fmt.Errorf("generate CoRIM: %w", err)
	}
	if err := writePolicies(opts.outputDir, corim, policyJSON); err != nil {
		return nil, err
	}
	return &result{
		Status: "google_signed_firmware_policy_prepared", TimestampUTC: now.Format(time.RFC3339),
		GoogleRootSHA256: digest(rootDER), EndorsementSHA256: digest(serialized),
		CoRIMSHA256: digest(corim), PlatformPolicySHA256: digest(policyJSON),
		ExpectedLaunchVMSAs: opts.launchVMSAs, VMPL: opts.vmpl,
	}, nil
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("input must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxInputBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxInputBytes {
		return nil, errors.New("input is empty, unreadable, or exceeds 4 MiB")
	}
	return data, nil
}

func writePolicies(dir string, corim, policy []byte) (err error) {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("create new output directory: %w", err)
	}
	corimPath := filepath.Join(dir, "approved.corim.cbor")
	policyPath := filepath.Join(dir, "platform-policy.json")
	defer func() {
		if err != nil {
			_ = os.Remove(corimPath)
			_ = os.Remove(policyPath)
			_ = os.Remove(dir)
		}
	}()
	if err = os.WriteFile(corimPath, corim, 0o600); err != nil {
		return err
	}
	return os.WriteFile(policyPath, policy, 0o600)
}

func digest(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
