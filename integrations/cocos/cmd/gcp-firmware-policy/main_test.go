package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/integrations/cocos/platformmodule"
	snp "github.com/ToppyMicroServices/agents-secure-binding/modules/attestation/snp"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/vtpm"
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	checkpb "github.com/google/go-sev-guest/proto/check"
	sevp "github.com/google/go-sev-guest/proto/sevsnp"
	sevtest "github.com/google/go-sev-guest/testing"
	sevvalidate "github.com/google/go-sev-guest/validate"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/veraison/corim/corim"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// All keys and endorsements below are synthetic, temporary control fixtures.
// They are never valid under main's pinned Google production root.
type syntheticFixture struct {
	root, leaf []byte
	key        *rsa.PrivateKey
	now        time.Time
	golden     *epb.VMGoldenMeasurement
}

func newSyntheticFixture(t *testing.T) syntheticFixture {
	t.Helper()
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic control root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "synthetic control signer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return syntheticFixture{
		root: rootDER, leaf: leafDER, key: leafKey, now: now,
		golden: &epb.VMGoldenMeasurement{
			Timestamp: timestamppb.New(now.Add(-time.Minute)), ClSpec: 123,
			Cert: leafDER, Digest: bytes.Repeat([]byte{0x11}, 48),
			SevSnp: &epb.VMSevSnp{
				Svn: 77, FamilyId: bytes.Repeat([]byte{1}, 16), ImageId: bytes.Repeat([]byte{2}, 16),
				Policy:          abi.SnpPolicyToBytes(abi.SnpPolicy{SMT: true}),
				Measurements:    map[uint32][]byte{2: bytes.Repeat([]byte{0x33}, 48)},
				SvsmMeasurement: bytes.Repeat([]byte{0x44}, 48),
			},
		},
	}
}

func (f syntheticFixture) sign(t *testing.T, golden *epb.VMGoldenMeasurement) []byte {
	t.Helper()
	payload, err := proto.Marshal(golden)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(payload)
	signature, err := rsa.SignPSS(rand.Reader, f.key, crypto.SHA256, hash[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := proto.Marshal(&epb.VMLaunchEndorsement{SerializedUefiGolden: payload, Signature: signature})
	if err != nil {
		t.Fatal(err)
	}
	return serialized
}

func (f syntheticFixture) options(t *testing.T, serialized []byte) options {
	t.Helper()
	dir := t.TempDir()
	opts := options{
		rootPath: filepath.Join(dir, "root.der"), endorsementPath: filepath.Join(dir, "endorsement.binarypb"),
		measurementHex: hex.EncodeToString(f.golden.SevSnp.Measurements[2]),
		launchVMSAs:    2, vmpl: 0, outputDir: filepath.Join(dir, "approved"),
	}
	if err := os.WriteFile(opts.rootPath, f.root, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opts.endorsementPath, serialized, 0o600); err != nil {
		t.Fatal(err)
	}
	return opts
}

func TestSyntheticSignedControlPreparesCompatiblePolicies(t *testing.T) {
	f := newSyntheticFixture(t)
	opts := f.options(t, f.sign(t, f.golden))
	res, err := run(opts, f.now, digest(f.root))
	if err != nil {
		t.Fatal(err)
	}
	if res.LiveHardwareTested || res.TCBFloorEnforced || res.GuestSVNFloorEnforced {
		t.Fatal("preparation overstated validation scope")
	}
	verification, validation, err := platformmodule.LoadSNPPlatformPolicy(filepath.Join(opts.outputDir, "platform-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := snp.ValidateConfig(verification, validation); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(opts.outputDir, "platform-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policy checkpb.Config
	if err := protojson.Unmarshal(encoded, &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Policy.MinimumGuestSvn != 0 || policy.Policy.MinimumTcb != 0 || policy.Policy.MinimumLaunchTcb != 0 || len(policy.Policy.FamilyId) != 0 || len(policy.Policy.ImageId) != 0 {
		t.Fatal("metadata without an approved report-field mapping became a baseline")
	}
	if !bytes.Equal(policy.Policy.Measurement, f.golden.SevSnp.Measurements[2]) || !policy.RootOfTrust.CheckCrl || policy.Policy.Vmpl == nil || policy.Policy.Vmpl.Value != 0 {
		t.Fatal("approved measurement, revocation or exact VMPL missing")
	}
	for _, name := range []string{"approved.corim.cbor", "platform-policy.json"} {
		info, err := os.Stat(filepath.Join(opts.outputDir, name))
		if err != nil || info.Size() == 0 || info.Mode().Perm() != 0o600 {
			t.Fatalf("invalid output %s", name)
		}
	}
}

func TestInvalidControlsDoNotCreateOutput(t *testing.T) {
	f := newSyntheticFixture(t)
	for _, name := range []string{
		"production_pin_rejects_synthetic_root", "tampered_signature", "malformed_endorsement",
		"wrong_measurement", "wrong_vmsa_count", "missing_vmsa_count", "missing_vmpl",
		"debug_policy", "future_timestamp", "missing_timestamp", "expired_signer",
	} {
		t.Run(name, func(t *testing.T) {
			golden := proto.Clone(f.golden).(*epb.VMGoldenMeasurement)
			if name == "debug_policy" {
				golden.SevSnp.Policy = abi.SnpPolicyToBytes(abi.SnpPolicy{Debug: true})
			}
			if name == "future_timestamp" {
				golden.Timestamp = timestamppb.New(f.now.Add(time.Hour))
			}
			if name == "missing_timestamp" {
				golden.Timestamp = nil
			}
			serialized := f.sign(t, golden)
			if name == "tampered_signature" {
				serialized[len(serialized)-1] ^= 0xff
			}
			if name == "malformed_endorsement" {
				serialized = []byte("nonempty malformed endorsement")
			}
			opts := f.options(t, serialized)
			pin, now := digest(f.root), f.now
			switch name {
			case "production_pin_rejects_synthetic_root":
				pin = productionRootSHA256
			case "wrong_measurement":
				opts.measurementHex = hex.EncodeToString(bytes.Repeat([]byte{0x88}, 48))
			case "wrong_vmsa_count":
				opts.launchVMSAs = 4
			case "missing_vmsa_count":
				opts.launchVMSAs = 0
			case "missing_vmpl":
				opts.vmpl = 4
			case "expired_signer":
				now = f.now.Add(25 * time.Hour)
			}
			if _, err := run(opts, now, pin); err == nil {
				t.Fatal("invalid input accepted")
			}
			if _, err := os.Stat(opts.outputDir); !os.IsNotExist(err) {
				t.Fatal("output created for rejected input")
			}
		})
	}
}

func TestExistingOutputIsPreserved(t *testing.T) {
	f := newSyntheticFixture(t)
	opts := f.options(t, f.sign(t, f.golden))
	if err := os.Mkdir(opts.outputDir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(opts.outputDir, "keep")
	if err := os.WriteFile(marker, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(opts, f.now, digest(f.root)); err == nil {
		t.Fatal("existing output accepted")
	}
	got, err := os.ReadFile(marker)
	if err != nil || string(got) != "unchanged" {
		t.Fatal("existing output was changed")
	}
}

// Synthetic field appraisal only. Report signature and production trust are
// exercised separately by the live full-verification harness and SNP tests.
func TestPairedPoliciesKeepAllowanceSemantics(t *testing.T) {
	f := newSyntheticFixture(t)
	f.golden.SevSnp.Policy = abi.SnpPolicyToBytes(abi.SnpPolicy{SMT: true, MigrateMA: true})
	opts := f.options(t, f.sign(t, f.golden))
	if _, err := run(opts, f.now, digest(f.root)); err != nil {
		t.Fatal(err)
	}
	_, validation, err := platformmodule.LoadSNPPlatformPolicy(filepath.Join(opts.outputDir, "platform-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !validation.GuestPolicy.MigrateMA || !validation.GuestPolicy.SMT || validation.GuestPolicy.Debug {
		t.Fatal("signed guest-policy restrictions changed")
	}
	encoded, err := os.ReadFile(filepath.Join(opts.outputDir, "approved.corim.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := corim.NewUnsignedCorim()
	if err := manifest.FromCBOR(encoded); err != nil {
		t.Fatal(err)
	}
	signer, err := sevtest.DefaultTestOnlyCertChain(kds.ProductName(abi.DefaultSevProduct()), f.now)
	if err != nil {
		t.Fatal(err)
	}
	raw := sevtest.CreateRawReport(&sevtest.TestReportOptions{ReportData: make([]byte, abi.ReportDataSize)})
	report, err := abi.ReportToProto(raw[:abi.ReportSize])
	if err != nil {
		t.Fatal(err)
	}
	report.Measurement = append([]byte(nil), f.golden.SevSnp.Measurements[2]...)
	report.Policy = abi.SnpPolicyToBytes(abi.SnpPolicy{SMT: true})
	report.Vmpl = 0
	candidate := &sevp.Attestation{Report: report, CertificateChain: &sevp.CertificateChain{VcekCert: signer.Vcek.Raw}}
	for _, tc := range []struct {
		name                    string
		mutate                  func(*sevp.Report)
		wantPlatform, wantCoRIM bool
	}{
		{"stricter_migration_policy", func(*sevp.Report) {}, true, true},
		{"equal_policy", func(r *sevp.Report) { r.Policy = f.golden.SevSnp.Policy }, true, true},
		{"debug_rejected", func(r *sevp.Report) { r.Policy |= 1 << 19 }, false, true},
		{"wrong_vmpl_rejected", func(r *sevp.Report) { r.Vmpl = 1 }, false, true},
		{"wrong_measurement_rejected", func(r *sevp.Report) { r.Measurement[0] ^= 1 }, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := proto.Clone(candidate).(*sevp.Attestation)
			tc.mutate(changed.Report)
			err := sevvalidate.SnpAttestation(changed, validation)
			if (err == nil) != tc.wantPlatform {
				t.Fatalf("platform appraisal: %v", err)
			}
			wrapped, err := proto.Marshal(&attest.Attestation{TeeAttestation: &attest.Attestation_SevSnpAttestation{SevSnpAttestation: changed}})
			if err != nil {
				t.Fatal(err)
			}
			err = vtpm.NewVerifier(io.Discard).VerifyWithCoRIM(wrapped, manifest)
			if (err == nil) != tc.wantCoRIM {
				t.Fatalf("CoRIM appraisal: %v", err)
			}
		})
	}
	// A migration allowance must still be rejected when the signed policy
	// prohibits it; removing the redundant CoRIM key must not skip this check.
	validation.GuestPolicy.MigrateMA = false
	changed := proto.Clone(candidate).(*sevp.Attestation)
	changed.Report.Policy = f.golden.SevSnp.Policy
	if err := sevvalidate.SnpAttestation(changed, validation); err == nil {
		t.Fatal("migration accepted when the platform policy prohibits it")
	}
}
