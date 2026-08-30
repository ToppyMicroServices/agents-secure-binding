// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package vtpm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/errors"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/corimgen"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/swid"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
)

var (
	_ attestation.Provider = (*provider)(nil)
	_ attestation.Verifier = (*verifier)(nil)
)

const (
	eventLog = "/sys/kernel/security/tpm0/binary_bios_measurements"
	Nonce    = 32
	PCR15    = 15
	PCR16    = 16
	Hash1    = 20
	Hash256  = 32
	Hash384  = 48
)

var (
	ExternalTPM   io.ReadWriteCloser
	ErrNoHashAlgo = errors.New("hash algo is not supported")
	ErrFetchQuote = errors.New("failed to fetch vTPM quote")
)

type tpm struct {
	io.ReadWriteCloser
}

func (et tpm) EventLog() ([]byte, error) {
	return os.ReadFile(eventLog)
}

func OpenTpm() (io.ReadWriteCloser, error) {
	if ExternalTPM != nil {
		return tpm{ExternalTPM}, nil
	}

	tw := tpm{}
	var err error

	tw.ReadWriteCloser, err = tpm2.OpenTPM("/dev/tpmrm0")
	if os.IsNotExist(err) {
		tw.ReadWriteCloser, err = tpm2.OpenTPM("/dev/tpm0")
	}

	return tw, err
}

func ExtendPCR(pcrIndex int, value []byte) error {
	rwc, err := OpenTpm()
	if err != nil {
		return err
	}
	defer rwc.Close()

	fixedSha256Hash := sha3.Sum256(value)
	if err := tpm2.PCRExtend(rwc, tpmutil.Handle(pcrIndex), tpm2.AlgSHA256, fixedSha256Hash[:], ""); err != nil {
		return err
	}

	fixedSha384Hash := sha3.Sum384(value)
	if err := tpm2.PCRExtend(rwc, tpmutil.Handle(pcrIndex), tpm2.AlgSHA384, fixedSha384Hash[:], ""); err != nil {
		return err
	}

	return nil
}

type provider struct {
	teeAttestaion bool
	vmpl          uint
}

func NewProvider(teeAttestation bool, vmpl uint) attestation.Provider {
	return &provider{
		teeAttestaion: teeAttestation,
		vmpl:          vmpl,
	}
}

func (v provider) Attestation(teeNonce []byte, vTpmNonce []byte) ([]byte, error) {
	return Attest(teeNonce, vTpmNonce, v.teeAttestaion, v.vmpl)
}

func (v provider) TeeAttestation(teeNonce []byte) ([]byte, error) {
	return fetchSEVAttestation(teeNonce, v.vmpl)
}

func (a provider) VTpmAttestation(vTpmNonce []byte) ([]byte, error) {
	quote, err := FetchQuote(vTpmNonce)
	if err != nil {
		return []byte{}, errors.Wrap(ErrFetchQuote, err)
	}

	return proto.Marshal(quote)
}

func (v provider) AzureAttestationToken(tokenNonce []byte) ([]byte, error) {
	return nil, errors.New("Azure attestation token is not supported")
}

type verifier struct {
	writer io.Writer
}

func NewVerifier(writer io.Writer) attestation.Verifier {
	return &verifier{
		writer: writer,
	}
}

func (v *verifier) VerifyWithCoRIM(report []byte, manifest *corim.UnsignedCorim) error {
	if manifest == nil {
		return fmt.Errorf("CoRIM manifest is nil")
	}

	attestation := &attest.Attestation{}
	if err := proto.Unmarshal(report, attestation); err != nil {
		return fmt.Errorf("failed to unmarshal attestation report: %w", err)
	}

	// Extract measurement from SEV-SNP report if present
	snp := attestation.GetSevSnpAttestation()
	if snp == nil {
		return fmt.Errorf("no SEV-SNP attestation found in report")
	}

	snpReport := snp.GetReport()
	if snpReport == nil {
		return fmt.Errorf("SEV-SNP attestation is missing its report")
	}
	measurement := snpReport.GetMeasurement()
	if len(measurement) == 0 {
		return fmt.Errorf("no measurement in SEV-SNP report")
	}

	// Iterate over CoMIDs tags looking for measurements
	for _, tag := range manifest.Tags {
		// Expecting a CoMID tag
		if !bytes.HasPrefix(tag, corim.ComidTag) {
			continue
		}

		tagValue := tag[len(corim.ComidTag):]

		var c comid.Comid
		if err := c.FromCBOR(tagValue); err != nil {
			return fmt.Errorf("failed to parse CoMID from tag: %w", err)
		}

		// Match one complete, field-aware reference-value profile in the CoMID.
		if c.Triples.ReferenceValues != nil {
			for _, rv := range *c.Triples.ReferenceValues {
				if err := rv.Measurements.Valid(); err != nil {
					return fmt.Errorf("invalid CoRIM measurements for SNP: %w", err)
				}
				matched, err := matchSNPReferenceValue(snpReport, rv.Measurements)
				if err != nil {
					return err
				}
				if matched {
					return nil
				}
			}
		}
	}

	return fmt.Errorf("no matching reference value found in CoRIM for SNP")
}

func matchSNPReferenceValue(report *sevsnp.Report, measurements comid.Measurements) (bool, error) {
	seen := make(map[uint64]struct{}, len(measurements))
	matched := true
	foundMeasurement := false
	for _, measurement := range measurements {
		if measurement.AuthorizedBy != nil {
			return false, fmt.Errorf("SNP CoRIM measurement contains unsupported authorized-by metadata")
		}
		if measurement.Key == nil {
			return false, fmt.Errorf("SNP CoRIM measurement key is required")
		}
		key, err := measurement.Key.GetKeyUint()
		if err != nil {
			return false, fmt.Errorf("SNP CoRIM measurement key must use the ASB uint profile: %w", err)
		}
		if _, duplicate := seen[key]; duplicate {
			return false, fmt.Errorf("duplicate SNP CoRIM measurement key %#x", key)
		}
		seen[key] = struct{}{}

		switch key {
		case corimgen.SNPMeasurementMKey:
			foundMeasurement = true
			valueMatched, err := matchSNPDigestAndSVN(report, measurement.Val)
			if err != nil {
				return false, err
			}
			matched = matched && valueMatched
		case corimgen.SNPHostDataMKey:
			value, err := exactRawValue(measurement.Val, "SNP HOST_DATA")
			if err != nil {
				return false, err
			}
			if len(value) != Hash256 {
				return false, fmt.Errorf("SNP HOST_DATA must be %d bytes", Hash256)
			}
			matched = matched && bytes.Equal(report.GetHostData(), value)
		case corimgen.SNPPolicyMKey:
			value, err := exactRawUint64Value(measurement.Val, "SNP policy")
			if err != nil {
				return false, err
			}
			matched = matched && report.GetPolicy() == value
		case corimgen.SNPMinimumLaunchTCBMKey:
			value, err := exactRawUint64Value(measurement.Val, "SNP minimum launch TCB")
			if err != nil {
				return false, err
			}
			minimum := kds.DecomposeTCBVersion(kds.TCBVersion(value))
			actual := kds.DecomposeTCBVersion(kds.TCBVersion(report.GetLaunchTcb()))
			matched = matched && kds.TCBPartsLE(minimum, actual)
		default:
			return false, fmt.Errorf("unsupported SNP CoRIM measurement key %#x", key)
		}
	}
	if !foundMeasurement {
		return false, fmt.Errorf("SNP CoRIM reference value is missing measurement key %#x", corimgen.SNPMeasurementMKey)
	}
	return matched, nil
}

func matchSNPDigestAndSVN(report *sevsnp.Report, value comid.Mval) (bool, error) {
	if value.Digests == nil || len(*value.Digests) != 1 {
		return false, fmt.Errorf("SNP measurement key requires exactly one digest")
	}
	digest := (*value.Digests)[0]
	if digest.HashAlgID != swid.Sha384 || len(digest.HashValue) != Hash384 {
		return false, fmt.Errorf("SNP measurement key requires one 48-byte SHA-384 digest")
	}
	if err := rejectUnexpectedMeasurementValues(value, true, value.SVN != nil, false, "SNP measurement"); err != nil {
		return false, err
	}
	matched := bytes.Equal(report.GetMeasurement(), digest.HashValue)
	if value.SVN != nil {
		svnMatched, err := matchSVN(value.SVN, uint64(report.GetGuestSvn()))
		if err != nil {
			return false, fmt.Errorf("invalid SNP guest SVN constraint: %w", err)
		}
		matched = matched && svnMatched
	}
	return matched, nil
}

func matchSVN(svn *comid.SVN, actual uint64) (bool, error) {
	if svn == nil || svn.Value == nil {
		return false, fmt.Errorf("SVN value is missing")
	}
	switch value := svn.Value.(type) {
	case comid.TaggedSVN:
		return actual == uint64(value), nil
	case *comid.TaggedSVN:
		return value != nil && actual == uint64(*value), nil
	case comid.TaggedMinSVN:
		return actual >= uint64(value), nil
	case *comid.TaggedMinSVN:
		return value != nil && actual >= uint64(*value), nil
	default:
		return false, fmt.Errorf("unsupported SVN type %T", svn.Value)
	}
}

func exactRawUint64Value(value comid.Mval, label string) (uint64, error) {
	raw, err := exactRawValue(value, label)
	if err != nil {
		return 0, err
	}
	if len(raw) != 8 {
		return 0, fmt.Errorf("%s must be an 8-byte little-endian value", label)
	}
	return binary.LittleEndian.Uint64(raw), nil
}

func exactRawValue(value comid.Mval, label string) ([]byte, error) {
	if value.RawValue == nil {
		return nil, fmt.Errorf("%s CoRIM raw value is missing", label)
	}
	if err := rejectUnexpectedMeasurementValues(value, false, false, true, label); err != nil {
		return nil, err
	}
	raw, err := value.RawValue.GetBytes()
	if err != nil {
		return nil, fmt.Errorf("invalid %s CoRIM raw value: %w", label, err)
	}
	return raw, nil
}

func rejectUnexpectedMeasurementValues(value comid.Mval, allowDigests, allowSVN, allowRaw bool, label string) error {
	if (!allowDigests && value.Digests != nil) ||
		(!allowSVN && value.SVN != nil) ||
		(!allowRaw && value.RawValue != nil) ||
		value.Ver != nil || value.Flags != nil || value.RawValueMask != nil ||
		value.MACAddr != nil || value.IPAddr != nil || value.SerialNumber != nil ||
		value.UEID != nil || value.UUID != nil || value.IntegrityRegisters != nil ||
		value.GetExtensions() != nil {
		return fmt.Errorf("%s CoRIM value contains unsupported constraints", label)
	}
	return nil
}

func Attest(teeNonce []byte, vTPMNonce []byte, teeAttestaion bool, vmpl uint) ([]byte, error) {
	attestation, err := FetchQuote(vTPMNonce)
	if err != nil {
		return []byte{}, err
	}

	if teeAttestaion {
		err = addTEEAttestation(attestation, teeNonce, vmpl)
		if err != nil {
			return []byte{}, err
		}
	}

	return marshalQuote(attestation)
}

func marshalQuote(attestation *attest.Attestation) ([]byte, error) {
	out, err := proto.Marshal(attestation)
	if err != nil {
		return []byte{}, errors.Wrap(fmt.Errorf("failed to marshal vTPM attestation report"), err)
	}

	return out, nil
}

func FetchQuote(nonce []byte) (*attest.Attestation, error) {
	rwc, err := OpenTpm()
	if err != nil {
		return nil, err
	}
	defer rwc.Close()

	attestationKey, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("failed to create attestation key: %v", err), err)
	}
	defer attestationKey.Close()

	var fixedNonce [Nonce]byte
	copy(fixedNonce[:], nonce)
	attestOpts := client.AttestOpts{}
	attestOpts.Nonce = fixedNonce[:]

	attestOpts.TCGEventLog, err = client.GetEventLog(rwc)
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("failed to retrieve TCG Event Log: %v", err), err)
	}

	attestation, err := attestationKey.Attest(attestOpts)
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("failed to attest: %v", err), err)
	}

	return attestation, nil
}

func addTEEAttestation(attestation *attest.Attestation, nonce []byte, vmpl uint) error {
	akPub := attestation.GetAkPub()

	teeNonce := make([]byte, 0, len(nonce)+len(akPub))
	teeNonce = append(teeNonce, nonce...)
	teeNonce = append(teeNonce, akPub...)

	attestData := sha3.Sum512(teeNonce)

	rawTeeAttestation, err := fetchSEVAttestation(attestData[:], vmpl)
	if err != nil {
		return fmt.Errorf("failed to fetch TEE attestation report: %v", err)
	}

	extReport := &sevsnp.Attestation{}
	err = proto.Unmarshal(rawTeeAttestation, extReport)
	if err != nil {
		return errors.Wrap(fmt.Errorf("failed to unmarshal TEE report proto"), err)
	}
	attestation.TeeAttestation = &attest.Attestation_SevSnpAttestation{
		SevSnpAttestation: extReport,
	}

	return nil
}

func getPCRValue(index int, algorithm tpm2.Algorithm) ([]byte, error) {
	rwc, err := OpenTpm()
	if err != nil {
		return nil, err
	}
	defer rwc.Close()

	pcrValue, err := tpm2.ReadPCR(rwc, index, algorithm)
	if err != nil {
		if _, ok := ExternalTPM.(*DummyRWC); ok {
			return make([]byte, 20), nil
		}
		return nil, err
	}

	return pcrValue, nil
}

func GetPCRSHA1Value(index int) ([]byte, error) {
	return getPCRValue(index, tpm2.AlgSHA1)
}

func GetPCRSHA256Value(index int) ([]byte, error) {
	return getPCRValue(index, tpm2.AlgSHA256)
}

func GetPCRSHA384Value(index int) ([]byte, error) {
	return getPCRValue(index, tpm2.AlgSHA384)
}
