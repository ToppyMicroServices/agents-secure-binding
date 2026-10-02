// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"crypto/sha512"
	"fmt"
	"os"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/gcp"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var (
	isJsonAttestation bool
	// 0o744 file permission gives RWX permission to the user and only the R permission to others.
	filePermission os.FileMode = 0o744
)

func (cli *CLI) NewAttestationPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Change attestation policy",
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}

	cmd.AddCommand(cli.NewCreateCoRIMCmd())

	return cmd
}

func (cli *CLI) NewDownloadGCPOvmfFile() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "download",
		Short:   "Download GCP OVMF file",
		Example: `download <bin_vtmp_attestation_report_file>`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			attestationBin, err := os.ReadFile(args[0])
			if err != nil {
				return printError(cmd, "Error reading attestation report file: %v ❌ ", err)
			}

			attestation := &attest.Attestation{}

			if isJsonAttestation {
				if err := protojson.Unmarshal(attestationBin, attestation); err != nil {
					return printError(cmd, "Error converting JSON attestation to binary: %v ❌", err)
				}
			} else {
				if err := proto.Unmarshal(attestationBin, attestation); err != nil {
					return printError(cmd, "Error unmarshaling attestation report: %v ❌ ", err)
				}
			}

			attestationPB := attestation.GetSevSnpAttestation()

			measurement, err := gcp.Extract384BitMeasurement(attestationPB)
			if err != nil {
				return printError(cmd, "Error extracting 384-bit measurement: %v ❌ ", err)
			}

			launchEndorsement, err := gcp.GetLaunchEndorsement(cmd.Context(), measurement)
			if err != nil {
				return printError(cmd, "Error getting launch endorsement: %v ❌ ", err)
			}

			ovmf, err := gcp.DownloadOvmfFile(cmd.Context(), fmt.Sprintf("%x", launchEndorsement.Digest))
			if err != nil {
				return printError(cmd, "Error downloading OVMF file: %v ❌ ", err)
			}

			sum384 := sha512.Sum384(ovmf)

			if !bytes.Equal(sum384[:], launchEndorsement.Digest) {
				return printError(cmd, "Error OVMF file does not match the measurement: %v ❌ ", fmt.Errorf("digest mismatch"))
			} else {
				cmd.Println("OVMF firmware in vm is unmodified ✅")
			}

			if err := os.WriteFile("ovmf.fd", ovmf, filePermission); err != nil {
				return printError(cmd, "Error writing OVMF file: %v ❌ ", err)
			}

			cmd.Println("OVMF file downloaded successfully ✅")
			return nil
		},
	}

	cmd.Flags().BoolVarP(&isJsonAttestation, "json", "j", false, "Use JSON attestation report instead of binary")
	return cmd
}
