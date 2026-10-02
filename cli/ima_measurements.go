// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/vtpm"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const (
	imaMeasurementsFilename = "ima_measurements"
)

func (cli *CLI) NewIMAMeasurementsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "ima-measurements",
		Short:   "Retrieve Linux IMA measurements file",
		Example: "ima-measurements <optional_file_name>",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cli.ensureAgentSDK(cmd); err != nil {
				return printError(cmd, "Failed to connect to agent: %v ❌ ", err)
			}

			cmd.Println("⏳ Retrieving computation Linux IMA measurements file")

			filename := imaMeasurementsFilename
			if len(args) >= 1 {
				filename = args[0]
			}

			imaMeasurementsFile, err := os.Create(filename)
			if err != nil {
				return printError(cmd, "Error creating imaMeasurements file: %v ❌ ", err)
			}
			defer imaMeasurementsFile.Close()

			pcr10, err := cli.agentSDK.IMAMeasurements(cmd.Context(), imaMeasurementsFile)
			if err != nil {
				return printError(cmd, "Error retrieving Linux IMA measurements file: %v ❌ ", err)
			}

			cmd.Println(color.New(color.FgGreen).Sprintf("Linux IMA measurements file retrieved and saved successfully as %s! PCR10 = %s ✔ ", filename, hex.EncodeToString(pcr10)))

			file, err := os.Open(filename)
			if err != nil {
				return printError(cmd, "Failed to open file: %v ❌ ", err)
			}
			defer file.Close()
			if err := verifyIMAMeasurements(file, pcr10); err != nil {
				return printError(cmd, "Measurements file not verified ❌ %v", err)
			}
			cmd.Println(color.New(color.FgGreen).Sprintf("Measurements file verified!"))
			return nil
		},
	}
}

func verifyIMAMeasurements(reader io.Reader, pcr10 []byte) error {
	if len(pcr10) != vtpm.Hash1 {
		return fmt.Errorf("invalid PCR10 digest length")
	}
	calculatedPCR10 := make([]byte, vtpm.Hash1)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) == 0 {
			continue
		}
		if len(parts) < 2 {
			return fmt.Errorf("incomplete IMA measurement entry")
		}
		if parts[0] != "10" {
			continue
		}
		digestHex := parts[1]
		if digestHex == strings.Repeat("0", 2*vtpm.Hash1) {
			digestHex = strings.Repeat("f", 2*vtpm.Hash1)
		}
		digest, err := hex.DecodeString(digestHex)
		if err != nil || len(digest) != vtpm.Hash1 {
			return fmt.Errorf("invalid IMA template digest")
		}
		hasher := sha1.New()
		_, _ = hasher.Write(calculatedPCR10)
		_, _ = hasher.Write(digest)
		calculatedPCR10 = hasher.Sum(nil)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read IMA measurements: %w", err)
	}
	if !bytes.Equal(pcr10, calculatedPCR10) {
		return fmt.Errorf("PCR10 digest mismatch")
	}
	return nil
}
