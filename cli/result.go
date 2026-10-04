// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"encoding/pem"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const resultFilename = "results.zip"

func (cli *CLI) NewResultsCmd() *cobra.Command {
	var outputDir string
	var filename string

	cmd := &cobra.Command{
		Use:     "result <private_key_file_path>",
		Short:   "Retrieve computation result file",
		Example: "result <private_key_file_path> --filename my_results.zip --output-dir /path/to/directory",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cli.ensureAgentSDK(cmd); err != nil {
				return printError(cmd, "Failed to connect to agent: %v ❌ ", err)
			}

			cmd.Println("⏳ Retrieving computation result file")

			privKeyFile, err := os.ReadFile(args[0])
			if err != nil {
				return printError(cmd, "Error reading private key file: %v ❌ ", err)
			}

			var outputPath string
			if outputDir != "" {
				if err := os.MkdirAll(outputDir, 0o755); err != nil {
					return printError(cmd, "Error creating output directory: %v ❌ ", err)
				}
				outputPath = filepath.Join(outputDir, filename)
			} else {
				outputPath = filename
			}

			absPath, err := filepath.Abs(outputPath)
			if err != nil {
				absPath = outputPath
			}

			pemBlock, _ := pem.Decode(privKeyFile)

			privKey, err := decodeKey(pemBlock)
			if err != nil {
				return printError(cmd, "Error decoding private key: %v ❌ ", err)
			}

			resultFile, err := os.Create(outputPath)
			if err != nil {
				return printError(cmd, "Error creating result file: %v ❌ ", err)
			}
			defer resultFile.Close()

			if err = cli.agentSDK.Result(cmd.Context(), privKey, resultFile); err != nil {
				return printError(cmd, "Error retrieving computation result: %v ❌ ", err)
			}

			cmd.Println(color.New(color.FgGreen).Sprintf("Computation result retrieved and saved successfully! ✔"))
			cmd.Println(color.New(color.FgCyan).Sprintf("📁 Location: %s", absPath))
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputDir, "output-dir", "o", "", "Directory where the result file will be saved")
	cmd.Flags().StringVarP(&filename, "filename", "f", resultFilename, "Name of the result file")

	return cmd
}
