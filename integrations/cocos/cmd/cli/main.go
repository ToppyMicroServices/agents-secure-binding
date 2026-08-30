// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/ToppyMicroServices/agents-secure-binding/integrations/cocos/platformmodule"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/cli"
	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/cmdconfig"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/caarlos0/env/v11"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	svcName              = "cli"
	envPrefixAgentGRPC   = "AGENT_GRPC_"
	envPrefixManagerGRPC = "MANAGER_GRPC_"
	completion           = "completion"
	filePermision        = 0o755
	cacheDirectory       = ".agents-secure-binding"
)

type config struct {
	LogLevel                          string `env:"AGENT_LOG_LEVEL" envDefault:"info"`
	IgvmBinaryPath                    string `env:"IGVM_BINARY_PATH" envDefault:"./build/igvmmeasure"`
	AgentAttestationModule            string `env:"AGENT_GRPC_ATTESTATION_MODULE" envDefault:""`
	AgentAttestationPlatformPolicy    string `env:"AGENT_GRPC_ATTESTATION_PLATFORM_POLICY" envDefault:""`
	AgentAttestationEATPublicKey      string `env:"AGENT_GRPC_ATTESTATION_EAT_PUBLIC_KEY" envDefault:""`
	AgentAttestationCoRIMPublicKey    string `env:"AGENT_GRPC_ATTESTATION_CORIM_PUBLIC_KEY" envDefault:""`
	AgentAttestationExpectedEATIssuer string `env:"AGENT_GRPC_ATTESTATION_EAT_ISSUER" envDefault:""`
}

func main() {
	os.Exit(run())
}

func run() int {
	rootCmd := &cobra.Command{
		Use:   "agents-secure-binding-cli [command]",
		Short: "CLI application for the Agents Secure Binding runtime API",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("CLI application for the Agents Secure Binding runtime API\n\n")
			fmt.Printf("Usage:\n  %s [command]\n\n", cmd.CommandPath())
			fmt.Printf("Available Commands:\n")

			// Filter out "completion" command
			availableCommands := make([]*cobra.Command, 0)
			for _, subCmd := range cmd.Commands() {
				if subCmd.Name() != completion {
					availableCommands = append(availableCommands, subCmd)
				}
			}

			for _, subCmd := range availableCommands {
				fmt.Printf("  %-15s%s\n", subCmd.Name(), subCmd.Short)
			}

			fmt.Printf("\nFlags:\n")
			cmd.Flags().VisitAll(func(flag *pflag.Flag) {
				fmt.Printf("  -%s, --%s %s\n", flag.Shorthand, flag.Name, flag.Usage)
			})
			fmt.Printf("\nUse \"%s [command] --help\" for more information about a command.\n", cmd.CommandPath())
		},
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signalChan
		fmt.Println()
		rootCmd.Println(color.New(color.FgRed).Sprint("Operation aborted by user!"))
		os.Exit(2)
	}()

	var cfg config
	if err := env.Parse(&cfg); err != nil {
		message := color.New(color.FgRed).Sprintf("failed to load %s configuration : %s", svcName, err)
		rootCmd.Println(message)
		return 1
	}

	homePath, err := os.UserHomeDir()
	if err != nil {
		message := color.New(color.FgRed).Sprintf("failed to fetch user home directory: %s", err)
		rootCmd.Println(message)
		return 1
	}

	directoryCachePath := path.Join(homePath, cacheDirectory)

	if err := os.MkdirAll(directoryCachePath, filePermision); err != nil {
		message := color.New(color.FgRed).Sprintf("failed to create directory %s : %s", directoryCachePath, err)
		rootCmd.Println(message)
		return 1
	}

	agentGRPCConfig := clients.AttestedClientConfig{}
	if err := env.ParseWithOptions(&agentGRPCConfig, env.Options{Prefix: envPrefixAgentGRPC}); err != nil {
		message := color.New(color.FgRed).Sprintf("failed to load %s gRPC client configuration : %s", svcName, err)
		rootCmd.Println(message)
		return 1
	}
	if err := configureAttestationModule(&agentGRPCConfig, attestationModuleConfig{
		Name:                     cfg.AgentAttestationModule,
		PlatformPolicyPath:       cfg.AgentAttestationPlatformPolicy,
		EATVerificationKeyPath:   cfg.AgentAttestationEATPublicKey,
		CoRIMVerificationKeyPath: cfg.AgentAttestationCoRIMPublicKey,
		ExpectedEATIssuer:        cfg.AgentAttestationExpectedEATIssuer,
	}); err != nil {
		message := color.New(color.FgRed).Sprintf("failed to configure the Agent attestation module: %s", err)
		rootCmd.Println(message)
		return 1
	}

	managerGRPCConfig := clients.StandardClientConfig{}
	if err := env.ParseWithOptions(&managerGRPCConfig, env.Options{Prefix: envPrefixManagerGRPC}); err != nil {
		message := color.New(color.FgRed).Sprintf("failed to load %s gRPC client configuration : %s", svcName, err)
		rootCmd.Println(message)
		return 1
	}

	options := cmdconfig.IgvmMeasureOptions
	measurement, err := cmdconfig.NewCmdConfig(cfg.IgvmBinaryPath, options, os.Stderr)
	if err != nil {
		message := color.New(color.FgRed).Sprintf("failed to initialize measurement: %s", err) // Use %s instead of %w
		rootCmd.Println(message)
		return 1
	}

	cliSVC := cli.New(agentGRPCConfig, managerGRPCConfig, measurement)

	if err := cliSVC.InitializeAgentSDK(rootCmd); err == nil {
		defer cliSVC.Close()
	}

	rootCmd.PersistentFlags().BoolVarP(&cli.Verbose, "verbose", "v", false, "Enable verbose output")

	keysCmd := cliSVC.NewKeysCmd()
	attestationCmd := cliSVC.NewAttestationCmd()
	attestationPolicyCmd := cliSVC.NewAttestationPolicyCmd()

	// Agent Commands
	rootCmd.AddCommand(cliSVC.NewAlgorithmCmd())
	rootCmd.AddCommand(cliSVC.NewDatasetsCmd())
	rootCmd.AddCommand(cliSVC.NewResultsCmd())
	rootCmd.AddCommand(attestationCmd)
	rootCmd.AddCommand(cliSVC.NewFileHashCmd())
	rootCmd.AddCommand(attestationPolicyCmd)
	rootCmd.AddCommand(keysCmd)
	rootCmd.AddCommand(cliSVC.NewCABundleCmd(directoryCachePath, nil))
	rootCmd.AddCommand(cliSVC.NewCreateVMCmd())
	rootCmd.AddCommand(cliSVC.NewRemoveVMCmd())
	rootCmd.AddCommand(cliSVC.NewIMAMeasurementsCmd())

	// Attestation commands
	attestationCmd.AddCommand(cliSVC.NewGetAttestationCmd())
	attestationCmd.AddCommand(cliSVC.NewValidateAttestationValidationCmd())

	// measure.
	rootCmd.AddCommand(cliSVC.NewMeasureCmd(cfg.IgvmBinaryPath))

	// Flags
	keysCmd.PersistentFlags().StringVarP(
		&cli.KeyType,
		"key-type",
		"k",
		"rsa",
		"User Key type",
	)

	// Attestation Policy commands
	// Legacy JSON policy commands removed in favor of CoRIM.
	// attestationPolicyCmd.AddCommand(cliSVC.NewAddMeasurementCmd())
	// attestationPolicyCmd.AddCommand(cliSVC.NewAddHostDataCmd())
	// attestationPolicyCmd.AddCommand(cliSVC.NewGCPAttestationPolicy())
	attestationPolicyCmd.AddCommand(cliSVC.NewDownloadGCPOvmfFile())
	// attestationPolicyCmd.AddCommand(cliSVC.NewAzureAttestationPolicy())
	// attestationPolicyCmd.AddCommand(cliSVC.NewExtendWithManifestCmd())

	if err := rootCmd.Execute(); err != nil {
		logErrorCmd(*rootCmd, err)
		return 1
	}
	return 0
}

func configureAttestationModule(cfg *clients.AttestedClientConfig, module attestationModuleConfig) error {
	if cfg == nil {
		return fmt.Errorf("attested client configuration is nil")
	}
	if !cfg.AttestedTLS {
		return nil
	}
	verifierConfig, err := loadAttestationVerifierConfig(module, cfg.AttestationPolicy)
	if err != nil {
		return err
	}
	verifier, err := platformmodule.NewEvidenceVerifier(verifierConfig)
	if err != nil {
		return err
	}
	cfg.AttestationVerificationPolicy = eaattestation.VerificationPolicy{EvidenceVerifier: verifier}
	return nil
}

func logErrorCmd(cmd cobra.Command, err error) {
	boldRed := color.New(color.FgRed, color.Bold)
	boldRed.Fprintf(cmd.ErrOrStderr(), "\nerror: ")

	fmt.Fprintf(cmd.ErrOrStderr(), "%s\n\n", color.RedString(err.Error()))
}
