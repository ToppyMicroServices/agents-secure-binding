// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/manager"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/cmdconfig"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients/grpc"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients/grpc/agent"
	managergrpc "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients/grpc/manager"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/sdk"
	"github.com/spf13/cobra"
)

var Verbose bool

type CLI struct {
	agentSDK      sdk.SDK
	agentConfig   clients.AttestedClientConfig
	managerConfig clients.StandardClientConfig
	client        grpc.Client
	managerClient manager.ManagerServiceClient
	connectErr    error
	measurement   cmdconfig.MeasurementProvider
}

func New(agentConfig clients.AttestedClientConfig, managerConfig clients.StandardClientConfig, measurement cmdconfig.MeasurementProvider) *CLI {
	return &CLI{
		agentConfig:   agentConfig,
		managerConfig: managerConfig,
		measurement:   measurement,
	}
}

func (c *CLI) InitializeAgentSDK(cmd *cobra.Command) error {
	agentGRPCClient, agentClient, err := agent.NewAgentClient(context.Background(), c.agentConfig)
	if err != nil {
		c.connectErr = err
		return err
	}
	cmd.Println("🔗 Connected to agent ", agentGRPCClient.Secure())
	c.client = agentGRPCClient

	c.agentSDK = sdk.NewAgentSDK(agentClient)
	return nil
}

func (c *CLI) InitializeManagerClient(cmd *cobra.Command) error {
	managerGRPCClient, managerClient, err := managergrpc.NewManagerClient(c.managerConfig)
	if err != nil {
		c.connectErr = err
		return err
	}

	cmd.Println("🔗 Connected to manager using ", managerGRPCClient.Secure())
	c.client = managerGRPCClient

	c.managerClient = managerClient
	return nil
}

func (c *CLI) Close() {
	if c.client != nil {
		c.client.Close()
	}
}
