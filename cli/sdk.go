// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"strings"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/auth"
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
	agentSDK          sdk.SDK
	instanceID        string
	computationID     string
	agentConfig       clients.AttestedClientConfig
	managerConfig     clients.StandardClientConfig
	client            grpc.Client
	managerClient     manager.ManagerServiceClient
	managerTransport  grpc.Client
	managerConnectErr error
	connectErr        error
	measurement       cmdconfig.MeasurementProvider
}

func New(agentConfig clients.AttestedClientConfig, managerConfig clients.StandardClientConfig, measurement cmdconfig.MeasurementProvider, instanceID, computationID string) *CLI {
	return &CLI{
		agentConfig:   agentConfig,
		managerConfig: managerConfig,
		measurement:   measurement,
		instanceID:    instanceID,
		computationID: computationID,
	}
}

func (c *CLI) InitializeAgentSDK(cmd *cobra.Command) error {
	if strings.TrimSpace(c.instanceID) == "" {
		return auth.ErrMissingInstanceID
	}
	if strings.TrimSpace(c.computationID) == "" {
		return auth.ErrMissingComputationID
	}
	agentGRPCClient, agentClient, err := agent.NewAgentClient(cmd.Context(), c.agentConfig)
	if err != nil {
		c.connectErr = err
		return err
	}
	agentSDK, err := sdk.NewAgentSDK(agentClient, c.instanceID, c.computationID)
	if err != nil {
		_ = agentGRPCClient.Close()
		c.connectErr = err
		return err
	}
	cmd.Println("🔗 Connected to agent ", agentGRPCClient.Secure())
	c.client = agentGRPCClient
	c.connectErr = nil
	c.agentSDK = agentSDK
	return nil
}

func (c *CLI) ensureAgentSDK(cmd *cobra.Command) error {
	if c.connectErr != nil {
		return c.connectErr
	}
	if c.agentSDK == nil {
		return c.InitializeAgentSDK(cmd)
	}
	return nil
}

func (c *CLI) InitializeManagerClient(cmd *cobra.Command) error {
	managerGRPCClient, managerClient, err := managergrpc.NewManagerClient(c.managerConfig)
	if err != nil {
		c.managerConnectErr = err
		return err
	}

	cmd.Println("🔗 Connected to manager using ", managerGRPCClient.Secure())
	c.managerTransport = managerGRPCClient
	c.managerConnectErr = nil

	c.managerClient = managerClient
	return nil
}

func (c *CLI) Close() {
	if c.managerTransport != nil {
		_ = c.managerTransport.Close()
		c.managerTransport = nil
	}
	if c.client != nil {
		_ = c.client.Close()
		c.client = nil
	}
}
