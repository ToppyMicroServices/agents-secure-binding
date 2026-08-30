// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"github.com/ToppyMicroServices/agents-secure-binding/v2/manager"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients/grpc"
)

// NewManagerClient creates new manager gRPC client instance.
func NewManagerClient(cfg clients.StandardClientConfig) (grpc.Client, manager.ManagerServiceClient, error) {
	client, err := grpc.NewClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	return client, manager.NewManagerServiceClient(client.Connection()), nil
}
