// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cvm

import (
	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/cvms"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients/grpc"
)

// NewManagerClient creates new manager gRPC client instance.
func NewCVMClient(cfg clients.StandardClientConfig) (grpc.Client, cvms.ServiceClient, error) {
	client, err := grpc.NewClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	return client, cvms.NewServiceClient(client.Connection()), nil
}
