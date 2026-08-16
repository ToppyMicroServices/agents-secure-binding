// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package docker

import (
	"errors"
	"log/slog"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/algorithm"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/events"
)

var (
	ErrDockerAlgorithmDisabled = errors.New("docker algorithm execution is disabled")

	_ algorithm.Algorithm = (*docker)(nil)
)

type docker struct {
	algoFile string
	logger   *slog.Logger
	cmpID    string
}

func NewAlgorithm(logger *slog.Logger, _ events.Service, algoFile, cmpID string) algorithm.Algorithm {
	return &docker{
		algoFile: algoFile,
		logger:   logger,
		cmpID:    cmpID,
	}
}

func (d *docker) Run() error {
	return ErrDockerAlgorithmDisabled
}

func (d *docker) Stop() error {
	return nil
}
