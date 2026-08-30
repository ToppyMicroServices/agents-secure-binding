// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package docker

import (
	"log/slog"
	"os"
	"testing"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/events/mocks"
	"github.com/stretchr/testify/assert"
)

// TestNewAlgorithm tests the NewAlgorithm function.
func TestNewAlgorithm(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventsSvc := new(mocks.Service)
	algoFile := "/path/to/algo.tar"

	algo := NewAlgorithm(logger, eventsSvc, algoFile, "")

	d, ok := algo.(*docker)
	assert.True(t, ok, "NewAlgorithm should return a *docker")
	assert.Equal(t, algoFile, d.algoFile, "algoFile should be set correctly")
	assert.NotNil(t, d.logger, "logger should be set")
}

func TestRunDisabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventsSvc := new(mocks.Service)

	algo := NewAlgorithm(logger, eventsSvc, "/path/to/algo.tar", "")

	assert.ErrorIs(t, algo.Run(), ErrDockerAlgorithmDisabled)
}
