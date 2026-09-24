// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package binary

import (
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"sync"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/algorithm"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/algorithm/logging"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/events"
)

var execCommand = exec.Command

var _ algorithm.Algorithm = (*binary)(nil)

type binary struct {
	algoFile string
	stderr   io.Writer
	stdout   io.Writer
	args     []string
	cmd      *exec.Cmd
	stopped  bool
	mu       sync.Mutex
}

func NewAlgorithm(logger *slog.Logger, eventsSvc events.Service, algoFile string, args []string, cmpID string) algorithm.Algorithm {
	return &binary{
		algoFile: algoFile,
		stderr:   &logging.Stderr{Logger: logger, EventSvc: eventsSvc, CmpID: cmpID},
		stdout:   &logging.Stdout{Logger: logger},
		args:     args,
	}
}

func (b *binary) Run() error {
	b.mu.Lock()
	if b.stopped {
		b.mu.Unlock()
		return algorithm.ErrStopped
	}
	b.cmd = execCommand(b.algoFile, b.args...)
	algorithm.ConfigureCommand(b.cmd)
	b.cmd.Stderr = b.stderr
	b.cmd.Stdout = b.stdout

	if err := algorithm.StartCommand(b.cmd); err != nil {
		b.mu.Unlock()
		return fmt.Errorf("error starting algorithm: %v", err)
	}
	b.mu.Unlock()

	if err := algorithm.WaitCommand(b.cmd); err != nil {
		return fmt.Errorf("algorithm execution error: %v", err)
	}

	return nil
}

func (b *binary) Stop() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stopped = true

	if b.cmd == nil {
		return nil
	}

	if b.cmd.Process == nil {
		return nil
	}

	if err := algorithm.StopCommand(b.cmd); err != nil {
		return fmt.Errorf("error stopping algorithm: %v", err)
	}

	return nil
}
