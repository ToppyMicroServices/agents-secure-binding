// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package wasm

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

const wasmRuntime = "wasmedge"

var mapDirOption = []string{"--dir", ".:" + algorithm.ResultsDir}

var _ algorithm.Algorithm = (*wasm)(nil)

type wasm struct {
	algoFile string
	stderr   io.Writer
	stdout   io.Writer
	args     []string
	cmd      *exec.Cmd
	stopped  bool
	mu       sync.Mutex
}

func NewAlgorithm(logger *slog.Logger, eventsSvc events.Service, args []string, algoFile, cmpID string) algorithm.Algorithm {
	return &wasm{
		algoFile: algoFile,
		stderr:   &logging.Stderr{Logger: logger, EventSvc: eventsSvc, CmpID: cmpID},
		stdout:   &logging.Stdout{Logger: logger},
		args:     args,
	}
}

func (w *wasm) Run() error {
	args := append(mapDirOption, w.algoFile)
	args = append(args, w.args...)
	w.mu.Lock()
	if w.stopped {
		w.mu.Unlock()
		return algorithm.ErrStopped
	}
	w.cmd = execCommand(wasmRuntime, args...)
	algorithm.ConfigureCommand(w.cmd)
	w.cmd.Stderr = w.stderr
	w.cmd.Stdout = w.stdout

	if err := algorithm.StartCommand(w.cmd); err != nil {
		w.mu.Unlock()
		return fmt.Errorf("error starting algorithm: %v", err)
	}
	w.mu.Unlock()

	if err := algorithm.WaitCommand(w.cmd); err != nil {
		return fmt.Errorf("algorithm execution error: %v", err)
	}

	return nil
}

func (w *wasm) Stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stopped = true

	if w.cmd == nil {
		return nil
	}

	if w.cmd.Process == nil {
		return nil
	}

	if err := algorithm.StopCommand(w.cmd); err != nil {
		return fmt.Errorf("error stopping algorithm: %v", err)
	}

	return nil
}
