// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package python

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"sync"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/algorithm"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/algorithm/logging"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/agent/events"
	"google.golang.org/grpc/metadata"
)

const (
	PyRuntime    = "python3"
	PyRuntimeKey = "python_runtime"
)

func PythonRunTimeToContext(ctx context.Context, runtime string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, PyRuntimeKey, runtime)
}

func PythonRunTimeFromContext(ctx context.Context) string {
	values := metadata.ValueFromIncomingContext(ctx, PyRuntimeKey)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

var _ algorithm.Algorithm = (*python)(nil)

type python struct {
	algoFile         string
	stderr           io.Writer
	stdout           io.Writer
	runtime          string
	requirementsFile string
	args             []string
	cmd              *exec.Cmd
	stopped          bool
	mu               sync.Mutex
}

func NewAlgorithm(logger *slog.Logger, eventsSvc events.Service, runtime, requirementsFile, algoFile string, args []string, cmpID string) algorithm.Algorithm {
	p := &python{
		algoFile:         algoFile,
		stderr:           &logging.Stderr{Logger: logger, EventSvc: eventsSvc, CmpID: cmpID},
		stdout:           &logging.Stdout{Logger: logger},
		requirementsFile: requirementsFile,
		args:             args,
	}
	if runtime != "" {
		p.runtime = runtime
	} else {
		p.runtime = PyRuntime
	}
	return p
}

func (p *python) Run() error {
	venvParent, err := os.MkdirTemp("", "asb-python-venv-")
	if err != nil {
		return fmt.Errorf("error creating virtual environment directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(venvParent); err != nil {
			_, _ = p.stderr.Write([]byte(fmt.Sprintf("error removing virtual environment: %v\n", err)))
		}
	}()
	venvPath := filepath.Join(venvParent, "venv")

	createVenvCmd := exec.Command(p.runtime, "-m", "venv", venvPath)
	createVenvCmd.Stderr = p.stderr
	createVenvCmd.Stdout = p.stdout
	if err := p.runCommand(createVenvCmd); err != nil {
		return fmt.Errorf("error creating virtual environment: %w", err)
	}

	pythonPath := filepath.Join(venvPath, "bin", "python")
	if goruntime.GOOS == "windows" {
		pythonPath = filepath.Join(venvPath, "Scripts", "python.exe")
	}

	if p.requirementsFile != "" {
		rcmd := exec.Command(pythonPath, "-m", "pip", "install", "--disable-pip-version-check", "--no-input", "-r", p.requirementsFile)
		rcmd.Stderr = p.stderr
		rcmd.Stdout = p.stdout
		if err := p.runCommand(rcmd); err != nil {
			return fmt.Errorf("error installing requirements: %w", err)
		}
	}

	args := append([]string{p.algoFile}, p.args...)
	cmd := exec.Command(pythonPath, args...)
	cmd.Stderr = p.stderr
	cmd.Stdout = p.stdout
	if err := p.runCommand(cmd); err != nil {
		return fmt.Errorf("algorithm execution error: %w", err)
	}

	return nil
}

func (p *python) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopped = true

	if p.cmd == nil {
		return nil
	}

	if p.cmd.Process == nil {
		return nil
	}

	if err := algorithm.StopCommand(p.cmd); err != nil {
		return fmt.Errorf("error stopping algorithm: %v", err)
	}

	return nil
}

func (p *python) runCommand(cmd *exec.Cmd) error {
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return algorithm.ErrStopped
	}
	algorithm.ConfigureCommand(cmd)
	p.cmd = cmd
	if err := algorithm.StartCommand(p.cmd); err != nil {
		p.cmd = nil
		p.mu.Unlock()
		return err
	}
	p.mu.Unlock()

	err := algorithm.WaitCommand(cmd)
	p.mu.Lock()
	if p.cmd == cmd {
		p.cmd = nil
	}
	p.mu.Unlock()
	return err
}
