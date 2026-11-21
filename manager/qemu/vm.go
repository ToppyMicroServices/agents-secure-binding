// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package qemu

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/manager/vm"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/manager"
	"github.com/gofrs/uuid"
)

const (
	firmwareVars    = "OVMF_VARS"
	KernelFile      = "bzImage"
	rootfsFile      = "rootfs.cpio"
	tmpDir          = "/tmp"
	shutdownTimeout = 30 * time.Second
)

type VMInfo struct {
	Config    Config
	LaunchTCB uint64 `env:"LAUNCH_TCB" envDefault:"0"`
}

type qemuVM struct {
	vmi      VMInfo
	cmd      *exec.Cmd
	restored bool
	cvmId    string
	logger   *slog.Logger
	vm.StateMachine
}

func NewVM(config any, cvmId string, logger *slog.Logger) vm.VM {
	return &qemuVM{
		vmi:          config.(VMInfo),
		cvmId:        cvmId,
		StateMachine: vm.NewStateMachine(),
		logger:       logger,
	}
}

func (v *qemuVM) Start() error {
	// Create unique qemu device identifiers
	id, err := uuid.NewV4()
	if err != nil {
		return err
	}

	v.vmi.Config.NetDevConfig.ID = fmt.Sprintf("%s-%s", v.vmi.Config.NetDevConfig.ID, id)
	v.vmi.Config.SEVSNPConfig.ID = fmt.Sprintf("%s-%s", v.vmi.Config.SEVSNPConfig.ID, id)
	v.vmi.Config.TDXConfig.ID = fmt.Sprintf("%s-%s", v.vmi.Config.TDXConfig.ID, id)

	if !v.vmi.Config.EnableSEVSNP && !v.vmi.Config.EnableTDX {
		// Copy firmware vars file.
		srcFile := v.vmi.Config.OVMFVarsConfig.File
		dstFile := fmt.Sprintf("%s/%s-%s.fd", tmpDir, firmwareVars, id)
		err = internal.CopyFile(srcFile, dstFile)
		if err != nil {
			return err
		}
		v.vmi.Config.OVMFVarsConfig.File = dstFile
	}

	exe, args, err := v.executableAndArgs()
	if err != nil {
		return err
	}

	v.cmd = exec.Command(exe, args...)
	v.cmd.Stdout = &vm.Stdout{StateMachine: v.StateMachine, Logger: v.logger.With(slog.String("cvm", v.cvmId))}
	v.cmd.Stderr = &vm.Stderr{StateMachine: v.StateMachine, Logger: v.logger.With(slog.String("cvm", v.cvmId))}

	return v.cmd.Start()
}

func (v *qemuVM) Stop() error {
	defer func() {
		err := v.StateMachine.Transition(manager.StopComputationRun)
		if err != nil {
			return
		}
	}()
	err := v.cmd.Process.Signal(syscall.SIGTERM)
	if err != nil && !(v.restored && errors.Is(err, os.ErrProcessDone)) {
		return fmt.Errorf("failed to send SIGTERM: %v", err)
	}

	if v.vmi.Config.CertsMount != "" {
		if err := os.RemoveAll(v.vmi.Config.CertsMount); err != nil {
			return fmt.Errorf("failed to remove certs mount: %v", err)
		}
	}

	if v.vmi.Config.EnvMount != "" {
		if err := os.RemoveAll(v.vmi.Config.EnvMount); err != nil {
			return fmt.Errorf("failed to remove env mount: %v", err)
		}
	}

	if v.restored {
		return stopRestored(v.cmd.Process)
	}
	done := make(chan error, 1)
	go func() {
		_, err := v.cmd.Process.Wait()
		done <- err
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(shutdownTimeout):
		err := v.cmd.Process.Kill()
		if err != nil {
			return fmt.Errorf("failed to kill process: %v", err)
		}
	}

	return nil
}

// A reattached process need not be our child, so os.Process.Wait can return
// ECHILD even while the VM is alive. Poll its pinned handle for actual exit.
func stopRestored(process *os.Process) error {
	exited, err := waitForRestoredProcess(process, shutdownTimeout)
	if err != nil {
		return err
	}
	if !exited {
		if err := process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		exited, err = waitForRestoredProcess(process, shutdownTimeout)
		if err != nil {
			return err
		}
		if !exited {
			return errors.New("VM did not exit after kill")
		}
	}
	return process.Release()
}

// SetProcess cannot safely identify a VM from its PID alone. Retain the
// method for existing callers, but require identity verification to reattach.
func (v *qemuVM) SetProcess(int) error {
	return errors.New("VM reattachment requires a verified process identity")
}

// SetVerifiedProcess takes ownership of a process returned by RestoreProcess.
func (v *qemuVM) SetVerifiedProcess(process *os.Process) error {
	if process == nil {
		return errors.New("missing verified process")
	}
	if err := process.WithHandle(func(uintptr) {}); err != nil {
		return fmt.Errorf("VM reattachment requires a pinned process handle: %w", err)
	}
	v.cmd = &exec.Cmd{Process: process}
	v.restored = true
	return nil
}

func (v *qemuVM) GetProcess() int {
	return v.cmd.Process.Pid
}

func (v *qemuVM) executableAndArgs() (string, []string, error) {
	exe, err := exec.LookPath(v.vmi.Config.QemuBinPath)
	if err != nil {
		return "", nil, err
	}

	args, err := v.vmi.Config.ConstructQemuArgsChecked()
	if err != nil {
		return "", nil, err
	}

	if v.vmi.Config.UseSudo {
		args = append([]string{exe}, args...)
		exe = "sudo"
	}

	return exe, args, nil
}

func (v *qemuVM) GetConfig() any {
	return v.vmi
}

func SEVSNPEnabled(cpuinfo, kernelParam string) bool {
	return strings.Contains(cpuinfo, "sev_snp") && strings.TrimSpace(kernelParam) == "Y"
}

func TDXEnabled(cpuinfo, kernelParam string) bool {
	return strings.Contains(cpuinfo, "tdx_host_platform") && strings.TrimSpace(kernelParam) == "Y"
}

func SEVSNPEnabledOnHost() bool {
	cpuinfo, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false
	}

	kernelParam, err := os.ReadFile("/sys/module/kvm_amd/parameters/sev_snp")
	if err != nil {
		return false
	}

	return SEVSNPEnabled(string(cpuinfo), string(kernelParam))
}

func TDXEnabledOnHost() bool {
	cpuinfo, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false
	}

	kernelParam, err := os.ReadFile("/sys/module/kvm_intel/parameters/tdx")
	if err != nil {
		return false
	}

	return TDXEnabled(string(cpuinfo), string(kernelParam))
}
