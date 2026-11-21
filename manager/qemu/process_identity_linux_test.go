// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package qemu

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/manager/vm"
	"github.com/stretchr/testify/require"
)

func TestRestoreProcessRequiresMatchingIdentity(t *testing.T) {
	pid := os.Getpid()
	id, err := CaptureProcessIdentity(pid)
	if errors.Is(err, os.ErrNoHandle) {
		t.Skip("Linux pidfd unsupported")
	}
	require.NoError(t, err)
	require.NotZero(t, id.Inode)
	require.NotEmpty(t, id.BootID)
	p, err := RestoreProcess(pid, id)
	require.NoError(t, err)
	require.NoError(t, p.Release())

	for _, change := range []func(*ProcessIdentity){
		func(id *ProcessIdentity) { *id = ProcessIdentity{} },
		func(id *ProcessIdentity) { id.Inode++ },
		func(id *ProcessIdentity) { id.StartTicks++ },
		func(id *ProcessIdentity) { id.BootID += "-old" },
	} {
		stale := id
		change(&stale)
		p, err := RestoreProcess(pid, stale)
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrVMProcessGone)
		require.Nil(t, p)
	}
}

func TestRestoredProcessStopObservesExitWithoutReaping(t *testing.T) {
	child := exec.Command("sleep", "30")
	require.NoError(t, child.Start())
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})

	id, err := CaptureProcessIdentity(child.Process.Pid)
	if errors.Is(err, os.ErrNoHandle) {
		t.Skip("Linux pidfd unsupported")
	}
	require.NoError(t, err)
	p, err := RestoreProcess(child.Process.Pid, id)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Release() })
	guest := &qemuVM{StateMachine: vm.NewStateMachine()}
	require.NoError(t, guest.SetVerifiedProcess(p))
	require.NoError(t, guest.Stop())
	_, err = RestoreProcess(child.Process.Pid, id)
	require.ErrorIs(t, err, ErrVMProcessGone)
	// Only the original parent consumes exit status; the reattached VM uses
	// its own pidfd to observe exit without relying on parenthood.
	state, err := child.Process.Wait()
	require.NoError(t, err)
	require.NotNil(t, state)
}
