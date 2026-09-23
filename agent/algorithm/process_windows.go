//go:build windows

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package algorithm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var commandJobs = struct {
	sync.Mutex
	jobs map[*exec.Cmd]windows.Handle
}{jobs: make(map[*exec.Cmd]windows.Handle)}

// ConfigureCommand bounds waits on descriptors retained by child processes.
func ConfigureCommand(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED
	cmd.WaitDelay = time.Second
}

// StartCommand creates a suspended computation, assigns it to a private Job,
// and resumes its only initial thread after containment is established.
func StartCommand(cmd *exec.Cmd) error {
	if cmd == nil {
		return errors.New("nil command")
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("create Windows Job Object: %w", err)
	}
	closeJob := true
	defer func() {
		if closeJob {
			_ = windows.CloseHandle(job)
		}
	}()
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return fmt.Errorf("configure Windows Job Object: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, process)
		_ = windows.CloseHandle(process)
	}
	if err != nil {
		terminateStartedCommand(cmd, job)
		return fmt.Errorf("assign computation to Windows Job Object: %w", err)
	}
	commandJobs.Lock()
	commandJobs.jobs[cmd] = job
	commandJobs.Unlock()
	if err := resumeSuspendedProcess(uint32(cmd.Process.Pid)); err != nil {
		commandJobs.Lock()
		delete(commandJobs.jobs, cmd)
		commandJobs.Unlock()
		terminateStartedCommand(cmd, job)
		return fmt.Errorf("resume contained computation: %w", err)
	}
	closeJob = false
	return nil
}

func resumeSuspendedProcess(processID uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)

	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	err = windows.Thread32First(snapshot, &entry)
	var threadID uint32
	for err == nil {
		if entry.OwnerProcessID == processID {
			if threadID != 0 {
				return fmt.Errorf("suspended computation has multiple initial threads")
			}
			threadID = entry.ThreadID
		}
		entry.Size = uint32(unsafe.Sizeof(windows.ThreadEntry32{}))
		err = windows.Thread32Next(snapshot, &entry)
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return err
	}
	if threadID == 0 {
		return fmt.Errorf("suspended computation thread not found")
	}
	thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, threadID)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(thread)
	previous, err := windows.ResumeThread(thread)
	if err != nil {
		return err
	}
	if previous != 1 {
		return fmt.Errorf("unexpected initial thread suspend count %d", previous)
	}
	return nil
}

func terminateStartedCommand(cmd *exec.Cmd, job windows.Handle) {
	_ = windows.TerminateJobObject(job, 1)
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	_ = cmd.Wait()
}

// WaitCommand waits for the computation, then closes its Job. Closing the Job
// removes descendants that retained inherited standard handles.
func WaitCommand(cmd *exec.Cmd) error {
	if cmd == nil {
		return errors.New("nil command")
	}
	err := cmd.Wait()
	commandJobs.Lock()
	job, ok := commandJobs.jobs[cmd]
	if ok {
		delete(commandJobs.jobs, cmd)
	}
	commandJobs.Unlock()
	if ok {
		if closeErr := windows.CloseHandle(job); err == nil && closeErr != nil {
			err = closeErr
		}
	}
	return err
}

// StopCommand terminates the computation Job and all assigned descendants.
func StopCommand(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	commandJobs.Lock()
	job, ok := commandJobs.jobs[cmd]
	if ok {
		err := windows.TerminateJobObject(job, 1)
		commandJobs.Unlock()
		if err != nil {
			return fmt.Errorf("terminate Windows Job Object: %w", err)
		}
		return nil
	}
	commandJobs.Unlock()
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}
