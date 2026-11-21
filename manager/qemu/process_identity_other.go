// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package qemu

import (
	"errors"
	"os"
	"time"
)

var errUnsupportedRestore = errors.New("verified VM process recovery requires Linux pidfds")

func identifyProcess(int) (*os.Process, ProcessIdentity, error) {
	return nil, ProcessIdentity{}, errUnsupportedRestore
}

func waitForRestoredProcess(*os.Process, time.Duration) (bool, error) {
	return false, errUnsupportedRestore
}
