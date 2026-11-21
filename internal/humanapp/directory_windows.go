// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanapp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Supply the ACL to CreateDirectory so a shared parent's inheritable ACEs
// never apply to the state directory or to keys subsequently created inside it.
func makeDataDirectory(dir string) error {
	if _, err := os.Lstat(dir); err == nil {
		return nil // The caller validates the existing directory before use.
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sid := user.User.Sid.String()
	desc, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: desc}
	if err := windows.CreateDirectory(name, &sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return fmt.Errorf("create private data directory: %w", err)
	}
	return nil
}

func checkDirectoryPermissions(dir string, _ os.FileInfo) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	if err := checkWindowsACL(dir, user.User.Sid, true); err != nil {
		return err
	}
	// A restored file can have a protected DACL independent of its parent.
	// Check existing credentials and live state before opening them by name.
	for _, name := range []string{
		"initialized", credentialPointerFile, "ui-token", "ca.pem", "authority-key.pem",
		"server.pem", "server-key.pem", "agent.pem", "agent-key.pem", "gateway.pem", "gateway-key.pem",
		".asb-human.lock", "human-approval.sqlite", "human-approval.sqlite-wal",
		"human-approval.sqlite-shm", "human-approval.sqlite-journal",
	} {
		err := checkWindowsACL(filepath.Join(dir, name), user.User.Sid, false)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func checkWindowsACL(path string, user *windows.SID, directory bool) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(name)
	if err != nil {
		return fmt.Errorf("check attributes of %q: %w", path, err)
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return fmt.Errorf("unexpected object or reparse point at private data path %q", path)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read access permissions for %q: %w", path, err)
	}
	if !privateACL(sd, user, directory) {
		return fmt.Errorf("private Windows ACL required for %q; choose a new --data-dir under your user profile, or restrict the existing directory and its contents to your account, SYSTEM and Administrators", path)
	}
	return nil
}

func privateACL(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID, directory bool) bool {
	trusted := func(sid *windows.SID) bool {
		return sid != nil && (sid.Equals(user) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
	}
	owner, _, err := sd.Owner()
	if err != nil || !trusted(owner) {
		return false
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return false
	}
	// Require a safe inheritable grant for both files and directories.
	// Otherwise child objects may fall back to the token's default DACL.
	var inherited uint8
	for i := uint16(0); i < acl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, uint32(i), &ace); err != nil {
			return false
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !trusted(sid) && !(ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 && sid.IsWellKnown(windows.WinCreatorOwnerSid)) {
				return false
			}
			if ace.Header.AceFlags&windows.NO_PROPAGATE_INHERIT_ACE == 0 {
				inherited |= ace.Header.AceFlags
			}
		default:
			return false
		}
	}
	const children = windows.CONTAINER_INHERIT_ACE | windows.OBJECT_INHERIT_ACE
	return !directory || inherited&children == children
}
