// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanapp

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestDataDirectoryACLPolicy(t *testing.T) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := u.User.Sid.String()
	for _, tc := range []struct {
		name, descriptor string
		allowed          bool
	}{
		{"private", "O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)", true},
		{"grants read to users", "O:" + sid + "D:(A;OICI;FA;;;SY)(A;;FR;;;BU)", false},
		{"grants read to users on children", "O:" + sid + "D:(A;OICI;FA;;;SY)(A;OICIIO;FR;;;BU)", false},
		{"owner can change permissions", "O:BUD:(A;OICI;FA;;;SY)", false},
		{"no inheritable permissions", "O:" + sid + "D:(A;;FA;;;" + sid + ")", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tc.descriptor)
			if err != nil {
				t.Fatal(err)
			}
			if got := privateACL(sd, u.User.Sid, true); got != tc.allowed {
				t.Fatalf("privateACL(directory) = %v, want %v", got, tc.allowed)
			}
		})
	}
}

func TestNewPrivateDirectoryAndInheritedChildren(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := makeDataDirectory(dir); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(dir, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateDirectory(child); err != nil {
		t.Fatal(err)
	}
}

func TestReusedCredentialHasItsOwnACLChecked(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := makeDataDirectory(dir); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "authority-key.pem")
	if err := os.WriteFile(key, []byte("test fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + u.User.Sid.String() + ")(A;;FR;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(key, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivateDirectory(dir); err == nil {
		t.Fatal("accepted a key with an independently shared ACL")
	}
}
