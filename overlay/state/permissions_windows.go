//go:build windows

package state

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

const (
	privateStateDirSDDL  = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"
	privateStateFileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)"
)

func secureStateDirectory(path string) error { return setPrivateStateACL(path, privateStateDirSDDL) }

func secureStateFile(path string) error { return setPrivateStateACL(path, privateStateFileSDDL) }

func preserveSudoDirectoryOwnership(string, bool) {}

func preserveSudoFileOwnership(string, string) {}

func replaceStateFile(source, target string) error {
	sourcePath, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	targetPath, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(sourcePath, targetPath, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func privateStateDirectory(path string, info os.FileInfo) bool {
	return info != nil && info.IsDir() && hasPrivateStateACL(path, true)
}

func privateStateRegular(path string, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && hasPrivateStateACL(path, false)
}

func statePermissionOK(path string, info os.FileInfo, expected os.FileMode) bool {
	if info == nil {
		return false
	}
	switch expected {
	case 0o700:
		return info.IsDir() && hasPrivateStateACL(path, true)
	case 0o600:
		return info.Mode().IsRegular() && hasPrivateStateACL(path, false)
	default:
		return false
	}
}

func setPrivateStateACL(path, sddl string) error {
	securityDescriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := securityDescriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
}

func hasPrivateStateACL(path string, isDir bool) bool {
	securityDescriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || securityDescriptor == nil {
		return false
	}
	control, _, err := securityDescriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	// SecurityDescriptor.String() includes owner/group sections before the
	// DACL on normal NTFS files (for example `O:...G:...D:P...`).  Checking
	// the whole string for a DACL prefix therefore rejects a file immediately
	// after we secured it.  Inspect only the DACL fragment and keep rejecting
	// any unexpected ACE there.
	sddl := securityDescriptor.String()
	daclOffset := strings.Index(sddl, "D:")
	if daclOffset < 0 {
		return false
	}
	body := strings.TrimPrefix(sddl[daclOffset+len("D:"):], "P")
	if body == sddl[daclOffset+len("D:"):] {
		return false
	}
	// Windows may retain the auto-inherited marker after an ACL is protected.
	// It is metadata, not an additional principal grant.
	body = strings.TrimPrefix(body, "AI")
	for _, principal := range []string{"SY", "BA", "OW"} {
		fileACE := "(A;;FA;;;" + principal + ")"
		dirACE := "(A;OICI;FA;;;" + principal + ")"
		switch {
		case isDir && strings.Count(body, dirACE) == 1 && strings.Count(body, fileACE) == 0:
			body = strings.Replace(body, dirACE, "", 1)
		case strings.Count(body, fileACE) == 1 && (!isDir || strings.Count(body, dirACE) == 0):
			body = strings.Replace(body, fileACE, "", 1)
		default:
			return false
		}
	}
	return body == ""
}
