package credential

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

type UserSession struct {
	Server       string    `json:"server"`
	Email        string    `json:"email,omitempty"`
	UserID       string    `json:"user_id,omitempty"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func sessionFilePath(stateDir string) string {
	return filepath.Join(stateDir, "protected", "user-session.json")
}

// CheckStateDirectoryUsability returns an empty string if stateDir can be read
// and written by the current user, or a short reason describing why it cannot.
func CheckStateDirectoryUsability(stateDir string) string {
	trimmed := strings.TrimSpace(stateDir)
	if trimmed == "" {
		return "empty state directory"
	}
	if reason := checkDirUsable(trimmed); reason != "" {
		return reason
	}
	protectedDir := filepath.Join(trimmed, "protected")
	info, err := os.Lstat(protectedDir)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return "permission denied"
		}
		return err.Error()
	}
	if !info.IsDir() {
		return "protected path is not a directory"
	}
	if uid, ok := directoryOwnerUID(info); ok && os.Geteuid() > 0 && uid != uint32(os.Geteuid()) {
		if uid == 0 {
			return "owned by root"
		}
		return fmt.Sprintf("owned by uid %d", uid)
	}
	if !isDirectoryWritableByCurrentUser(protectedDir) {
		return "not writable by current user"
	}
	return ""
}

// CheckStateDirectoryUsabilityForUID evaluates usability of stateDir from the
// perspective of targetUID (for example, the sudo-invoking user when running
// as euid 0). If targetUID == 0 or euid != 0, it falls back to
// CheckStateDirectoryUsability.
func CheckStateDirectoryUsabilityForUID(stateDir string, targetUID uint32) string {
	if os.Geteuid() != 0 || targetUID == 0 {
		return CheckStateDirectoryUsability(stateDir)
	}
	trimmed := strings.TrimSpace(stateDir)
	if trimmed == "" {
		return "empty state directory"
	}
	for _, checkPath := range []string{trimmed, filepath.Join(trimmed, "protected")} {
		info, err := os.Lstat(checkPath)
		if errors.Is(err, os.ErrNotExist) {
			if checkPath == trimmed {
				parent := nearestExistingAncestor(trimmed)
				if parent == "" {
					return "parent directory unavailable"
				}
				pInfo, pErr := os.Lstat(parent)
				if pErr != nil {
					return pErr.Error()
				}
				if !pInfo.IsDir() {
					return "parent path is not a directory"
				}
				if ownerUID, ok := directoryOwnerUID(pInfo); ok && ownerUID != targetUID {
					if ownerUID == 0 {
						return "parent directory owned by root"
					}
					return fmt.Sprintf("parent directory owned by uid %d", ownerUID)
				}
			}
			continue
		}
		if err != nil {
			return err.Error()
		}
		if !info.IsDir() {
			return "not a directory"
		}
		if ownerUID, ok := directoryOwnerUID(info); ok && ownerUID != targetUID {
			if ownerUID == 0 {
				return "owned by root"
			}
			return fmt.Sprintf("owned by uid %d", ownerUID)
		}
		if info.Mode().Perm()&0o700 != 0o700 {
			return "not writable by invoking user"
		}
	}
	return ""
}

func checkDirUsable(dir string) string {
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		parent := nearestExistingAncestor(dir)
		if parent == "" {
			return "parent directory unavailable"
		}
		pInfo, pErr := os.Lstat(parent)
		if pErr != nil {
			if errors.Is(pErr, os.ErrPermission) {
				return "parent directory permission denied"
			}
			return pErr.Error()
		}
		if !pInfo.IsDir() {
			return "parent path is not a directory"
		}
		if !isDirectoryWritableByCurrentUser(parent) {
			if uid, ok := directoryOwnerUID(pInfo); ok && os.Geteuid() > 0 && uid == 0 {
				return "parent directory owned by root"
			}
			return "parent directory not writable by current user"
		}
		return ""
	}
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return "permission denied"
		}
		return err.Error()
	}
	if !info.IsDir() {
		return "not a directory"
	}
	if uid, ok := directoryOwnerUID(info); ok && os.Geteuid() > 0 && uid != uint32(os.Geteuid()) {
		if uid == 0 {
			return "owned by root"
		}
		return fmt.Sprintf("owned by uid %d", uid)
	}
	if !isDirectoryWritableByCurrentUser(dir) {
		return "not writable by current user"
	}
	return ""
}

func nearestExistingAncestor(path string) string {
	clean := filepath.Clean(path)
	for {
		parent := filepath.Dir(clean)
		if parent == clean {
			if _, err := os.Lstat(parent); err == nil {
				return parent
			}
			return ""
		}
		if _, err := os.Lstat(parent); err == nil {
			return parent
		} else if !errors.Is(err, os.ErrNotExist) {
			return parent
		}
		clean = parent
	}
}

// EnsureWritableStateDir validates that stateDir (and its protected directory,
// if present) can be written by the current user, returning an actionable
// CodeCredentialStorage fault if not.
func EnsureWritableStateDir(stateDir string) error {
	trimmed := strings.TrimSpace(stateDir)
	if trimmed == "" {
		return fault.New(fault.CodeCredentialStorage, "state directory cannot be empty", nil)
	}
	if reason := CheckStateDirectoryUsability(trimmed); reason != "" {
		return fault.New(fault.CodeCredentialStorage, describeDirectoryAccessError(trimmed, trimmed, "validate state directory", os.ErrPermission), os.ErrPermission)
	}
	return nil
}

func describeDirectoryAccessError(stateDir, targetDir, action string, err error) string {
	for _, candidate := range []string{targetDir, stateDir, nearestExistingAncestor(targetDir)} {
		if candidate == "" {
			continue
		}
		info, statErr := os.Lstat(candidate)
		if statErr != nil {
			continue
		}
		if !info.IsDir() {
			return fmt.Sprintf("%s %q: path %q is not a directory (pass --state-dir with a user-writable directory)", action, targetDir, candidate)
		}
		if uid, ok := directoryOwnerUID(info); ok && os.Geteuid() > 0 && uid != uint32(os.Geteuid()) {
			if uid == 0 {
				return fmt.Sprintf("%s %q: permission denied (directory %q is owned by root; run 'sudo chown -R $(id -un):$(id -gn) %s' or pass --state-dir with a user-writable directory)", action, targetDir, candidate, stateDir)
			}
			return fmt.Sprintf("%s %q: permission denied (directory %q is owned by uid %d, current euid %d; fix ownership or pass --state-dir with a user-writable directory)", action, targetDir, candidate, uid, os.Geteuid())
		}
	}
	if errors.Is(err, os.ErrPermission) {
		return fmt.Sprintf("%s %q: permission denied (directory is not writable by current user; check permissions with 'chmod 700 %s' or pass --state-dir with a user-writable directory)", action, targetDir, stateDir)
	}
	return fmt.Sprintf("%s %q: %v", action, targetDir, err)
}

func LoadUserSession(stateDir string) (UserSession, error) {
	path := sessionFilePath(stateDir)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return UserSession{}, ErrNotFound
	}
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return UserSession{}, fault.New(fault.CodeCredentialStorage, describeDirectoryAccessError(stateDir, filepath.Dir(path), "access protected directory", err), err)
		}
		return UserSession{}, fault.New(fault.CodeCredentialStorage, "validate user session file", err)
	}
	if !privateOwnedRegularForStateDir(info, stateDir) {
		return UserSession{}, fault.New(fault.CodeCredentialStorage, "validate user session file", nil)
	}
	file, err := os.Open(path)
	if err != nil {
		return UserSession{}, fault.New(fault.CodeCredentialStorage, "open user session file", err)
	}
	defer file.Close()
	const maximumSessionSize = 64 << 10
	raw, err := io.ReadAll(io.LimitReader(file, maximumSessionSize+1))
	if err != nil || len(raw) > maximumSessionSize {
		return UserSession{}, fault.New(fault.CodeCredentialStorage, "read user session file", err)
	}
	var sess UserSession
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&sess); err != nil {
		return UserSession{}, fault.New(fault.CodeCredentialStorage, "decode user session file", err)
	}
	return sess, nil
}

func SaveUserSession(stateDir string, session UserSession) error {
	if strings.TrimSpace(stateDir) == "" {
		return fault.New(fault.CodeCredentialStorage, "state directory cannot be empty", nil)
	}
	dir := filepath.Join(stateDir, "protected")
	_, stateExistedErr := os.Lstat(stateDir)
	_, dirExistedErr := os.Lstat(dir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fault.New(fault.CodeCredentialStorage, describeDirectoryAccessError(stateDir, dir, "create protected directory", err), err)
	}
	if sudoUID, sudoGID, ok := sudoInvokerUIDGID(); ok {
		if errors.Is(stateExistedErr, os.ErrNotExist) {
			chownToSudoInvokerIfMatching(stateDir, sudoUID, sudoGID)
		}
		if errors.Is(dirExistedErr, os.ErrNotExist) {
			chownToSudoInvokerIfMatching(dir, sudoUID, sudoGID)
		}
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || !isDirectoryWritableByCurrentUser(dir) {
		if err == nil {
			err = os.ErrPermission
		}
		return fault.New(fault.CodeCredentialStorage, describeDirectoryAccessError(stateDir, dir, "validate protected directory", err), err)
	}
	if uid, ok := directoryOwnerUID(info); ok && os.Geteuid() > 0 && uid != uint32(os.Geteuid()) {
		return fault.New(fault.CodeCredentialStorage, describeDirectoryAccessError(stateDir, dir, "validate protected directory", os.ErrPermission), os.ErrPermission)
	}
	session.UpdatedAt = time.Now().UTC()
	raw, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return fault.New(fault.CodeCredentialStorage, "encode user session", err)
	}
	path := sessionFilePath(stateDir)
	tmpPath := filepath.Join(dir, ".user-session.json.tmp")
	if err := os.WriteFile(tmpPath, raw, 0600); err != nil {
		return fault.New(fault.CodeCredentialStorage, describeDirectoryAccessError(stateDir, dir, "write temp session file", err), err)
	}
	if sudoUID, sudoGID, ok := sudoInvokerUIDGID(); ok {
		if ownerUID, hasOwner := directoryOwnerUID(info); hasOwner && ownerUID == sudoUID {
			chownToSudoInvokerIfMatching(tmpPath, sudoUID, sudoGID)
		}
	}
	if err := os.Chmod(tmpPath, 0600); err != nil {
		_ = os.Remove(tmpPath)
		return fault.New(fault.CodeCredentialStorage, "chmod temp session file", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fault.New(fault.CodeCredentialStorage, describeDirectoryAccessError(stateDir, dir, "persist session file", err), err)
	}
	return nil
}

func DeleteUserSession(stateDir string) error {
	path := sessionFilePath(stateDir)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		if errors.Is(err, os.ErrPermission) {
			return fault.New(fault.CodeCredentialStorage, describeDirectoryAccessError(stateDir, filepath.Dir(path), "delete user session file", err), err)
		}
		return fault.New(fault.CodeCredentialStorage, "delete user session file", err)
	}
	return nil
}
