package credential

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
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

func LoadUserSession(stateDir string) (UserSession, error) {
	path := sessionFilePath(stateDir)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return UserSession{}, ErrNotFound
	}
	if err != nil || !privateOwnedRegular(info) {
		return UserSession{}, fault.New(fault.CodeCredentialStorage, "validate user session file", nil)
	}
	file, err := os.Open(path)
	if err != nil {
		return UserSession{}, fault.New(fault.CodeCredentialStorage, "open user session file", nil)
	}
	defer file.Close()
	const maximumSessionSize = 64 << 10
	raw, err := io.ReadAll(io.LimitReader(file, maximumSessionSize+1))
	if err != nil || len(raw) > maximumSessionSize {
		return UserSession{}, fault.New(fault.CodeCredentialStorage, "read user session file", nil)
	}
	var sess UserSession
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&sess); err != nil {
		return UserSession{}, fault.New(fault.CodeCredentialStorage, "decode user session file", nil)
	}
	return sess, nil
}

func SaveUserSession(stateDir string, session UserSession) error {
	dir := filepath.Join(stateDir, "protected")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fault.New(fault.CodeCredentialStorage, "create protected directory", err)
	}
	session.UpdatedAt = time.Now().UTC()
	raw, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return fault.New(fault.CodeCredentialStorage, "encode user session", err)
	}
	path := sessionFilePath(stateDir)
	tmpPath := filepath.Join(dir, ".user-session.json.tmp")
	if err := os.WriteFile(tmpPath, raw, 0600); err != nil {
		return fault.New(fault.CodeCredentialStorage, "write temp session file", err)
	}
	if err := os.Chmod(tmpPath, 0600); err != nil {
		_ = os.Remove(tmpPath)
		return fault.New(fault.CodeCredentialStorage, "chmod temp session file", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fault.New(fault.CodeCredentialStorage, "persist session file", err)
	}
	return nil
}

func DeleteUserSession(stateDir string) error {
	path := sessionFilePath(stateDir)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fault.New(fault.CodeCredentialStorage, "delete user session file", err)
	}
	return nil
}
