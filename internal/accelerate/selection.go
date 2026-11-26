package accelerate

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
)

const selectionFile = "acceleration-node.json"

type selection struct {
	Server  string `json:"server"`
	Account string `json:"account"`
	NodeKey string `json:"node_key"`
}

func account(session credential.UserSession) string {
	if session.UserID != "" {
		return session.UserID
	}
	return session.Email
}

func SaveSelection(stateDir string, session credential.UserSession, node Node) error {
	if session.Server == "" || account(session) == "" || node.Key == "" {
		return errors.New("current login session cannot be bound to an acceleration node")
	}
	if err := credential.EnsureWritableStateDir(stateDir); err != nil {
		return err
	}
	dir := filepath.Join(stateDir, "protected")
	file, err := os.CreateTemp(dir, ".acceleration-node-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := json.NewEncoder(file).Encode(selection{session.Server, account(session), node.Key}); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), filepath.Join(dir, selectionFile))
}

func LoadSelection(stateDir string, session credential.UserSession) (string, error) {
	file, err := os.Open(filepath.Join(stateDir, "protected", selectionFile))
	if errors.Is(err, os.ErrNotExist) {
		return "", errors.New("choose a node first with xconnect accelerate join")
	}
	if err != nil {
		return "", err
	}
	defer file.Close()
	var selected selection
	data, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(data) > 8192 || json.Unmarshal(data, &selected) != nil || selected.NodeKey == "" {
		return "", errors.New("invalid node selection; run xconnect accelerate join again")
	}
	if selected.Server != session.Server || selected.Account == "" || selected.Account != account(session) {
		return "", errors.New("node selection belongs to another login; run xconnect accelerate join again")
	}
	return selected.NodeKey, nil
}
