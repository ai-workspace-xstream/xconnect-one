//go:build darwin && !ios

package credential

import "os"

func NewPlatformStore(stateDirectory string) Store {
	if os.Getenv("XCONNECT_CREDENTIAL_BACKEND") == "file" {
		return NewFileStore(stateDirectory)
	}
	return NewKeychainStore(stateDirectory)
}
