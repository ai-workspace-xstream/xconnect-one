//go:build darwin && !ios

package credential

import "os"

func NewPlatformStore(stateDirectory string) Store {
	if os.Getenv("XCONNECT_CREDENTIAL_BACKEND") == "keychain" {
		return NewKeychainStore(stateDirectory)
	}
	return NewFileStore(stateDirectory)
}
