//go:build darwin && !ios

package credential

import (
	"context"
	"os"
)

type resilientDarwinStore struct {
	keychain *KeychainStore
	file     *FileStore
}

func (s *resilientDarwinStore) Backend() string {
	return "macos-resilient"
}

func (s *resilientDarwinStore) Load(ctx context.Context) (Record, error) {
	rec, err := s.keychain.Load(ctx)
	if err == nil {
		return rec, nil
	}
	return s.file.Load(ctx)
}

func (s *resilientDarwinStore) Save(ctx context.Context, record Record) error {
	if err := s.keychain.Save(ctx, record); err == nil {
		_ = s.file.Save(ctx, record)
		return nil
	}
	return s.file.Save(ctx, record)
}

func (s *resilientDarwinStore) Delete(ctx context.Context) error {
	_ = s.keychain.Delete(ctx)
	return s.file.Delete(ctx)
}

func NewPlatformStore(stateDirectory string) Store {
	if os.Getenv("XCONNECT_CREDENTIAL_BACKEND") == "file" {
		return NewFileStore(stateDirectory)
	}
	if os.Getenv("XCONNECT_CREDENTIAL_BACKEND") == "keychain" {
		return NewKeychainStore(stateDirectory)
	}
	return &resilientDarwinStore{
		keychain: NewKeychainStore(stateDirectory),
		file:     NewFileStore(stateDirectory),
	}
}
