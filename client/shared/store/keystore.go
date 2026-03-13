package store

import (
	"fmt"
	"os"
	"path/filepath"
)

type Keystore struct {
	Dir        string
	Passphrase string
}

func NewKeystore(dir string) *Keystore {
	return &Keystore{Dir: dir}
}

func NewKeystoreEncrypted(dir, passphrase string) *Keystore {
	return &Keystore{Dir: dir, Passphrase: passphrase}
}

func (k *Keystore) WriteFile(sessionID, filename string, data []byte) error {
	dir := filepath.Join(k.Dir, sessionID)
	err := os.MkdirAll(dir, 0o700)
	if err != nil {
		return fmt.Errorf("create keystore dir: %w", err)
	}

	toWrite := data
	if k.Passphrase != "" {
		encrypted, encErr := encryptData(data, k.Passphrase)
		if encErr != nil {
			return fmt.Errorf("encrypt keystore file: %w", encErr)
		}
		toWrite = encrypted
	}

	path := filepath.Join(dir, filename)
	return os.WriteFile(path, toWrite, 0o600)
}

func (k *Keystore) ReadFile(sessionID, filename string) ([]byte, error) {
	path := filepath.Join(k.Dir, sessionID, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if k.Passphrase != "" {
		decrypted, decErr := decryptData(data, k.Passphrase)
		if decErr != nil {
			return nil, fmt.Errorf("decrypt keystore file: %w", decErr)
		}
		return decrypted, nil
	}

	return data, nil
}

func (k *Keystore) FileExists(sessionID, filename string) bool {
	path := filepath.Join(k.Dir, sessionID, filename)
	_, err := os.Stat(path)
	return err == nil
}
