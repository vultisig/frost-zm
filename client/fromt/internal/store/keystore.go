package store

import (
	"github.com/vultisig/frost-zm/client/shared/store"
)

type Keystore struct {
	base *store.Keystore
}

func NewKeystore(dir string) *Keystore {
	return &Keystore{base: store.NewKeystore(dir)}
}

func NewKeystoreEncrypted(dir, passphrase string) *Keystore {
	return &Keystore{base: store.NewKeystoreEncrypted(dir, passphrase)}
}

func (k *Keystore) SaveBundle(sessionID string, data []byte) error {
	return k.base.WriteFile(sessionID, "bundle.bin", data)
}

func (k *Keystore) LoadBundle(sessionID string) ([]byte, error) {
	return k.base.ReadFile(sessionID, "bundle.bin")
}

func (k *Keystore) HasBundle(sessionID string) bool {
	return k.base.FileExists(sessionID, "bundle.bin")
}

func (k *Keystore) SaveKeyShare(sessionID string, data []byte) error {
	return k.base.WriteFile(sessionID, "key_share.bin", data)
}

func (k *Keystore) SavePubKey(sessionID string, data []byte) error {
	return k.base.WriteFile(sessionID, "pub_key.bin", data)
}

func (k *Keystore) LoadKeyShare(sessionID string) ([]byte, error) {
	if k.HasBundle(sessionID) {
		return k.LoadBundle(sessionID)
	}
	return k.base.ReadFile(sessionID, "key_share.bin")
}

func (k *Keystore) LoadPubKey(sessionID string) ([]byte, error) {
	return k.base.ReadFile(sessionID, "pub_key.bin")
}

func (k *Keystore) HasKeys(sessionID string) bool {
	return k.base.FileExists(sessionID, "key_share.bin")
}

func (k *Keystore) SaveSpentOffsets(sessionID string, offsets []byte) error {
	existing, _ := k.LoadSpentOffsets(sessionID)
	combined := append(existing, offsets...)
	return k.base.WriteFile(sessionID, "spent_offsets.bin", combined)
}

func (k *Keystore) LoadSpentOffsets(sessionID string) ([]byte, error) {
	return k.base.ReadFile(sessionID, "spent_offsets.bin")
}
