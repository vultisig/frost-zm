package store

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

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

func (k *Keystore) SaveKeyPackage(sessionID string, data []byte) error {
	return k.base.WriteFile(sessionID, "key_package.bin", data)
}

func (k *Keystore) SavePubKeyPackage(sessionID string, data []byte) error {
	return k.base.WriteFile(sessionID, "pub_key_package.bin", data)
}

func (k *Keystore) LoadKeyPackage(sessionID string) ([]byte, error) {
	return k.base.ReadFile(sessionID, "key_package.bin")
}

func (k *Keystore) LoadPubKeyPackage(sessionID string) ([]byte, error) {
	return k.base.ReadFile(sessionID, "pub_key_package.bin")
}

func (k *Keystore) SaveSaplingExtras(sessionID string, data []byte) error {
	return k.base.WriteFile(sessionID, "sapling_extras.bin", data)
}

func (k *Keystore) LoadSaplingExtras(sessionID string) ([]byte, error) {
	return k.base.ReadFile(sessionID, "sapling_extras.bin")
}

type SpentNote struct {
	TxHash string `json:"tx_hash"`
	Index  int    `json:"index"`
	Height uint64 `json:"height"`
}

func (k *Keystore) MarkNoteSpent(sessionID string, txHash []byte, index int, height uint64) error {
	spent, _ := k.LoadSpentNotes(sessionID)
	spent = append(spent, SpentNote{
		TxHash: hex.EncodeToString(txHash),
		Index:  index,
		Height: height,
	})
	data, err := json.Marshal(spent)
	if err != nil {
		return fmt.Errorf("marshal spent notes: %w", err)
	}
	return k.base.WriteFile(sessionID, "spent_notes.json", data)
}

func (k *Keystore) LoadSpentNotes(sessionID string) ([]SpentNote, error) {
	data, err := k.base.ReadFile(sessionID, "spent_notes.json")
	if err != nil {
		return nil, nil
	}
	var notes []SpentNote
	err = json.Unmarshal(data, &notes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal spent notes: %w", err)
	}
	return notes, nil
}

func (k *Keystore) IsNoteSpent(sessionID string, txHash []byte, index int) bool {
	spent, _ := k.LoadSpentNotes(sessionID)
	txHashHex := hex.EncodeToString(txHash)
	for _, s := range spent {
		if s.TxHash == txHashHex && s.Index == index {
			return true
		}
	}
	return false
}

func (k *Keystore) SaveBundle(sessionID string, data []byte) error {
	return k.base.WriteFile(sessionID, "keyshare_bundle.bin", data)
}

func (k *Keystore) LoadBundle(sessionID string) ([]byte, error) {
	return k.base.ReadFile(sessionID, "keyshare_bundle.bin")
}

func (k *Keystore) HasBundle(sessionID string) bool {
	return k.base.FileExists(sessionID, "keyshare_bundle.bin")
}

func (k *Keystore) HasKeys(sessionID string) bool {
	return k.base.FileExists(sessionID, "key_package.bin")
}
