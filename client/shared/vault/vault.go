package vault

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"
	"google.golang.org/protobuf/proto"
)

const (
	ChainZcashSapling = "ZcashSapling"
	ChainMonero       = "Monero"
	ChainEthereum     = "Ethereum"
)

type ChainKeyEntry struct {
	Chain     string
	PublicKey string
	KeyShare  string
}

func FroztChainKeyEntry(bundle []byte, verifyingKeyHex string) ChainKeyEntry {
	return ChainKeyEntry{
		Chain:     ChainZcashSapling,
		PublicKey: verifyingKeyHex,
		KeyShare:  base64.StdEncoding.EncodeToString(bundle),
	}
}

func FroethChainKeyEntry(bundle []byte, verifyingKeyHex string) ChainKeyEntry {
	return ChainKeyEntry{
		Chain:     ChainEthereum,
		PublicKey: verifyingKeyHex,
		KeyShare:  base64.StdEncoding.EncodeToString(bundle),
	}
}

func FromtChainKeyEntry(bundle []byte, verifyingKeyHex string) ChainKeyEntry {
	return ChainKeyEntry{
		Chain:     ChainMonero,
		PublicKey: verifyingKeyHex,
		KeyShare:  base64.StdEncoding.EncodeToString(bundle),
	}
}

func ParseChainKeyEntry(entry ChainKeyEntry) (bundle []byte, verifyingKey []byte, err error) {
	bundle, err = base64.StdEncoding.DecodeString(entry.KeyShare)
	if err != nil {
		return nil, nil, fmt.Errorf("decode keyshare: %w", err)
	}
	verifyingKey, err = hex.DecodeString(entry.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decode public key: %w", err)
	}
	return bundle, verifyingKey, nil
}

func ParseVultContainer(data []byte) (*v1.VaultContainer, error) {
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("base64 decode container: %w", err)
	}
	var container v1.VaultContainer
	err = proto.Unmarshal(decoded, &container)
	if err != nil {
		return nil, fmt.Errorf("unmarshal container: %w", err)
	}
	return &container, nil
}

func ParseVault(vaultBase64 string) (*v1.Vault, error) {
	vaultBytes, err := base64.StdEncoding.DecodeString(vaultBase64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode vault: %w", err)
	}
	var vault v1.Vault
	err = proto.Unmarshal(vaultBytes, &vault)
	if err != nil {
		return nil, fmt.Errorf("unmarshal vault: %w", err)
	}
	return &vault, nil
}

func ParseVultFile(data []byte) (*v1.Vault, error) {
	container, err := ParseVultContainer(data)
	if err != nil {
		return nil, err
	}
	if container.IsEncrypted {
		return nil, fmt.Errorf("vault is encrypted, password decryption not supported")
	}
	return ParseVault(container.Vault)
}

func BuildVultFile(vault *v1.Vault) ([]byte, error) {
	vaultBytes, err := proto.Marshal(vault)
	if err != nil {
		return nil, fmt.Errorf("marshal vault: %w", err)
	}
	container := &v1.VaultContainer{
		Version:     1,
		Vault:       base64.StdEncoding.EncodeToString(vaultBytes),
		IsEncrypted: false,
	}
	containerBytes, err := proto.Marshal(container)
	if err != nil {
		return nil, fmt.Errorf("marshal container: %w", err)
	}
	return []byte(base64.StdEncoding.EncodeToString(containerBytes)), nil
}

func FindChainKeyEntry(vault *v1.Vault, chain string) (ChainKeyEntry, bool) {
	var publicKey string
	for _, cpk := range vault.ChainPublicKeys {
		if cpk.Chain == chain {
			publicKey = cpk.PublicKey
			break
		}
	}
	if publicKey == "" {
		return ChainKeyEntry{}, false
	}
	for _, ks := range vault.KeyShares {
		if ks.PublicKey == publicKey {
			return ChainKeyEntry{
				Chain:     chain,
				PublicKey: publicKey,
				KeyShare:  ks.Keyshare,
			}, true
		}
	}
	return ChainKeyEntry{}, false
}

func SetChainKeyEntry(vault *v1.Vault, entry ChainKeyEntry) {
	found := false
	for _, cpk := range vault.ChainPublicKeys {
		if cpk.Chain == entry.Chain {
			cpk.PublicKey = entry.PublicKey
			found = true
			break
		}
	}
	if !found {
		vault.ChainPublicKeys = append(vault.ChainPublicKeys, &v1.Vault_ChainPublicKey{
			Chain:     entry.Chain,
			PublicKey: entry.PublicKey,
		})
	}

	ksFound := false
	for _, ks := range vault.KeyShares {
		if ks.PublicKey == entry.PublicKey {
			ks.Keyshare = entry.KeyShare
			ksFound = true
			break
		}
	}
	if !ksFound {
		vault.KeyShares = append(vault.KeyShares, &v1.Vault_KeyShare{
			PublicKey: entry.PublicKey,
			Keyshare:  entry.KeyShare,
		})
	}
}
