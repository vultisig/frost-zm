package mnemonic

import (
	"crypto/sha512"
	"fmt"
	"math/big"
	"strings"

	legacymnemonic "github.com/dimalinux/gopherphis/mnemonic"
	"github.com/dimalinux/gopherphis/polyseed"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"
)

func init() {
	polyseed.SetPackageCoin(polyseed.MoneroCoin)
}

func DeriveMoneroSeed(phrase string) ([]byte, error) {
	words := strings.Fields(strings.TrimSpace(phrase))

	switch len(words) {
	case 16:
		return deriveFromPolyseed(words)
	case 12, 24:
		return deriveFromBIP39(words)
	case 25, 13:
		return deriveFromLegacy(words)
	default:
		return nil, fmt.Errorf("unsupported mnemonic word count: %d (expected 12, 13, 16, 24, or 25)", len(words))
	}
}

func deriveFromPolyseed(words []string) ([]byte, error) {
	seedData, err := polyseed.CreateSeedData(words)
	if err != nil {
		return nil, fmt.Errorf("invalid polyseed: %w", err)
	}
	defer seedData.Clear()

	return seedData.KeyGen(), nil
}

func deriveFromBIP39(words []string) ([]byte, error) {
	joined := strings.Join(words, " ")
	if !bip39.IsMnemonicValid(joined) {
		return nil, fmt.Errorf("invalid BIP39 checksum")
	}

	bip39Seed := pbkdf2.Key(
		[]byte(joined),
		[]byte("mnemonic"),
		2048,
		64,
		sha512.New,
	)

	masterKey, err := bip32.NewMasterKey(bip39Seed)
	if err != nil {
		return nil, fmt.Errorf("bip32 master key: %w", err)
	}

	// m/44'/128'/0'/0/0  (Cake Wallet Monero BIP39 path)
	path := []uint32{
		bip32.FirstHardenedChild + 44,  // 44'
		bip32.FirstHardenedChild + 128, // 128'
		bip32.FirstHardenedChild + 0,   // 0'
		0,                              // 0
		0,                              // 0
	}

	key := masterKey
	for _, idx := range path {
		key, err = key.NewChildKey(idx)
		if err != nil {
			return nil, fmt.Errorf("bip32 child %d: %w", idx, err)
		}
	}

	return scReduce32(key.Key), nil
}

var ed25519Order, _ = new(big.Int).SetString("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED", 16)

func scReduce32(key []byte) []byte {
	k := new(big.Int).SetBytes(reverseBytes(key))
	k.Mod(k, ed25519Order)

	result := make([]byte, 32)
	kBytes := k.Bytes()
	for i, b := range kBytes {
		result[len(kBytes)-1-i] = b
	}
	return result
}

func reverseBytes(b []byte) []byte {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return r
}

func deriveFromLegacy(words []string) ([]byte, error) {
	key, err := legacymnemonic.CreateKeyFromSeeds(words)
	if err != nil {
		return nil, fmt.Errorf("invalid legacy mnemonic: %w", err)
	}

	return key, nil
}
