package vault

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	frozt "github.com/vultisig/frosty-lib/go/frozt"

	"github.com/vultisig/frosty-lib/client/frozt/internal/bip39"
	sharedvault "github.com/vultisig/frosty-lib/client/shared/vault"

	v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"
	keygenV1 "github.com/vultisig/commondata/go/vultisig/keygen/v1"
)

func TestVultRoundTrip(t *testing.T) {
	mnemonic, birthday, expectedAddr := loadEnv(t)

	t.Log("=== BIP39 seed derivation ===")
	seed := bip39.MnemonicToSeed(mnemonic)

	t.Log("=== Key import 2-of-3 ===")
	result := runKeyImport(t, 3, 2, seed, 0)

	verifyingKey, err := frozt.PubKeyPackageVerifyingKey(result.pubKeyPackage)
	if err != nil {
		t.Fatalf("PubKeyPackageVerifyingKey: %v", err)
	}
	vkHex := hex.EncodeToString(verifyingKey)

	keys, err := frozt.SaplingDeriveKeys(result.pubKeyPackage, result.extras)
	if err != nil {
		t.Fatalf("SaplingDeriveKeys: %v", err)
	}
	if keys.Address != expectedAddr {
		t.Fatalf("address mismatch:\n  got:  %s\n  want: %s", keys.Address, expectedAddr)
	}
	t.Logf("z-address: %s", keys.Address)
	t.Logf("verifying key: %s", vkHex)

	t.Log("=== Build .vult file per party ===")
	tmpDir := t.TempDir()

	signers := []string{"party-1", "party-2", "party-3"}

	for i, kp := range result.keyPackages {
		bundle, bundleErr := frozt.KeyShareBundlePack(kp, result.pubKeyPackage, result.extras, uint64(birthday))
		if bundleErr != nil {
			t.Fatalf("KeyShareBundlePack party %d: %v", i+1, bundleErr)
		}

		entry := sharedvault.FroztChainKeyEntry(bundle, vkHex)

		vault := &v1.Vault{
			Name:           fmt.Sprintf("frozt-test-party-%d", i+1),
			Signers:        signers,
			LocalPartyId:   signers[i],
			LibType:        keygenV1.LibType_LIB_TYPE_KEYIMPORT,
		}
		sharedvault.SetChainKeyEntry(vault, entry)

		data, buildErr := sharedvault.BuildVultFile(vault)
		if buildErr != nil {
			t.Fatalf("BuildVultFile party %d: %v", i+1, buildErr)
		}

		path := filepath.Join(tmpDir, fmt.Sprintf("party-%d.vult", i+1))
		writeErr := os.WriteFile(path, data, 0o600)
		if writeErr != nil {
			t.Fatalf("WriteFile party %d: %v", i+1, writeErr)
		}

		info, _ := os.Stat(path)
		t.Logf("exported party-%d.vult (%d bytes)", i+1, info.Size())
	}

	t.Log("=== Re-import .vult files and verify ===")
	importedKPs := make([][]byte, 3)
	var importedPKP []byte
	var importedExtras []byte

	for i := 0; i < 3; i++ {
		path := filepath.Join(tmpDir, fmt.Sprintf("party-%d.vult", i+1))
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("ReadFile party %d: %v", i+1, readErr)
		}

		parsedVault, parseErr := sharedvault.ParseVultFile(data)
		if parseErr != nil {
			t.Fatalf("ParseVultFile party %d: %v", i+1, parseErr)
		}

		if parsedVault.Name != fmt.Sprintf("frozt-test-party-%d", i+1) {
			t.Fatalf("vault name mismatch party %d: %s", i+1, parsedVault.Name)
		}
		if parsedVault.LocalPartyId != signers[i] {
			t.Fatalf("local party id mismatch party %d: %s", i+1, parsedVault.LocalPartyId)
		}
		if parsedVault.LibType != keygenV1.LibType_LIB_TYPE_KEYIMPORT {
			t.Fatalf("lib_type mismatch party %d: %v", i+1, parsedVault.LibType)
		}

		chainEntry, found := sharedvault.FindChainKeyEntry(parsedVault, sharedvault.ChainZcashSapling)
		if !found {
			t.Fatalf("ZcashSapling chain key entry not found in party %d", i+1)
		}
		if chainEntry.PublicKey != vkHex {
			t.Fatalf("public key mismatch party %d:\n  got:  %s\n  want: %s", i+1, chainEntry.PublicKey, vkHex)
		}

		bundleBytes, vk, decodeErr := sharedvault.ParseChainKeyEntry(chainEntry)
		if decodeErr != nil {
			t.Fatalf("ParseChainKeyEntry party %d: %v", i+1, decodeErr)
		}
		if !bytes.Equal(vk, verifyingKey) {
			t.Fatalf("decoded verifying key mismatch party %d", i+1)
		}

		kpBytes, kpErr := frozt.KeyShareBundleKeyPackage(bundleBytes)
		if kpErr != nil {
			t.Fatalf("KeyShareBundleKeyPackage party %d: %v", i+1, kpErr)
		}
		pkpBytes, pkpErr := frozt.KeyShareBundlePubKeyPackage(bundleBytes)
		if pkpErr != nil {
			t.Fatalf("KeyShareBundlePubKeyPackage party %d: %v", i+1, pkpErr)
		}
		extrasBytes, extErr := frozt.KeyShareBundleSaplingExtras(bundleBytes)
		if extErr != nil {
			t.Fatalf("KeyShareBundleSaplingExtras party %d: %v", i+1, extErr)
		}
		bday, bdayErr := frozt.KeyShareBundleBirthday(bundleBytes)
		if bdayErr != nil {
			t.Fatalf("KeyShareBundleBirthday party %d: %v", i+1, bdayErr)
		}
		if bday != uint64(birthday) {
			t.Fatalf("birthday mismatch party %d: got %d, want %d", i+1, bday, birthday)
		}

		importedKPs[i] = kpBytes
		if i == 0 {
			importedPKP = pkpBytes
			importedExtras = extrasBytes
		}

		t.Logf("party %d: bundle=%d bytes, kp=%d bytes, pkp=%d bytes, extras=%d bytes, birthday=%d",
			i+1, len(bundleBytes), len(kpBytes), len(pkpBytes), len(extrasBytes), bday)
	}

	t.Log("=== Re-derive address from imported shares ===")
	reKeys, err := frozt.SaplingDeriveKeys(importedPKP, importedExtras)
	if err != nil {
		t.Fatalf("re-derive SaplingDeriveKeys: %v", err)
	}
	if reKeys.Address != expectedAddr {
		t.Fatalf("re-derived address mismatch:\n  got:  %s\n  want: %s", reKeys.Address, expectedAddr)
	}
	t.Logf("re-derived z-address: %s", reKeys.Address)

	t.Log("=== Sign with imported .vult shares (parties 0,1) ===")
	sig1 := runSign(t, importedKPs, importedPKP, []int{0, 1}, []byte("vult round-trip test"))
	t.Logf("signature (0,1): %x (%d bytes)", sig1, len(sig1))

	t.Log("=== Sign with imported .vult shares (parties 1,2) ===")
	sig2 := runSign(t, importedKPs, importedPKP, []int{1, 2}, []byte("vult round-trip test"))
	t.Logf("signature (1,2): %x (%d bytes)", sig2, len(sig2))

	t.Log("=== .vult round-trip test passed ===")
}
