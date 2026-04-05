package vult

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"

	v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"
	keygenV1 "github.com/vultisig/commondata/go/vultisig/keygen/v1"

	fromt "github.com/vultisig/frosty-lib/go/fromt"
	frozts "github.com/vultisig/frosty-lib/go/frozts"

	sharedconfig "github.com/vultisig/frosty-lib/client/shared/config"
	sharedvault "github.com/vultisig/frosty-lib/client/shared/vault"
)

func loadDotEnv(t *testing.T) map[string]string {
	t.Helper()
	path := filepath.Join("..", "..", ".env")
	env, err := sharedconfig.LoadDotEnv(path)
	if err != nil {
		t.Fatalf("LoadDotEnv: %v", err)
	}
	return env
}

func zcashSeedFromMnemonic(mnemonic string) []byte {
	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"), 2048, 64, sha512.New)
}

var ed25519Order, _ = new(big.Int).SetString("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED", 16)

func scReduce32(key []byte) []byte {
	reversed := make([]byte, len(key))
	for i, b := range key {
		reversed[len(key)-1-i] = b
	}
	k := new(big.Int).SetBytes(reversed)
	k.Mod(k, ed25519Order)
	result := make([]byte, 32)
	kBytes := k.Bytes()
	for i, b := range kBytes {
		result[len(kBytes)-1-i] = b
	}
	return result
}

func moneroSeedFromMnemonic(t *testing.T, mnemonic string) []byte {
	t.Helper()
	if !bip39.IsMnemonicValid(mnemonic) {
		t.Fatalf("invalid BIP39 mnemonic for Monero derivation")
	}
	bip39Seed := pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"), 2048, 64, sha512.New)

	masterKey, err := bip32.NewMasterKey(bip39Seed)
	if err != nil {
		t.Fatalf("bip32 master key: %v", err)
	}

	path := []uint32{
		bip32.FirstHardenedChild + 44,
		bip32.FirstHardenedChild + 128,
		bip32.FirstHardenedChild + 0,
		0,
		0,
	}
	key := masterKey
	for _, idx := range path {
		key, err = key.NewChildKey(idx)
		if err != nil {
			t.Fatalf("bip32 child %d: %v", idx, err)
		}
	}
	return scReduce32(key.Key)
}

type froztsKeyImportResult struct {
	keyPackages   [][]byte
	pubKeyPackage []byte
	vk            []byte
	extras        []byte
}

func runFroztKeyImport(t *testing.T, n, threshold uint16, seed []byte, accountIndex uint32) froztsKeyImportResult {
	t.Helper()

	type party struct {
		id     uint16
		secret frozts.DkgSecretHandle
		r1Pkg  []byte
	}

	parties := make([]party, n)
	var vk []byte
	var extras []byte
	for i := uint16(0); i < n; i++ {
		id := i + 1
		var s []byte
		if id == 1 {
			s = seed
		}
		secret, pkg, outVK, outExtras, err := frozts.KeyImportPart1(id, n, threshold, s, accountIndex)
		if err != nil {
			t.Fatalf("frozts KeyImportPart1 party %d: %v", id, err)
		}
		if id == 1 {
			vk = outVK
			extras = outExtras
		}
		parties[i] = party{id: id, secret: secret, r1Pkg: pkg}
	}

	type r2Result struct {
		secret frozts.DkgSecretHandle
		r2Pkgs []frozts.MapEntry
	}
	r2Results := make([]r2Result, n)

	for i := uint16(0); i < n; i++ {
		var others []frozts.MapEntry
		for j := uint16(0); j < n; j++ {
			if j == i {
				continue
			}
			others = append(others, frozts.MapEntry{ID: parties[j].id, Value: parties[j].r1Pkg})
		}
		secret, pkgsBytes, err := frozts.DkgPart2(parties[i].secret, frozts.EncodeMap(others))
		if err != nil {
			t.Fatalf("frozts DkgPart2 party %d: %v", parties[i].id, err)
		}
		entries, decErr := frozts.DecodeMap(pkgsBytes)
		if decErr != nil {
			t.Fatalf("frozts DecodeMap r2 party %d: %v", parties[i].id, decErr)
		}
		r2Results[i] = r2Result{secret: secret, r2Pkgs: entries}
	}

	kps := make([][]byte, n)
	var pkp []byte
	for i := uint16(0); i < n; i++ {
		myID := i + 1
		var r1Others []frozts.MapEntry
		for j := uint16(0); j < n; j++ {
			if j == i {
				continue
			}
			r1Others = append(r1Others, frozts.MapEntry{ID: parties[j].id, Value: parties[j].r1Pkg})
		}
		var r2ForMe []frozts.MapEntry
		for senderIdx := uint16(0); senderIdx < n; senderIdx++ {
			if senderIdx == i {
				continue
			}
			for _, entry := range r2Results[senderIdx].r2Pkgs {
				if entry.ID == myID {
					r2ForMe = append(r2ForMe, frozts.MapEntry{ID: parties[senderIdx].id, Value: entry.Value})
				}
			}
		}
		kp, p, err := frozts.KeyImportPart3(r2Results[i].secret, frozts.EncodeMap(r1Others), frozts.EncodeMap(r2ForMe), vk)
		if err != nil {
			t.Fatalf("frozts KeyImportPart3 party %d: %v", i+1, err)
		}
		kps[i] = kp
		if i == 0 {
			pkp = p
		}
	}

	return froztsKeyImportResult{keyPackages: kps, pubKeyPackage: pkp, vk: vk, extras: extras}
}

func runFroztSign(t *testing.T, keyPackages [][]byte, pubKeyPackage []byte, signerIndices []int, message []byte) []byte {
	t.Helper()

	type signerState struct {
		idx    int
		id     uint16
		nonces frozts.NoncesHandle
		commit []byte
	}

	signers := make([]signerState, len(signerIndices))
	for i, idx := range signerIndices {
		id := uint16(idx + 1)
		nonces, commitments, err := frozts.SignCommit(keyPackages[idx])
		if err != nil {
			t.Fatalf("frozts SignCommit signer %d: %v", id, err)
		}
		signers[i] = signerState{idx: idx, id: id, nonces: nonces, commit: commitments}
	}

	var commitEntries []frozts.MapEntry
	for _, s := range signers {
		commitEntries = append(commitEntries, frozts.MapEntry{ID: s.id, Value: s.commit})
	}

	signingPackage, randomizer, err := frozts.SignNewPackage(message, frozts.EncodeMap(commitEntries), pubKeyPackage)
	if err != nil {
		t.Fatalf("frozts SignNewPackage: %v", err)
	}

	var shareEntries []frozts.MapEntry
	for _, s := range signers {
		share, signErr := frozts.Sign(signingPackage, s.nonces, keyPackages[s.idx], randomizer)
		if signErr != nil {
			t.Fatalf("frozts Sign signer %d: %v", s.id, signErr)
		}
		shareEntries = append(shareEntries, frozts.MapEntry{ID: s.id, Value: share})
	}

	signature, err := frozts.SignAggregate(signingPackage, frozts.EncodeMap(shareEntries), pubKeyPackage, randomizer)
	if err != nil {
		t.Fatalf("frozts SignAggregate: %v", err)
	}
	return signature
}

type fromtKeyImportResult struct {
	keyShares [][]byte
	pubKey    []byte
}

func runFromtKeyImport(t *testing.T, n, threshold uint16, moneroSeed []byte, network uint8, birthday uint64) fromtKeyImportResult {
	t.Helper()

	spendKey, _, err := fromt.DeriveKeysFromSeed(moneroSeed)
	if err != nil {
		t.Fatalf("fromt DeriveKeysFromSeed: %v", err)
	}
	expectedVK, err := fromt.SpendKeyToPublic(spendKey)
	if err != nil {
		t.Fatalf("fromt SpendKeyToPublic: %v", err)
	}

	type party struct {
		id     uint16
		secret *fromt.DkgSecretHandle
		r1Pkg  []byte
		idEnc  []byte
	}

	parties := make([]party, n)
	for i := uint16(0); i < n; i++ {
		id := i + 1
		var sk []byte
		if id == 1 {
			sk = spendKey
		}
		secret, pkg, kiErr := fromt.KeyImportPart1(id, n, threshold, sk)
		if kiErr != nil {
			t.Fatalf("fromt KeyImportPart1 party %d: %v", id, kiErr)
		}
		idEnc, encErr := fromt.EncodeIdentifier(id)
		if encErr != nil {
			t.Fatalf("fromt EncodeIdentifier %d: %v", id, encErr)
		}
		parties[i] = party{id: id, secret: secret, r1Pkg: pkg, idEnc: idEnc}
	}

	type r2Result struct {
		secret *fromt.DkgSecretHandle
		r2Pkgs []fromt.MapEntry
	}
	r2Results := make([]r2Result, n)

	for i := uint16(0); i < n; i++ {
		var others []fromt.MapEntry
		for j := uint16(0); j < n; j++ {
			if j == i {
				continue
			}
			others = append(others, fromt.MapEntry{ID: parties[j].idEnc, Value: parties[j].r1Pkg})
		}
		secret, pkgsBytes, dkgErr := fromt.DkgPart2(parties[i].secret, fromt.EncodeMap(others))
		if dkgErr != nil {
			t.Fatalf("fromt DkgPart2 party %d: %v", parties[i].id, dkgErr)
		}
		entries, decErr := fromt.DecodeMap(pkgsBytes)
		if decErr != nil {
			t.Fatalf("fromt DecodeMap r2 party %d: %v", parties[i].id, decErr)
		}
		r2Results[i] = r2Result{secret: secret, r2Pkgs: entries}
	}

	keyShares := make([][]byte, n)
	var pubKey []byte
	for i := uint16(0); i < n; i++ {
		myIDEnc := parties[i].idEnc
		var r1Others []fromt.MapEntry
		for j := uint16(0); j < n; j++ {
			if j == i {
				continue
			}
			r1Others = append(r1Others, fromt.MapEntry{ID: parties[j].idEnc, Value: parties[j].r1Pkg})
		}
		var r2ForMe []fromt.MapEntry
		for senderIdx := uint16(0); senderIdx < n; senderIdx++ {
			if senderIdx == i {
				continue
			}
			for _, entry := range r2Results[senderIdx].r2Pkgs {
				if bytes.Equal(entry.ID, myIDEnc) {
					r2ForMe = append(r2ForMe, fromt.MapEntry{ID: parties[senderIdx].idEnc, Value: entry.Value})
				}
			}
		}
		ks, pk, kiErr := fromt.KeyImportPart3(
			r2Results[i].secret,
			fromt.EncodeMap(r1Others),
			fromt.EncodeMap(r2ForMe),
			expectedVK,
			network,
			birthday,
		)
		if kiErr != nil {
			t.Fatalf("fromt KeyImportPart3 party %d: %v", i+1, kiErr)
		}
		keyShares[i] = ks
		if i == 0 {
			pubKey = pk
		}
	}

	return fromtKeyImportResult{keyShares: keyShares, pubKey: pubKey}
}

func runFromtSign(t *testing.T, keyShares [][]byte, signerIndices []int, message []byte) []byte {
	t.Helper()

	type signerState struct {
		idx    int
		id     uint16
		nonces *fromt.NoncesHandle
		commit []byte
		idEnc  []byte
	}

	signers := make([]signerState, len(signerIndices))
	for i, idx := range signerIndices {
		id := uint16(idx + 1)
		nonces, commitments, err := fromt.SignCommit(keyShares[idx])
		if err != nil {
			t.Fatalf("fromt SignCommit signer %d: %v", id, err)
		}
		idEnc, encErr := fromt.EncodeIdentifier(id)
		if encErr != nil {
			t.Fatalf("fromt EncodeIdentifier %d: %v", id, encErr)
		}
		signers[i] = signerState{idx: idx, id: id, nonces: nonces, commit: commitments, idEnc: idEnc}
	}

	var commitEntries []fromt.MapEntry
	for _, s := range signers {
		commitEntries = append(commitEntries, fromt.MapEntry{ID: s.idEnc, Value: s.commit})
	}

	signingPackage, err := fromt.SignCreatePackage(message, fromt.EncodeMap(commitEntries))
	if err != nil {
		t.Fatalf("fromt SignCreatePackage: %v", err)
	}

	var shareEntries []fromt.MapEntry
	for _, s := range signers {
		share, signErr := fromt.Sign(signingPackage, s.nonces, keyShares[s.idx])
		if signErr != nil {
			t.Fatalf("fromt Sign signer %d: %v", s.id, signErr)
		}
		shareEntries = append(shareEntries, fromt.MapEntry{ID: s.idEnc, Value: share})
	}

	signature, err := fromt.SignAggregate(signingPackage, fromt.EncodeMap(shareEntries), keyShares[signerIndices[0]])
	if err != nil {
		t.Fatalf("fromt SignAggregate: %v", err)
	}
	return signature
}

func TestVultCombinedRoundTrip(t *testing.T) {
	env := loadDotEnv(t)

	mnemonic := env["FROZT_MNEMONIC"]
	if mnemonic == "" {
		t.Fatal("FROZT_MNEMONIC not set in .env")
	}
	froztsBirthdayStr := env["FROZT_BIRTHDAY"]
	froztsBirthday, err := strconv.Atoi(froztsBirthdayStr)
	if err != nil {
		t.Fatalf("invalid FROZT_BIRTHDAY: %v", err)
	}
	froztsExpectedAddr := env["FROZT_EXPECTED_ADDRESS"]
	if froztsExpectedAddr == "" {
		t.Fatal("FROZT_EXPECTED_ADDRESS not set in .env")
	}

	fromtMnemonic := env["FROMT_MNEMONIC"]
	if fromtMnemonic == "" {
		fromtMnemonic = mnemonic
		t.Log("FROMT_MNEMONIC not set, reusing FROZT_MNEMONIC for Monero derivation")
	}
	fromtBirthday := uint64(0)
	if s := env["FROMT_BIRTHDAY"]; s != "" {
		v, parseErr := strconv.ParseUint(s, 10, 64)
		if parseErr != nil {
			t.Fatalf("invalid FROMT_BIRTHDAY: %v", parseErr)
		}
		fromtBirthday = v
	}

	const n = uint16(3)
	const threshold = uint16(2)
	signers := []string{"party-1", "party-2", "party-3"}

	t.Log("=== Frozt: key import 2-of-3 from mnemonic ===")
	zcashSeed := zcashSeedFromMnemonic(mnemonic)
	froztsResult := runFroztKeyImport(t, n, threshold, zcashSeed, 0)

	froztsVK, err := frozts.PubKeyPackageVerifyingKey(froztsResult.pubKeyPackage)
	if err != nil {
		t.Fatalf("frozts PubKeyPackageVerifyingKey: %v", err)
	}
	froztsVKHex := hex.EncodeToString(froztsVK)

	froztsKeys, err := frozts.SaplingDeriveKeys(froztsResult.pubKeyPackage, froztsResult.extras)
	if err != nil {
		t.Fatalf("frozts SaplingDeriveKeys: %v", err)
	}
	if froztsKeys.Address != froztsExpectedAddr {
		t.Fatalf("frozts address mismatch:\n  got:  %s\n  want: %s", froztsKeys.Address, froztsExpectedAddr)
	}
	t.Logf("frozts z-address: %s", froztsKeys.Address)
	t.Logf("frozts verifying key: %s", froztsVKHex)

	t.Log("=== Fromt: key import 2-of-3 from mnemonic ===")
	moneroSeed := moneroSeedFromMnemonic(t, fromtMnemonic)
	fromtResult := runFromtKeyImport(t, n, threshold, moneroSeed, 0, fromtBirthday)

	fromtPK, err := fromt.KeySharePublicKey(fromtResult.keyShares[0])
	if err != nil {
		t.Fatalf("fromt KeySharePublicKey: %v", err)
	}
	fromtPKHex := hex.EncodeToString(fromtPK)

	fromtAddr, err := fromt.DeriveAddress(fromtResult.keyShares[0])
	if err != nil {
		t.Fatalf("fromt DeriveAddress: %v", err)
	}
	t.Logf("fromt address: %s", fromtAddr)
	t.Logf("fromt public key: %s", fromtPKHex)

	fromtVK, err := fromt.KeyShareViewKey(fromtResult.keyShares[0])
	if err != nil {
		t.Fatalf("fromt KeyShareViewKey: %v", err)
	}
	t.Logf("fromt view key: %s", hex.EncodeToString(fromtVK))

	t.Log("=== Build .vult files with both chains ===")
	tmpDir := t.TempDir()

	for i := 0; i < int(n); i++ {
		froztsBundle, bundleErr := frozts.KeyShareBundlePack(
			froztsResult.keyPackages[i], froztsResult.pubKeyPackage, froztsResult.extras, uint64(froztsBirthday),
		)
		if bundleErr != nil {
			t.Fatalf("frozts KeyShareBundlePack party %d: %v", i+1, bundleErr)
		}

		vault := &v1.Vault{
			Name:         fmt.Sprintf("combined-test-party-%d", i+1),
			Signers:      signers,
			LocalPartyId: signers[i],
			LibType:      keygenV1.LibType_LIB_TYPE_KEYIMPORT,
		}

		froztsEntry := sharedvault.FroztChainKeyEntry(froztsBundle, froztsVKHex)
		sharedvault.SetChainKeyEntry(vault, froztsEntry)

		fromtEntry := sharedvault.FromtChainKeyEntry(fromtResult.keyShares[i], fromtPKHex)
		sharedvault.SetChainKeyEntry(vault, fromtEntry)

		if len(vault.ChainPublicKeys) != 2 {
			t.Fatalf("expected 2 chain_public_keys, got %d", len(vault.ChainPublicKeys))
		}
		if len(vault.KeyShares) != 2 {
			t.Fatalf("expected 2 key_shares, got %d", len(vault.KeyShares))
		}

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

	t.Log("=== Re-import .vult and verify both chains ===")

	importedFroztKPs := make([][]byte, n)
	var importedFroztPKP []byte
	var importedFroztExtras []byte
	importedFromtKS := make([][]byte, n)

	for i := 0; i < int(n); i++ {
		path := filepath.Join(tmpDir, fmt.Sprintf("party-%d.vult", i+1))
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("ReadFile party %d: %v", i+1, readErr)
		}

		parsedVault, parseErr := sharedvault.ParseVultFile(data)
		if parseErr != nil {
			t.Fatalf("ParseVultFile party %d: %v", i+1, parseErr)
		}

		if parsedVault.Name != fmt.Sprintf("combined-test-party-%d", i+1) {
			t.Fatalf("vault name mismatch party %d: %s", i+1, parsedVault.Name)
		}
		if parsedVault.LocalPartyId != signers[i] {
			t.Fatalf("local_party_id mismatch party %d", i+1)
		}
		if parsedVault.LibType != keygenV1.LibType_LIB_TYPE_KEYIMPORT {
			t.Fatalf("lib_type mismatch party %d", i+1)
		}
		if len(parsedVault.ChainPublicKeys) != 2 {
			t.Fatalf("expected 2 chain_public_keys in party %d, got %d", i+1, len(parsedVault.ChainPublicKeys))
		}
		if len(parsedVault.KeyShares) != 2 {
			t.Fatalf("expected 2 key_shares in party %d, got %d", i+1, len(parsedVault.KeyShares))
		}

		// --- Frozt chain entry ---
		froztsEntry, found := sharedvault.FindChainKeyEntry(parsedVault, sharedvault.ChainZcashSapling)
		if !found {
			t.Fatalf("ZcashSapling chain key not found in party %d", i+1)
		}
		if froztsEntry.PublicKey != froztsVKHex {
			t.Fatalf("frozts public key mismatch party %d", i+1)
		}

		froztsBundle, vk, decErr := sharedvault.ParseChainKeyEntry(froztsEntry)
		if decErr != nil {
			t.Fatalf("frozts ParseChainKeyEntry party %d: %v", i+1, decErr)
		}
		if !bytes.Equal(vk, froztsVK) {
			t.Fatalf("frozts decoded VK mismatch party %d", i+1)
		}

		kpBytes, kpErr := frozts.KeyShareBundleKeyPackage(froztsBundle)
		if kpErr != nil {
			t.Fatalf("frozts KeyShareBundleKeyPackage party %d: %v", i+1, kpErr)
		}
		pkpBytes, pkpErr := frozts.KeyShareBundlePubKeyPackage(froztsBundle)
		if pkpErr != nil {
			t.Fatalf("frozts KeyShareBundlePubKeyPackage party %d: %v", i+1, pkpErr)
		}
		extrasBytes, extErr := frozts.KeyShareBundleSaplingExtras(froztsBundle)
		if extErr != nil {
			t.Fatalf("frozts KeyShareBundleSaplingExtras party %d: %v", i+1, extErr)
		}
		bday, bdayErr := frozts.KeyShareBundleBirthday(froztsBundle)
		if bdayErr != nil {
			t.Fatalf("frozts KeyShareBundleBirthday party %d: %v", i+1, bdayErr)
		}
		if bday != uint64(froztsBirthday) {
			t.Fatalf("frozts birthday mismatch party %d: got %d, want %d", i+1, bday, froztsBirthday)
		}

		importedFroztKPs[i] = kpBytes
		if i == 0 {
			importedFroztPKP = pkpBytes
			importedFroztExtras = extrasBytes
		}

		// --- Fromt chain entry ---
		fromtEntry, found := sharedvault.FindChainKeyEntry(parsedVault, sharedvault.ChainMonero)
		if !found {
			t.Fatalf("Monero chain key not found in party %d", i+1)
		}
		if fromtEntry.PublicKey != fromtPKHex {
			t.Fatalf("fromt public key mismatch party %d", i+1)
		}

		fromtBundle, fromtVKDec, decErr := sharedvault.ParseChainKeyEntry(fromtEntry)
		if decErr != nil {
			t.Fatalf("fromt ParseChainKeyEntry party %d: %v", i+1, decErr)
		}
		if !bytes.Equal(fromtVKDec, fromtPK) {
			t.Fatalf("fromt decoded PK mismatch party %d", i+1)
		}

		importedFromtKS[i] = fromtBundle

		importedPK, pkErr := fromt.KeySharePublicKey(fromtBundle)
		if pkErr != nil {
			t.Fatalf("fromt KeySharePublicKey party %d: %v", i+1, pkErr)
		}
		if !bytes.Equal(importedPK, fromtPK) {
			t.Fatalf("fromt public key from bundle mismatch party %d", i+1)
		}

		importedAddr, addrErr := fromt.DeriveAddress(fromtBundle)
		if addrErr != nil {
			t.Fatalf("fromt DeriveAddress party %d: %v", i+1, addrErr)
		}
		if importedAddr != fromtAddr {
			t.Fatalf("fromt address mismatch party %d:\n  got:  %s\n  want: %s", i+1, importedAddr, fromtAddr)
		}

		importedViewKey, vkErr := fromt.KeyShareViewKey(fromtBundle)
		if vkErr != nil {
			t.Fatalf("fromt KeyShareViewKey party %d: %v", i+1, vkErr)
		}
		if !bytes.Equal(importedViewKey, fromtVK) {
			t.Fatalf("fromt view key mismatch party %d", i+1)
		}

		importedBday, fromtBdayErr := fromt.KeyShareBirthday(fromtBundle)
		if fromtBdayErr != nil {
			t.Fatalf("fromt KeyShareBirthday party %d: %v", i+1, fromtBdayErr)
		}
		if importedBday != fromtBirthday {
			t.Fatalf("fromt birthday mismatch party %d: got %d, want %d", i+1, importedBday, fromtBirthday)
		}

		t.Logf("party %d: frozts bundle=%d bytes, fromt keyshare=%d bytes — all fields match",
			i+1, len(froztsBundle), len(fromtBundle))
	}

	t.Log("=== Frozt: re-derive address from imported shares ===")
	reKeys, err := frozts.SaplingDeriveKeys(importedFroztPKP, importedFroztExtras)
	if err != nil {
		t.Fatalf("frozts SaplingDeriveKeys: %v", err)
	}
	if reKeys.Address != froztsExpectedAddr {
		t.Fatalf("frozts re-derived address mismatch:\n  got:  %s\n  want: %s", reKeys.Address, froztsExpectedAddr)
	}
	t.Logf("frozts re-derived address: %s", reKeys.Address)

	t.Log("=== Frozt: sign with imported .vult shares (parties 0,1) ===")
	froztsSig1 := runFroztSign(t, importedFroztKPs, importedFroztPKP, []int{0, 1}, []byte("combined vult test"))
	t.Logf("frozts signature (0,1): %x (%d bytes)", froztsSig1, len(froztsSig1))

	t.Log("=== Frozt: sign with imported .vult shares (parties 1,2) ===")
	froztsSig2 := runFroztSign(t, importedFroztKPs, importedFroztPKP, []int{1, 2}, []byte("combined vult test"))
	t.Logf("frozts signature (1,2): %x (%d bytes)", froztsSig2, len(froztsSig2))

	t.Log("=== Fromt: sign with imported .vult shares (parties 0,1) ===")
	fromtSig1 := runFromtSign(t, importedFromtKS, []int{0, 1}, []byte("combined vult test"))
	t.Logf("fromt signature (0,1): %x (%d bytes)", fromtSig1, len(fromtSig1))

	t.Log("=== Fromt: sign with imported .vult shares (parties 1,2) ===")
	fromtSig2 := runFromtSign(t, importedFromtKS, []int{1, 2}, []byte("combined vult test"))
	t.Logf("fromt signature (1,2): %x (%d bytes)", fromtSig2, len(fromtSig2))

	t.Log("=== Combined .vult round-trip test passed ===")
}
