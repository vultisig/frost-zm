package froztsdk

import (
	"encoding/hex"
	"os"
	"testing"

	frozt "github.com/vultisig/frost-zm/go/frozt"
)

func mnemonic2Seed(t *testing.T) []byte {
	t.Helper()
	seedHex := os.Getenv("FROZT_SEED_HEX_2")
	if seedHex == "" {
		t.Skip("FROZT_SEED_HEX_2 not set")
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	return seed
}

func doKeyImport(t *testing.T, seed []byte) (pubKeyPackage, extras []byte) {
	t.Helper()

	s1, r1p1, vk, ext, err := frozt.KeyImportPart1(1, 2, 2, seed, 0)
	if err != nil {
		t.Fatalf("p1 import part1: %v", err)
	}

	s2, r1p2, _, _, err := frozt.KeyImportPart1(2, 2, 2, nil, 0)
	if err != nil {
		t.Fatalf("p2 import part1: %v", err)
	}

	r1For1 := frozt.EncodeMap([]frozt.MapEntry{{ID: 2, Value: r1p2}})
	r1For2 := frozt.EncodeMap([]frozt.MapEntry{{ID: 1, Value: r1p1}})

	s1b, r2p1, err := frozt.DkgPart2(s1, r1For1)
	if err != nil {
		t.Fatalf("p1 dkg part2: %v", err)
	}

	s2b, r2p2, err := frozt.DkgPart2(s2, r1For2)
	if err != nil {
		t.Fatalf("p2 dkg part2: %v", err)
	}

	entries2For1, err := frozt.DecodeMap(r2p2)
	if err != nil {
		t.Fatalf("decode r2p2: %v", err)
	}
	var r2For1Entries []frozt.MapEntry
	for _, e := range entries2For1 {
		if e.ID == 1 {
			r2For1Entries = append(r2For1Entries, frozt.MapEntry{ID: 2, Value: e.Value})
		}
	}

	entries2For2, err := frozt.DecodeMap(r2p1)
	if err != nil {
		t.Fatalf("decode r2p1: %v", err)
	}
	var r2For2Entries []frozt.MapEntry
	for _, e := range entries2For2 {
		if e.ID == 2 {
			r2For2Entries = append(r2For2Entries, frozt.MapEntry{ID: 1, Value: e.Value})
		}
	}

	_, pkp, err := frozt.KeyImportPart3(s1b, r1For1, frozt.EncodeMap(r2For1Entries), vk)
	if err != nil {
		t.Fatalf("p1 import part3: %v", err)
	}

	_, _, err = frozt.KeyImportPart3(s2b, r1For2, frozt.EncodeMap(r2For2Entries), vk)
	if err != nil {
		t.Fatalf("p2 import part3: %v", err)
	}

	return pkp, ext
}

func TestScanMnemonic2(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live scan test")
	}

	seed := mnemonic2Seed(t)
	pkp, extras := doKeyImport(t, seed)

	keys, err := frozt.SaplingDeriveKeys(pkp, extras)
	if err != nil {
		t.Fatalf("derive keys: %v", err)
	}
	t.Logf("Address: %s", keys.Address)

	expectedAddr := os.Getenv("FROZT_EXPECTED_ADDRESS_2")
	if expectedAddr != "" && keys.Address != expectedAddr {
		t.Fatalf("address mismatch: got %s, want %s", keys.Address, expectedAddr)
	}

	dfvk, err := frozt.SaplingBuildDfvk(pkp, extras)
	if err != nil {
		t.Fatalf("build dfvk: %v", err)
	}
	t.Logf("DFVK: %d bytes", len(dfvk))

	result, err := Scan(dfvk, "https://zec.rocks:443", 3256538)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	t.Logf("Balance: %d zatoshis (%.8f ZEC)", result.SpendableBalance, float64(result.SpendableBalance)/1e8)
	t.Logf("Chain height: %d, Scanned height: %d", result.ChainHeight, result.ScannedHeight)

	if result.SpendableBalance == 0 {
		t.Error("expected non-zero balance for mnemonic2")
	}
}
