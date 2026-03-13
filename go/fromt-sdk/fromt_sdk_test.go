package fromtsdk

import (
	"encoding/hex"
	"os"
	"testing"

	fromt "github.com/vultisig/frost-zm/go/fromt"
)

func mnemonic2Seed(t *testing.T) []byte {
	t.Helper()
	seedHex := os.Getenv("FROMT_SEED_HEX")
	if seedHex == "" {
		t.Skip("FROMT_SEED_HEX not set")
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	return seed
}

func doKeyImport(t *testing.T, seed []byte) (keyShare []byte) {
	t.Helper()

	sk, _, err := fromt.DeriveKeysFromSeed(seed)
	if err != nil {
		t.Fatalf("DeriveKeysFromSeed: %v", err)
	}

	s1, r1p1, err := fromt.KeyImportPart1(1, 2, 2, sk)
	if err != nil {
		t.Fatalf("p1 import part1: %v", err)
	}

	s2, r1p2, err := fromt.KeyImportPart1(2, 2, 2, nil)
	if err != nil {
		t.Fatalf("p2 import part1: %v", err)
	}

	id1, err := fromt.EncodeIdentifier(1)
	if err != nil {
		t.Fatalf("encode id 1: %v", err)
	}
	id2, err := fromt.EncodeIdentifier(2)
	if err != nil {
		t.Fatalf("encode id 2: %v", err)
	}

	r1For1 := fromt.EncodeMap([]fromt.MapEntry{{ID: id2, Value: r1p2}})
	r1For2 := fromt.EncodeMap([]fromt.MapEntry{{ID: id1, Value: r1p1}})

	s1b, r2p1, err := fromt.DkgPart2(s1, r1For1)
	if err != nil {
		t.Fatalf("p1 dkg part2: %v", err)
	}

	s2b, r2p2, err := fromt.DkgPart2(s2, r1For2)
	if err != nil {
		t.Fatalf("p2 dkg part2: %v", err)
	}

	entries2For1, err := fromt.DecodeMap(r2p2)
	if err != nil {
		t.Fatalf("decode r2p2: %v", err)
	}
	var r2For1Entries []fromt.MapEntry
	for _, e := range entries2For1 {
		decoded, decErr := fromt.DecodeIdentifier(e.ID)
		if decErr != nil {
			t.Fatalf("decode id: %v", decErr)
		}
		if decoded == 1 {
			r2For1Entries = append(r2For1Entries, fromt.MapEntry{ID: id2, Value: e.Value})
		}
	}

	entries2For2, err := fromt.DecodeMap(r2p1)
	if err != nil {
		t.Fatalf("decode r2p1: %v", err)
	}
	var r2For2Entries []fromt.MapEntry
	for _, e := range entries2For2 {
		decoded, decErr := fromt.DecodeIdentifier(e.ID)
		if decErr != nil {
			t.Fatalf("decode id: %v", decErr)
		}
		if decoded == 2 {
			r2For2Entries = append(r2For2Entries, fromt.MapEntry{ID: id1, Value: e.Value})
		}
	}

	vk, err := fromt.SpendKeyToPublic(sk)
	if err != nil {
		t.Fatalf("SpendKeyToPublic: %v", err)
	}

	const networkMainnet uint8 = 0
	ks, _, err := fromt.KeyImportPart3(s1b, r1For1, fromt.EncodeMap(r2For1Entries), vk, networkMainnet, 0)
	if err != nil {
		t.Fatalf("p1 import part3: %v", err)
	}

	_, _, err = fromt.KeyImportPart3(s2b, r1For2, fromt.EncodeMap(r2For2Entries), vk, networkMainnet, 0)
	if err != nil {
		t.Fatalf("p2 import part3: %v", err)
	}

	return ks
}

func TestScanBalance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live scan test")
	}

	seed := mnemonic2Seed(t)
	ks := doKeyImport(t, seed)

	addr, err := fromt.DeriveAddress(ks)
	if err != nil {
		t.Fatalf("DeriveAddress: %v", err)
	}
	t.Logf("Address: %s", addr)

	balance, numOutputs, err := ScanBalance(ks, "http://node.monerodevs.org:38089", 0, nil)
	if err != nil {
		t.Fatalf("ScanBalance: %v", err)
	}

	t.Logf("Balance: %d piconero (%d outputs)", balance, numOutputs)
}
