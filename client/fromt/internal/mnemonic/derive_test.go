package mnemonic

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"

	legacymnemonic "github.com/dimalinux/gopherphis/mnemonic"
	"github.com/tyler-smith/go-bip39"
	fromt "github.com/vultisig/frost-zm/go/fromt"
)

func TestPolyseed_KnownVector(t *testing.T) {
	phrase := os.Getenv("FROMT_POLYSEED_MNEMONIC")
	if phrase == "" {
		t.Skip("FROMT_POLYSEED_MNEMONIC not set")
	}
	expected := os.Getenv("FROMT_POLYSEED_EXPECTED_SEED")
	seed, err := DeriveMoneroSeed(phrase)
	if err != nil {
		t.Fatalf("DeriveMoneroSeed: %v", err)
	}
	got := hex.EncodeToString(seed)
	if expected != "" && got != expected {
		t.Fatalf("seed mismatch:\n  want: %s\n  got:  %s", expected, got)
	}
}

func TestPolyseed_AllAbandon(t *testing.T) {
	seed, err := DeriveMoneroSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon")
	if err != nil {
		t.Fatalf("DeriveMoneroSeed: %v", err)
	}
	got := hex.EncodeToString(seed)
	expected := "a9bf27d5916c4414f0b84702d598136c94ea03ca7cc4ab56d3b40a1189d4fb18"
	if got != expected {
		t.Fatalf("seed mismatch:\n  want: %s\n  got:  %s", expected, got)
	}
}

func TestPolyseed_LegacyRoundTrip(t *testing.T) {
	seed, err := DeriveMoneroSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon")
	if err != nil {
		t.Fatalf("DeriveMoneroSeed: %v", err)
	}

	sk, _, err := fromt.DeriveKeysFromSeed(seed)
	if err != nil {
		t.Fatalf("DeriveKeysFromSeed: %v", err)
	}

	expectedSK := "bceb3178770932bc191c505ff69e345794ea03ca7cc4ab56d3b40a1189d4fb08"
	gotSK := hex.EncodeToString(sk)
	if gotSK != expectedSK {
		t.Fatalf("spend key mismatch:\n  want: %s\n  got:  %s", expectedSK, gotSK)
	}

	wl := legacymnemonic.EnglishWordList
	words := wl.CreateSeedsFromKey(sk)
	legacy := strings.Join(words, " ")
	expectedLegacy := "yacht rebel cycling timber axis sulking language flying ponies spying dehydrate meeting economics cohesive voted vapidly upstairs emotion asked dormant fading scoop september sonic spying"
	if legacy != expectedLegacy {
		t.Fatalf("legacy mnemonic mismatch:\n  want: %s\n  got:  %s", expectedLegacy, legacy)
	}

	recovered, err := wl.CreateKeyFromSeeds(words)
	if err != nil {
		t.Fatalf("CreateKeyFromSeeds: %v", err)
	}
	if hex.EncodeToString(recovered) != expectedSK {
		t.Fatalf("round-trip spend key mismatch:\n  want: %s\n  got:  %s", expectedSK, hex.EncodeToString(recovered))
	}
}

func TestLegacy25_Decode(t *testing.T) {
	legacy := "yacht rebel cycling timber axis sulking language flying ponies spying dehydrate meeting economics cohesive voted vapidly upstairs emotion asked dormant fading scoop september sonic spying"
	seed, err := DeriveMoneroSeed(legacy)
	if err != nil {
		t.Fatalf("DeriveMoneroSeed: %v", err)
	}

	expectedSK := "bceb3178770932bc191c505ff69e345794ea03ca7cc4ab56d3b40a1189d4fb08"
	got := hex.EncodeToString(seed)
	if got != expectedSK {
		t.Fatalf("legacy decode mismatch:\n  want: %s\n  got:  %s", expectedSK, got)
	}
}

func TestBIP39_KeyDerivation(t *testing.T) {
	phrase := os.Getenv("FROMT_MNEMONIC")
	if phrase == "" {
		t.Skip("FROMT_MNEMONIC not set")
	}
	if !bip39.IsMnemonicValid(phrase) {
		t.Fatal("expected valid BIP39 mnemonic")
	}

	seed, err := DeriveMoneroSeed(phrase)
	if err != nil {
		t.Fatalf("DeriveMoneroSeed: %v", err)
	}

	sk, vk, err := fromt.DeriveKeysFromSeed(seed)
	if err != nil {
		t.Fatalf("DeriveKeysFromSeed: %v", err)
	}

	pk, err := fromt.SpendKeyToPublic(sk)
	if err != nil {
		t.Fatalf("SpendKeyToPublic: %v", err)
	}

	t.Logf("spend priv: %x", sk)
	t.Logf("spend pub:  %x", pk)
	t.Logf("view priv:  %x", vk)
}

func TestBIP39_InvalidChecksum(t *testing.T) {
	_, err := DeriveMoneroSeed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon")
	if err == nil {
		t.Fatal("expected error for invalid BIP39 checksum")
	}
}

func TestUnsupportedWordCount(t *testing.T) {
	_, err := DeriveMoneroSeed("one two three four five")
	if err == nil {
		t.Fatal("expected error for unsupported word count")
	}
}
