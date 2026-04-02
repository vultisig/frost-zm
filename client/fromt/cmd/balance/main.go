package main

import (
	"fmt"
	"log"
	"strconv"

	fromt "github.com/vultisig/frosty-lib/go/fromt"
	fromtsdk "github.com/vultisig/frosty-lib/go/fromt-sdk"

	"github.com/vultisig/frosty-lib/client/fromt/internal/config"
	"github.com/vultisig/frosty-lib/client/fromt/internal/mnemonic"
)

func main() {
	env, err := config.LoadDotEnv("../../../../.env")
	if err != nil {
		log.Fatalf("LoadDotEnv: %v", err)
	}

	phrase := env["FROMT_MNEMONIC"]
	if phrase == "" {
		log.Fatal("FROMT_MNEMONIC not set in .env")
	}
	birthdayStr := env["FROMT_BIRTHDAY"]
	var birthday uint64
	if birthdayStr != "" {
		birthday, err = strconv.ParseUint(birthdayStr, 10, 64)
		if err != nil {
			log.Fatalf("invalid FROMT_BIRTHDAY: %v", err)
		}
	}

	seed, err := mnemonic.DeriveMoneroSeed(phrase)
	if err != nil {
		log.Fatalf("DeriveMoneroSeed: %v", err)
	}

	sk, _, err := fromt.DeriveKeysFromSeed(seed)
	if err != nil {
		log.Fatalf("DeriveKeysFromSeed: %v", err)
	}

	vk, err := fromt.SpendKeyToPublic(sk)
	if err != nil {
		log.Fatalf("SpendKeyToPublic: %v", err)
	}

	ks := keyImport(sk, vk, 2, 2, birthday)

	addr, err := fromt.DeriveAddress(ks)
	if err != nil {
		log.Fatalf("DeriveAddress: %v", err)
	}

	fmt.Printf("Address:  %s\n", addr)
	fmt.Printf("Scanning from block %d...\n", birthday)

	balance, numOutputs, err := fromtsdk.ScanBalance(ks, "http://xmr-node.cakewallet.com:18081", birthday, sk)
	if err != nil {
		log.Fatalf("ScanBalance: %v", err)
	}

	fmt.Println()
	fmt.Println("=== Monero Balance ===")
	fmt.Printf("Address:  %s\n", addr)
	fmt.Printf("Outputs:  %d\n", numOutputs)
	fmt.Printf("Balance:  %.12f XMR (%d piconero)\n", float64(balance)/1e12, balance)
}

func keyImport(sk, expectedVK []byte, n, threshold uint16, birthday uint64) []byte {
	s1, r1p1, err := fromt.KeyImportPart1(1, n, threshold, sk)
	if err != nil {
		log.Fatalf("p1 import part1: %v", err)
	}
	s2, r1p2, err := fromt.KeyImportPart1(2, n, threshold, nil)
	if err != nil {
		log.Fatalf("p2 import part1: %v", err)
	}

	id1, _ := fromt.EncodeIdentifier(1)
	id2, _ := fromt.EncodeIdentifier(2)

	r1For1 := fromt.EncodeMap([]fromt.MapEntry{{ID: id2, Value: r1p2}})
	r1For2 := fromt.EncodeMap([]fromt.MapEntry{{ID: id1, Value: r1p1}})

	s1b, r2p1, err := fromt.DkgPart2(s1, r1For1)
	if err != nil {
		log.Fatalf("p1 dkg part2: %v", err)
	}
	s2b, r2p2, err := fromt.DkgPart2(s2, r1For2)
	if err != nil {
		log.Fatalf("p2 dkg part2: %v", err)
	}

	entries2For1, _ := fromt.DecodeMap(r2p2)
	var r2For1Entries []fromt.MapEntry
	for _, e := range entries2For1 {
		decoded, _ := fromt.DecodeIdentifier(e.ID)
		if decoded == 1 {
			r2For1Entries = append(r2For1Entries, fromt.MapEntry{ID: id2, Value: e.Value})
		}
	}

	entries2For2, _ := fromt.DecodeMap(r2p1)
	var r2For2Entries []fromt.MapEntry
	for _, e := range entries2For2 {
		decoded, _ := fromt.DecodeIdentifier(e.ID)
		if decoded == 2 {
			r2For2Entries = append(r2For2Entries, fromt.MapEntry{ID: id1, Value: e.Value})
		}
	}

	const networkMainnet uint8 = 0
	ks, _, err := fromt.KeyImportPart3(s1b, r1For1, fromt.EncodeMap(r2For1Entries), expectedVK, networkMainnet, birthday)
	if err != nil {
		log.Fatalf("p1 import part3: %v", err)
	}
	_, _, err = fromt.KeyImportPart3(s2b, r1For2, fromt.EncodeMap(r2For2Entries), expectedVK, networkMainnet, birthday)
	if err != nil {
		log.Fatalf("p2 import part3: %v", err)
	}

	return ks
}
