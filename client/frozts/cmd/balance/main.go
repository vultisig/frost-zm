package main

import (
	"context"
	"fmt"
	"log"
	"strconv"

	frozts "github.com/vultisig/frosty-lib/go/frozts"

	"github.com/vultisig/frosty-lib/client/frozts/internal/bip39"
	"github.com/vultisig/frosty-lib/client/frozts/internal/config"
	"github.com/vultisig/frosty-lib/client/frozts/internal/lightwalletd"
)

func main() {
	env, err := config.LoadDotEnv("../../../../.env")
	if err != nil {
		log.Fatalf("LoadDotEnv: %v", err)
	}

	mnemonic := env["FROZT_MNEMONIC"]
	if mnemonic == "" {
		log.Fatal("FROZT_MNEMONIC not set in .env")
	}
	birthdayStr := env["FROZT_BIRTHDAY"]
	birthday, err := strconv.ParseUint(birthdayStr, 10, 64)
	if err != nil {
		log.Fatalf("invalid FROZT_BIRTHDAY: %v", err)
	}

	seed := bip39.MnemonicToSeed(mnemonic)
	result := keyImport(seed, 3, 2)

	keys, err := frozts.SaplingDeriveKeys(result.pkp, result.extras)
	if err != nil {
		log.Fatalf("SaplingDeriveKeys: %v", err)
	}

	scanner, err := lightwalletd.NewScanner("zec.rocks:443")
	if err != nil {
		log.Fatalf("NewScanner: %v", err)
	}
	defer scanner.Close()

	ctx := context.Background()
	tip, err := scanner.GetLatestBlock(ctx)
	if err != nil {
		log.Fatalf("GetLatestBlock: %v", err)
	}

	fmt.Printf("Address:  %s\n", keys.Address)
	fmt.Printf("Scanning blocks %d → %d...\n", birthday, tip)

	scanResult, err := scanner.Scan(ctx, keys.Ivk, birthday, tip, 0, func(scanned, total uint64) {
		if scanned%50000 == 0 && scanned > 0 {
			fmt.Printf("  progress: %d / %d (%.1f%%)\n", scanned, total, float64(scanned)/float64(total)*100)
		}
	})
	if err != nil {
		log.Fatalf("Scan: %v", err)
	}

	fmt.Println()
	fmt.Println("=== Zcash Balance ===")
	fmt.Printf("Address:  %s\n", keys.Address)
	fmt.Printf("Notes:    %d\n", len(scanResult.Notes))
	for i, note := range scanResult.Notes {
		fmt.Printf("  note %d: height=%d value=%.8f ZEC\n", i, note.Height, float64(note.Value)/1e8)
	}
	fmt.Printf("Total:    %.8f ZEC (%d zatoshi)\n", float64(scanResult.TotalValue)/1e8, scanResult.TotalValue)
}

type importResult struct {
	kps    [][]byte
	pkp    []byte
	extras []byte
}

func keyImport(seed []byte, n, threshold uint16) importResult {
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
		secret, pkg, outVK, outExtras, err := frozts.KeyImportPart1(id, n, threshold, s, 0)
		if err != nil {
			log.Fatalf("KeyImportPart1 party %d: %v", id, err)
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
			log.Fatalf("DkgPart2 party %d: %v", parties[i].id, err)
		}
		entries, err := frozts.DecodeMap(pkgsBytes)
		if err != nil {
			log.Fatalf("DecodeMap r2 party %d: %v", parties[i].id, err)
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
			log.Fatalf("KeyImportPart3 party %d: %v", i+1, err)
		}
		kps[i] = kp
		if i == 0 {
			pkp = p
		}
	}

	return importResult{kps: kps, pkp: pkp, extras: extras}
}
