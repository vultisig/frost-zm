package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	fromt "github.com/vultisig/frosty-lib/go/fromt"
	fromtsdk "github.com/vultisig/frosty-lib/go/fromt-sdk"
)

func main() {
	nodeURL := flag.String("node", "", "Monero daemon URL (e.g. http://xmr-node.cakewallet.com:18081)")
	keyshareFile := flag.String("keyshare", "", "Path to keyshare file")
	birthday := flag.Uint64("birthday", 0, "Start scanning from this block height")
	flag.Parse()

	if *nodeURL == "" || *keyshareFile == "" {
		fmt.Fprintln(os.Stderr, "Usage: fromt-scan --node URL --keyshare FILE [--birthday HEIGHT]")
		flag.Usage()
		os.Exit(1)
	}

	data, err := os.ReadFile(*keyshareFile)
	if err != nil {
		log.Fatalf("Failed to read keyshare: %v", err)
	}

	addr, err := fromt.DeriveAddress(data)
	if err != nil {
		log.Fatalf("Failed to derive address: %v", err)
	}
	log.Printf("Address: %s", addr)
	log.Printf("Scanning from block %d...", *birthday)

	balance, numOutputs, err := fromtsdk.ScanBalance(data, *nodeURL, *birthday, nil)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	fmt.Println()
	fmt.Println("=== Scan Results ===")
	fmt.Printf("Address:    %s\n", addr)
	fmt.Printf("Outputs:    %d\n", numOutputs)
	fmt.Printf("Balance:    %.12f XMR (%d piconero)\n", float64(balance)/1e12, balance)
}
