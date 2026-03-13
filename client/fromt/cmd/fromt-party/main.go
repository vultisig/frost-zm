package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/vultisig/frost-zm/client/fromt/internal/party"
)

func main() {
	cfg := party.Config{
		RelayURL:           envOrDefault("RELAY_URL", "http://localhost:9090"),
		PartyID:            requireEnv("PARTY_ID"),
		SessionID:          requireEnv("SESSION_ID"),
		Operation:          requireEnv("OPERATION"),
		KeystoreDir:        envOrDefault("KEYSTORE_DIR", "/data/keystore"),
		SignMessage:        envOrDefault("SIGN_MESSAGE", ""),
		EncryptionKeyHex:   os.Getenv("ENCRYPTION_KEY"),
		KeystorePassphrase: os.Getenv("KEYSTORE_PASSPHRASE"),
	}

	identifier, err := strconv.ParseUint(requireEnv("IDENTIFIER"), 10, 16)
	if err != nil {
		log.Fatalf("invalid IDENTIFIER: %v", err)
	}
	cfg.Identifier = uint16(identifier)

	maxSigners, err := strconv.ParseUint(envOrDefault("MAX_SIGNERS", "3"), 10, 16)
	if err != nil {
		log.Fatalf("invalid MAX_SIGNERS: %v", err)
	}
	cfg.MaxSigners = uint16(maxSigners)

	minSigners, err := strconv.ParseUint(envOrDefault("MIN_SIGNERS", "2"), 10, 16)
	if err != nil {
		log.Fatalf("invalid MIN_SIGNERS: %v", err)
	}
	cfg.MinSigners = uint16(minSigners)

	partiesStr := requireEnv("PARTIES")
	cfg.Parties = strings.Split(partiesStr, ",")

	signersStr := os.Getenv("SIGNERS")
	if signersStr != "" {
		cfg.Signers = strings.Split(signersStr, ",")
	}

	cfg.KeygenSessionID = os.Getenv("KEYGEN_SESSION_ID")
	cfg.Mnemonic = os.Getenv("MNEMONIC")

	birthdayStr := os.Getenv("BIRTHDAY")
	if birthdayStr != "" {
		bday, parseErr := strconv.ParseUint(birthdayStr, 10, 64)
		if parseErr != nil {
			log.Fatalf("invalid BIRTHDAY: %v", parseErr)
		}
		cfg.Birthday = bday
	}

	cfg.DaemonURL = os.Getenv("DAEMON_URL")
	cfg.Recipient = os.Getenv("RECIPIENT")

	amountStr := os.Getenv("AMOUNT")
	if amountStr != "" {
		amt, parseErr := strconv.ParseUint(amountStr, 10, 64)
		if parseErr != nil {
			log.Fatalf("invalid AMOUNT: %v", parseErr)
		}
		cfg.Amount = amt
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		cancel()
	}()

	node := party.NewNode(cfg)
	err = node.Run(ctx)
	if err != nil {
		log.Fatalf("Operation failed: %v", err)
	}

	log.Println("Done.")
}

func requireEnv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		log.Fatalf("required env var %s not set", key)
	}
	return val
}

func envOrDefault(key, def string) string {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	return val
}
