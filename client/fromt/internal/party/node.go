package party

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/vultisig/frosty-lib/client/shared/relay"
	"github.com/vultisig/frosty-lib/client/fromt/internal/store"
)

type Config struct {
	RelayURL           string
	PartyID            string
	Identifier         uint16
	SessionID          string
	KeygenSessionID    string
	Parties            []string
	MaxSigners         uint16
	MinSigners         uint16
	Operation          string
	KeystoreDir        string
	KeystorePassphrase string
	SignMessage        string
	Signers            []string
	EncryptionKeyHex   string
	Mnemonic           string
	Birthday           uint64
	DaemonURL          string
	Recipient          string
	Amount             uint64
}

type Node struct {
	Config       Config
	Client       *relay.RelayClient
	Keystore     *store.Keystore
	spentOffsets []byte
}

func NewNode(cfg Config) *Node {
	var client *relay.RelayClient
	if cfg.EncryptionKeyHex != "" {
		client = relay.NewRelayClientWithEncryption(cfg.RelayURL, cfg.EncryptionKeyHex)
	} else {
		client = relay.NewRelayClient(cfg.RelayURL)
	}
	var ks *store.Keystore
	if cfg.KeystorePassphrase != "" {
		ks = store.NewKeystoreEncrypted(cfg.KeystoreDir, cfg.KeystorePassphrase)
	} else {
		ks = store.NewKeystore(cfg.KeystoreDir)
	}

	client.PartyID = cfg.PartyID

	return &Node{
		Config:   cfg,
		Client:   client,
		Keystore: ks,
	}
}

func (n *Node) Run(ctx context.Context) error {
	log.Printf("[%s] Starting node (identifier=%d, operation=%s)", n.Config.PartyID, n.Config.Identifier, n.Config.Operation)

	if n.Config.Operation == "address" {
		return n.runAddress()
	}

	if n.Config.Operation == "sign" || n.Config.Operation == "spend" {
		signers := n.Config.Signers
		if len(signers) > 0 && !contains(signers, n.Config.PartyID) {
			log.Printf("[%s] Not a signer for this session, exiting", n.Config.PartyID)
			return nil
		}
	}

	err := n.waitForRelay(ctx)
	if err != nil {
		return fmt.Errorf("wait for relay: %w", err)
	}

	participants := n.Config.Parties
	if (n.Config.Operation == "sign" || n.Config.Operation == "spend") && len(n.Config.Signers) > 0 {
		participants = n.Config.Signers
	}

	err = n.Client.JoinSession(ctx, n.Config.SessionID, participants)
	if err != nil {
		return fmt.Errorf("join session: %w", err)
	}

	log.Printf("[%s] Joined session %s, waiting for all parties", n.Config.PartyID, n.Config.SessionID)

	err = n.waitForParties(ctx, len(participants))
	if err != nil {
		return fmt.Errorf("wait for parties: %w", err)
	}

	log.Printf("[%s] All parties joined, running %s", n.Config.PartyID, n.Config.Operation)

	switch n.Config.Operation {
	case "keygen":
		return n.runKeygen(ctx)
	case "key_import":
		return n.runKeyImport(ctx)
	case "sign":
		return n.runSign(ctx)
	case "spend":
		return n.runSpend(ctx)
	default:
		return fmt.Errorf("unknown operation: %s", n.Config.Operation)
	}
}

func contains(list []string, item string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}

func (n *Node) waitForRelay(ctx context.Context) error {
	for i := 0; i < 30; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		_, err := n.Client.GetSessionParties(ctx, "health-check")
		if err == nil {
			return nil
		}

		log.Printf("[%s] Waiting for relay... (%d/30)", n.Config.PartyID, i+1)
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("relay not available after 30 attempts")
}

func (n *Node) waitForParties(ctx context.Context, expected int) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		parties, err := n.Client.GetSessionParties(ctx, n.Config.SessionID)
		if err != nil {
			return err
		}

		if len(parties) >= expected {
			sort.Strings(parties)
			log.Printf("[%s] All %d parties joined: %s", n.Config.PartyID, len(parties), strings.Join(parties, ", "))
			return nil
		}

		time.Sleep(500 * time.Millisecond)
	}
}
