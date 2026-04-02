package party

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"

	fromt "github.com/vultisig/frosty-lib/go/fromt"
	"github.com/vultisig/frosty-lib/client/fromt/internal/orchestration"
)

func (n *Node) runKeygen(ctx context.Context) error {
	bundle, result, err := orchestration.RunKeygen(
		ctx,
		n.Client,
		n.Config.SessionID,
		n.Config.PartyID,
		n.Config.MaxSigners,
		n.Config.MinSigners,
		n.Config.Parties,
		0,
		n.Config.Birthday,
	)
	if err != nil {
		if result != nil && result.Blame != nil {
			log.Printf("[%s] Blame result: agreed=%v blamed=%s type=%s",
				n.Config.PartyID, result.Blame.Agreed, result.Blame.BlamedParty, result.Blame.BlameType)
		}
		return fmt.Errorf("keygen failed: %w", err)
	}

	err = n.Keystore.SaveBundle(n.Config.SessionID, bundle)
	if err != nil {
		return fmt.Errorf("save bundle: %w", err)
	}

	id, err := fromt.KeyShareIdentifier(bundle)
	if err != nil {
		return fmt.Errorf("get key share identifier: %w", err)
	}

	pubKey, err := fromt.KeySharePublicKey(bundle)
	if err != nil {
		return fmt.Errorf("get public key: %w", err)
	}

	viewKey, err := fromt.KeyShareViewKey(bundle)
	if err != nil {
		return fmt.Errorf("get view key: %w", err)
	}

	address, err := fromt.DeriveAddress(bundle)
	if err != nil {
		return fmt.Errorf("derive address: %w", err)
	}

	log.Printf("[%s] Keygen complete!", n.Config.PartyID)
	log.Printf("[%s]   Identifier: %d", n.Config.PartyID, id)
	log.Printf("[%s]   Public key: %s", n.Config.PartyID, hex.EncodeToString(pubKey))
	log.Printf("[%s]   View key:   %s", n.Config.PartyID, hex.EncodeToString(viewKey))
	log.Printf("[%s]   Address:    %s", n.Config.PartyID, address)

	err = n.Client.CompleteTSS(ctx, n.Config.SessionID, n.Config.Parties)
	if err != nil {
		return fmt.Errorf("complete TSS: %w", err)
	}

	return nil
}
