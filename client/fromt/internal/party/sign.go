package party

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/vultisig/frosty-lib/client/fromt/internal/orchestration"
)

func (n *Node) runSign(ctx context.Context) error {
	keystoreSession := n.Config.KeygenSessionID
	if keystoreSession == "" {
		keystoreSession = n.Config.SessionID
	}
	keyShare, err := n.Keystore.LoadKeyShare(keystoreSession)
	if err != nil {
		return fmt.Errorf("load key share: %w", err)
	}

	message := []byte(n.Config.SignMessage)
	if len(message) == 0 {
		message = []byte("fromt monero test message")
	}

	signerParties := n.Config.Signers
	if len(signerParties) == 0 {
		signerParties = n.Config.Parties
	}

	result, ceremony, err := orchestration.RunSign(
		ctx,
		n.Client,
		n.Config.SessionID,
		n.Config.PartyID,
		n.Config.Identifier,
		keyShare,
		message,
		signerParties,
	)
	if err != nil {
		if ceremony != nil && ceremony.Blame != nil {
			log.Printf("[%s] Blame result: agreed=%v blamed=%s type=%s",
				n.Config.PartyID, ceremony.Blame.Agreed, ceremony.Blame.BlamedParty, ceremony.Blame.BlameType)
		}
		return fmt.Errorf("sign failed: %w", err)
	}

	log.Printf("[%s] Signing complete!", n.Config.PartyID)
	log.Printf("[%s]   Message:   %s", n.Config.PartyID, string(message))
	log.Printf("[%s]   Signature: %s", n.Config.PartyID, hex.EncodeToString(result.Signature))

	err = n.Client.CompleteTSS(ctx, n.Config.SessionID, signerParties)
	if err != nil {
		return fmt.Errorf("complete TSS: %w", err)
	}

	return nil
}
