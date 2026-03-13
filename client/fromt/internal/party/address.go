package party

import (
	"encoding/hex"
	"fmt"
	"log"

	fromt "github.com/vultisig/frost-zm/go/fromt"
)

func (n *Node) runAddress() error {
	keystoreSession := n.Config.KeygenSessionID
	if keystoreSession == "" {
		keystoreSession = n.Config.SessionID
	}

	keyShare, err := n.Keystore.LoadKeyShare(keystoreSession)
	if err != nil {
		return fmt.Errorf("load key share: %w", err)
	}

	id, err := fromt.KeyShareIdentifier(keyShare)
	if err != nil {
		return fmt.Errorf("get identifier: %w", err)
	}

	pubKey, err := fromt.KeySharePublicKey(keyShare)
	if err != nil {
		return fmt.Errorf("get public key: %w", err)
	}

	viewKey, err := fromt.KeyShareViewKey(keyShare)
	if err != nil {
		return fmt.Errorf("get view key: %w", err)
	}

	address, err := fromt.DeriveAddress(keyShare)
	if err != nil {
		return fmt.Errorf("derive address: %w", err)
	}

	log.Printf("[%s] Address derivation", n.Config.PartyID)
	log.Printf("[%s]   Identifier:  %d", n.Config.PartyID, id)
	log.Printf("[%s]   Public key:  %s", n.Config.PartyID, hex.EncodeToString(pubKey))
	log.Printf("[%s]   View key:    %s", n.Config.PartyID, hex.EncodeToString(viewKey))
	log.Printf("[%s]   Address:     %s", n.Config.PartyID, address)

	return nil
}
