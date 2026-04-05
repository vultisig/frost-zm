package party

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"

	frozts "github.com/vultisig/frosty-lib/go/frozts"
	"github.com/vultisig/frosty-lib/client/frozts/internal/orchestration"
)

func (n *Node) runSign(ctx context.Context) error {
	var keyPackage, pubKeyPackage []byte
	var err error

	if n.Keystore.HasBundle(n.Config.SessionID) {
		bundle, bundleErr := n.Keystore.LoadBundle(n.Config.SessionID)
		if bundleErr != nil {
			return fmt.Errorf("load bundle: %w", bundleErr)
		}
		keyPackage, err = frozts.KeyShareBundleKeyPackage(bundle)
		if err != nil {
			return fmt.Errorf("extract key package from bundle: %w", err)
		}
		pubKeyPackage, err = frozts.KeyShareBundlePubKeyPackage(bundle)
		if err != nil {
			return fmt.Errorf("extract pub key package from bundle: %w", err)
		}
	} else {
		keyPackage, err = n.Keystore.LoadKeyPackage(n.Config.SessionID)
		if err != nil {
			return fmt.Errorf("load key package: %w", err)
		}
		pubKeyPackage, err = n.Keystore.LoadPubKeyPackage(n.Config.SessionID)
		if err != nil {
			return fmt.Errorf("load pub key package: %w", err)
		}
	}

	message := []byte(n.Config.SignMessage)
	if len(message) == 0 {
		message = []byte("frozts-zcash test message")
	}

	signerParties := n.Config.Signers
	if len(signerParties) == 0 {
		signerParties = n.Config.Parties
	}

	result, ceremonyResult, err := orchestration.RunSign(
		ctx,
		n.Client,
		n.Config.SessionID,
		n.Config.PartyID,
		n.Config.Identifier,
		keyPackage,
		pubKeyPackage,
		message,
		signerParties,
	)
	if err != nil {
		if ceremonyResult != nil && ceremonyResult.Blame != nil {
			log.Printf("[%s] Blame result: agreed=%v blamed=%s type=%s",
				n.Config.PartyID, ceremonyResult.Blame.Agreed, ceremonyResult.Blame.BlamedParty, ceremonyResult.Blame.BlameType)
		}
		return fmt.Errorf("sign failed: %w", err)
	}

	log.Printf("[%s] Signing complete!", n.Config.PartyID)
	log.Printf("[%s]   Message: %s", n.Config.PartyID, string(message))
	log.Printf("[%s]   Signature: %s", n.Config.PartyID, hex.EncodeToString(result.Signature))

	err = n.Client.CompleteTSS(ctx, n.Config.SessionID, signerParties)
	if err != nil {
		return fmt.Errorf("complete TSS: %w", err)
	}

	return nil
}
