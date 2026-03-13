package party

import (
	"context"
	"fmt"
	"log"

	frozt "github.com/vultisig/frost-zm/go/frozt"
	"github.com/vultisig/frost-zm/client/frozt/internal/orchestration"
)

func (n *Node) runKeygen(ctx context.Context) error {
	bundle, err := orchestration.RunKeygen(
		ctx,
		n.Client,
		n.Config.SessionID,
		n.Config.PartyID,
		n.Config.MaxSigners,
		n.Config.MinSigners,
		n.Config.Parties,
		n.Config.Birthday,
	)
	if err != nil {
		return fmt.Errorf("keygen failed: %w", err)
	}

	err = n.Keystore.SaveBundle(n.Config.SessionID, bundle)
	if err != nil {
		return fmt.Errorf("save bundle: %w", err)
	}

	kp, err := frozt.KeyShareBundleKeyPackage(bundle)
	if err != nil {
		return fmt.Errorf("extract key package: %w", err)
	}

	pkp, err := frozt.KeyShareBundlePubKeyPackage(bundle)
	if err != nil {
		return fmt.Errorf("extract pub key package: %w", err)
	}

	extras, err := frozt.KeyShareBundleSaplingExtras(bundle)
	if err != nil {
		return fmt.Errorf("extract sapling extras: %w", err)
	}

	err = n.Keystore.SaveKeyPackage(n.Config.SessionID, kp)
	if err != nil {
		return fmt.Errorf("save key package: %w", err)
	}

	err = n.Keystore.SavePubKeyPackage(n.Config.SessionID, pkp)
	if err != nil {
		return fmt.Errorf("save pub key package: %w", err)
	}

	err = n.Keystore.SaveSaplingExtras(n.Config.SessionID, extras)
	if err != nil {
		return fmt.Errorf("save sapling extras: %w", err)
	}

	id, err := frozt.KeyPackageIdentifier(kp)
	if err != nil {
		return fmt.Errorf("get key package identifier: %w", err)
	}

	verifyingKey, err := frozt.PubKeyPackageVerifyingKey(pkp)
	if err != nil {
		return fmt.Errorf("get verifying key: %w", err)
	}

	keys, err := frozt.SaplingDeriveKeys(pkp, extras)
	if err != nil {
		return fmt.Errorf("derive z-address: %w", err)
	}

	log.Printf("[%s] Keygen complete!", n.Config.PartyID)
	log.Printf("[%s]   Identifier: %d", n.Config.PartyID, id)
	log.Printf("[%s]   Verifying key: %x", n.Config.PartyID, verifyingKey)
	log.Printf("[%s]   Z-address: %s", n.Config.PartyID, keys.Address)

	err = n.Client.CompleteTSS(ctx, n.Config.SessionID, n.Config.Parties)
	if err != nil {
		return fmt.Errorf("complete TSS: %w", err)
	}

	return nil
}
