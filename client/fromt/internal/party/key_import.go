package party

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"

	fromt "github.com/vultisig/frosty-lib/go/fromt"
	"github.com/vultisig/frosty-lib/client/fromt/internal/mnemonic"
	"github.com/vultisig/frosty-lib/client/fromt/internal/orchestration"
	"github.com/vultisig/frosty-lib/client/shared/relay"
)

type expectedVKMessage struct {
	PubKey string `json:"pub_key"`
}

func (n *Node) runKeyImport(ctx context.Context) error {
	var spendKey []byte
	var expectedVK []byte

	if n.Config.Mnemonic != "" {
		seed, err := mnemonic.DeriveMoneroSeed(n.Config.Mnemonic)
		if err != nil {
			return fmt.Errorf("derive seed from mnemonic: %w", err)
		}

		sk, vk, err := fromt.DeriveKeysFromSeed(seed)
		if err != nil {
			return fmt.Errorf("derive keys from seed: %w", err)
		}

		pk, err := fromt.SpendKeyToPublic(sk)
		if err != nil {
			return fmt.Errorf("spend key to public: %w", err)
		}

		spendKey = sk
		expectedVK = pk

		log.Printf("[%s] Derived spend key from mnemonic", n.Config.PartyID)
		log.Printf("[%s]   View key:    %s", n.Config.PartyID, hex.EncodeToString(vk))
		log.Printf("[%s]   Expected VK: %s", n.Config.PartyID, hex.EncodeToString(pk))

		msg, err := json.Marshal(expectedVKMessage{
			PubKey: base64.StdEncoding.EncodeToString(pk),
		})
		if err != nil {
			return fmt.Errorf("marshal expected vk: %w", err)
		}

		recipients := orchestration.OtherParties(n.Config.Parties, n.Config.PartyID)
		err = n.Client.SendMessage(ctx, n.Config.SessionID, "import-expected-vk", relay.Message{
			SessionID: n.Config.SessionID,
			From:      n.Config.PartyID,
			To:        recipients,
			Body:      string(msg),
		})
		if err != nil {
			return fmt.Errorf("broadcast expected vk: %w", err)
		}
	} else {
		log.Printf("[%s] No mnemonic provided, joining as auxiliary party", n.Config.PartyID)

		vk, err := receiveExpectedVK(ctx, n.Client, n.Config.SessionID, n.Config.PartyID)
		if err != nil {
			return fmt.Errorf("receive expected vk: %w", err)
		}
		expectedVK = vk
		log.Printf("[%s]   Expected VK: %s", n.Config.PartyID, hex.EncodeToString(vk))
	}

	_, err := n.Client.WaitForBarrier(ctx, n.Config.SessionID, "import-vk-exchanged", n.Config.PartyID, 1, len(n.Config.Parties))
	if err != nil {
		return fmt.Errorf("barrier import-vk-exchanged: %w", err)
	}

	result, err := orchestration.RunKeyImport(
		ctx,
		n.Client,
		n.Config.SessionID,
		n.Config.PartyID,
		n.Config.Identifier,
		n.Config.MaxSigners,
		n.Config.MinSigners,
		n.Config.Parties,
		spendKey,
		expectedVK,
		n.Config.Birthday,
	)
	if err != nil {
		return fmt.Errorf("key import failed: %w", err)
	}

	err = n.Keystore.SaveKeyShare(n.Config.SessionID, result.KeyShare)
	if err != nil {
		return fmt.Errorf("save key share: %w", err)
	}

	err = n.Keystore.SavePubKey(n.Config.SessionID, result.PubKey)
	if err != nil {
		return fmt.Errorf("save pub key: %w", err)
	}

	id, err := fromt.KeyShareIdentifier(result.KeyShare)
	if err != nil {
		return fmt.Errorf("get key share identifier: %w", err)
	}

	pubKey, err := fromt.KeySharePublicKey(result.KeyShare)
	if err != nil {
		return fmt.Errorf("get public key: %w", err)
	}

	viewKey, err := fromt.KeyShareViewKey(result.KeyShare)
	if err != nil {
		return fmt.Errorf("get view key: %w", err)
	}

	address, err := fromt.DeriveAddress(result.KeyShare)
	if err != nil {
		return fmt.Errorf("derive address: %w", err)
	}

	birthday, err := fromt.KeyShareBirthday(result.KeyShare)
	if err != nil {
		return fmt.Errorf("get birthday: %w", err)
	}

	log.Printf("[%s] Key import complete!", n.Config.PartyID)
	log.Printf("[%s]   Identifier: %d", n.Config.PartyID, id)
	log.Printf("[%s]   Public key: %s", n.Config.PartyID, hex.EncodeToString(pubKey))
	log.Printf("[%s]   View key:   %s", n.Config.PartyID, hex.EncodeToString(viewKey))
	log.Printf("[%s]   Address:    %s", n.Config.PartyID, address)
	log.Printf("[%s]   Birthday:   %d", n.Config.PartyID, birthday)

	err = n.Client.CompleteTSS(ctx, n.Config.SessionID, n.Config.Parties)
	if err != nil {
		return fmt.Errorf("complete TSS: %w", err)
	}

	return nil
}

func receiveExpectedVK(ctx context.Context, client *relay.RelayClient, sessionID, partyID string) ([]byte, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		msgs, err := client.GetMessages(ctx, sessionID, partyID, "import-expected-vk")
		if err != nil {
			return nil, err
		}

		for _, m := range msgs {
			body, decErr := client.DecryptAndVerify(m)
			if decErr != nil {
				return nil, fmt.Errorf("decrypt expected vk: %w", decErr)
			}
			var vkMsg expectedVKMessage
			err = json.Unmarshal([]byte(body), &vkMsg)
			if err != nil {
				return nil, fmt.Errorf("unmarshal expected vk: %w", err)
			}
			pk, err := base64.StdEncoding.DecodeString(vkMsg.PubKey)
			if err != nil {
				return nil, fmt.Errorf("decode expected vk base64: %w", err)
			}
			return pk, nil
		}

		time.Sleep(client.MessagePollInterval)
	}
}
