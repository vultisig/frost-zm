package party

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	fromt "github.com/vultisig/frosty-lib/go/fromt"
	fromtsdk "github.com/vultisig/frosty-lib/go/fromt-sdk"
	"github.com/vultisig/frosty-lib/client/fromt/internal/mnemonic"
	"github.com/vultisig/frosty-lib/client/fromt/internal/orchestration"
	"github.com/vultisig/frosty-lib/client/shared/relay"
)

type signableTxMessage struct {
	Data string `json:"data"`
}

func (n *Node) runSpend(ctx context.Context) error {
	keyShare, err := n.Keystore.LoadKeyShare(n.Config.KeygenSessionID)
	if err != nil {
		return fmt.Errorf("load keyshare: %w", err)
	}

	signers := n.Config.Signers
	if len(signers) == 0 {
		signers = n.Config.Parties
	}

	isCoordinator := signers[0] == n.Config.PartyID

	var signableTx []byte

	if isCoordinator {
		log.Printf("[%s] Coordinator: preparing spend transaction...", n.Config.PartyID)
		log.Printf("[%s]   Daemon: %s", n.Config.PartyID, n.Config.DaemonURL)
		log.Printf("[%s]   Recipient: %s", n.Config.PartyID, n.Config.Recipient)
		log.Printf("[%s]   Amount: %d piconero", n.Config.PartyID, n.Config.Amount)
		log.Printf("[%s]   Birthday: %d", n.Config.PartyID, n.Config.Birthday)

		excludedOffsets, _ := n.Keystore.LoadSpentOffsets(n.Config.KeygenSessionID)

		var spendKey []byte
		if n.Config.Mnemonic != "" {
			seed, seedErr := mnemonic.DeriveMoneroSeed(n.Config.Mnemonic)
			if seedErr == nil {
				sk, _, skErr := fromt.DeriveKeysFromSeed(seed)
				if skErr == nil {
					spendKey = sk
					log.Printf("[%s] Derived spend key from mnemonic for key image checking", n.Config.PartyID)
				}
			}
		}

		stx, spentOffsets, prepErr := fromtsdk.SpendPrepare(
			keyShare,
			n.Config.DaemonURL,
			n.Config.Recipient,
			n.Config.Amount,
			n.Config.Birthday,
			excludedOffsets,
			spendKey,
		)
		if prepErr != nil {
			return fmt.Errorf("spend prepare: %w", prepErr)
		}
		signableTx = stx
		n.spentOffsets = spentOffsets

		log.Printf("[%s] Transaction prepared (%d bytes), broadcasting to signers", n.Config.PartyID, len(signableTx))

		msg, marshalErr := json.Marshal(signableTxMessage{
			Data: base64.StdEncoding.EncodeToString(signableTx),
		})
		if marshalErr != nil {
			return fmt.Errorf("marshal signable tx: %w", marshalErr)
		}

		recipients := orchestration.OtherParties(signers, n.Config.PartyID)
		err = n.Client.SendMessage(ctx, n.Config.SessionID, "spend-signable-tx", relay.Message{
			SessionID: n.Config.SessionID,
			From:      n.Config.PartyID,
			To:        recipients,
			Body:      string(msg),
		})
		if err != nil {
			return fmt.Errorf("broadcast signable tx: %w", err)
		}
	} else {
		log.Printf("[%s] Waiting for signable transaction from coordinator...", n.Config.PartyID)

		stx, rcvErr := receiveSignableTx(ctx, n.Client, n.Config.SessionID, n.Config.PartyID)
		if rcvErr != nil {
			return fmt.Errorf("receive signable tx: %w", rcvErr)
		}
		signableTx = stx
		log.Printf("[%s] Received signable transaction (%d bytes)", n.Config.PartyID, len(signableTx))
	}

	_, err = n.Client.WaitForBarrier(ctx, n.Config.SessionID, "spend-tx-exchanged", n.Config.PartyID, 1, len(signers))
	if err != nil {
		return fmt.Errorf("barrier spend-tx-exchanged: %w", err)
	}

	log.Printf("[%s] Running CLSAG signing ceremony...", n.Config.PartyID)

	rawTx, err := orchestration.RunSpendSign(
		ctx,
		n.Client,
		n.Config.SessionID,
		n.Config.PartyID,
		n.Config.Identifier,
		keyShare,
		signableTx,
		signers,
	)
	if err != nil {
		return fmt.Errorf("spend sign: %w", err)
	}

	log.Printf("[%s] Transaction signed! (%d bytes)", n.Config.PartyID, len(rawTx))

	if isCoordinator {
		log.Printf("[%s] Broadcasting transaction to %s...", n.Config.PartyID, n.Config.DaemonURL)

		result, broadcastErr := broadcastRawTx(n.Config.DaemonURL, rawTx)
		if broadcastErr != nil {
			log.Printf("[%s] Broadcast error: %v", n.Config.PartyID, broadcastErr)
			return fmt.Errorf("broadcast: %w", broadcastErr)
		}

		log.Printf("[%s] Transaction broadcast! status=%s", n.Config.PartyID, result)

		if len(n.spentOffsets) > 0 {
			saveErr := n.Keystore.SaveSpentOffsets(n.Config.KeygenSessionID, n.spentOffsets)
			if saveErr != nil {
				log.Printf("[%s] Warning: failed to save spent offsets: %v", n.Config.PartyID, saveErr)
			} else {
				log.Printf("[%s] Saved %d spent output offsets", n.Config.PartyID, len(n.spentOffsets)/32)
			}
		}
	}

	_, err = n.Client.WaitForBarrier(ctx, n.Config.SessionID, "spend-done", n.Config.PartyID, 1, len(signers))
	if err != nil {
		return fmt.Errorf("barrier spend-done: %w", err)
	}

	log.Printf("[%s] Spend complete!", n.Config.PartyID)

	return nil
}

func receiveSignableTx(ctx context.Context, client *relay.RelayClient, sessionID, partyID string) ([]byte, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		msgs, err := client.GetMessages(ctx, sessionID, partyID, "spend-signable-tx")
		if err != nil {
			return nil, err
		}

		for _, m := range msgs {
			body, decErr := client.DecryptAndVerify(m)
			if decErr != nil {
				return nil, fmt.Errorf("decrypt signable tx: %w", decErr)
			}
			var stxMsg signableTxMessage
			err = json.Unmarshal([]byte(body), &stxMsg)
			if err != nil {
				return nil, fmt.Errorf("unmarshal signable tx: %w", err)
			}
			decoded, err := base64.StdEncoding.DecodeString(stxMsg.Data)
			if err != nil {
				return nil, fmt.Errorf("decode signable tx base64: %w", err)
			}
			return decoded, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}
}

func broadcastRawTx(daemonURL string, rawTx []byte) (string, error) {
	body, err := json.Marshal(map[string]string{
		"tx_as_hex": hex.EncodeToString(rawTx),
	})
	if err != nil {
		return "", err
	}

	resp, err := http.Post(daemonURL+"/sendrawtransaction", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	var result struct {
		Status      string `json:"status"`
		Reason      string `json:"reason"`
		DoubleSpend bool   `json:"double_spend"`
		InvalidInput bool  `json:"invalid_input"`
	}
	err = json.Unmarshal(respBody, &result)
	if err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	if result.Status != "OK" {
		return "", fmt.Errorf("rejected: status=%s reason=%q double_spend=%v invalid_input=%v",
			result.Status, result.Reason, result.DoubleSpend, result.InvalidInput)
	}
	return "OK", nil
}
