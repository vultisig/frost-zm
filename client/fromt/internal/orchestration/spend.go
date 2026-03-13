package orchestration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	fromt "github.com/vultisig/frost-zm/go/fromt"
	"github.com/vultisig/frost-zm/client/shared/relay"
)

type SpendResult struct {
	RawTx []byte
	TxID  string
}

func RunSpendSign(ctx context.Context, client *relay.RelayClient, sessionID, partyID string, identifier uint16, keyShare, signableTx []byte, allParties []string) ([]byte, error) {
	handle, preprocess, err := fromt.SpendPreprocess(keyShare, signableTx)
	if err != nil {
		return nil, fmt.Errorf("spend preprocess: %w", err)
	}

	msg := RoundMessage{
		SenderID: identifier,
		Data:     base64.StdEncoding.EncodeToString(preprocess),
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal preprocess msg: %w", err)
	}

	recipients := OtherParties(allParties, partyID)
	err = client.SendMessage(ctx, sessionID, "spend-preprocess", relay.Message{
		SessionID: sessionID,
		From:      partyID,
		To:        recipients,
		Body:      string(msgBytes),
	})
	if err != nil {
		return nil, fmt.Errorf("send preprocess: %w", err)
	}

	_, err = client.WaitForBarrier(ctx, sessionID, "spend-preprocess", partyID, 1, len(allParties))
	if err != nil {
		return nil, fmt.Errorf("barrier spend-preprocess: %w", err)
	}

	preprocessMessages, err := collectMessages(ctx, client, sessionID, partyID, "spend-preprocess", len(allParties)-1)
	if err != nil {
		return nil, fmt.Errorf("collect preprocesses: %w", err)
	}

	preprocessMap, err := buildRoundMap(preprocessMessages)
	if err != nil {
		return nil, fmt.Errorf("build preprocess map: %w", err)
	}
	preprocessEncoded := fromt.EncodeMap(preprocessMap)

	sigHandle, share, err := fromt.SpendSign(handle, preprocessEncoded)
	if err != nil {
		return nil, fmt.Errorf("spend sign: %w", err)
	}

	shareMsg := RoundMessage{
		SenderID: identifier,
		Data:     base64.StdEncoding.EncodeToString(share),
	}
	shareMsgBytes, err := json.Marshal(shareMsg)
	if err != nil {
		return nil, fmt.Errorf("marshal share msg: %w", err)
	}

	err = client.SendMessage(ctx, sessionID, "spend-share", relay.Message{
		SessionID: sessionID,
		From:      partyID,
		To:        recipients,
		Body:      string(shareMsgBytes),
	})
	if err != nil {
		return nil, fmt.Errorf("send share: %w", err)
	}

	_, err = client.WaitForBarrier(ctx, sessionID, "spend-share", partyID, 1, len(allParties))
	if err != nil {
		return nil, fmt.Errorf("barrier spend-share: %w", err)
	}

	shareMessages, err := collectMessages(ctx, client, sessionID, partyID, "spend-share", len(allParties)-1)
	if err != nil {
		return nil, fmt.Errorf("collect shares: %w", err)
	}

	sharesMap, err := buildRoundMap(shareMessages)
	if err != nil {
		return nil, fmt.Errorf("build shares map: %w", err)
	}
	sharesEncoded := fromt.EncodeMap(sharesMap)

	rawTx, err := fromt.SpendComplete(sigHandle, sharesEncoded)
	if err != nil {
		return nil, fmt.Errorf("spend complete: %w", err)
	}

	return rawTx, nil
}
