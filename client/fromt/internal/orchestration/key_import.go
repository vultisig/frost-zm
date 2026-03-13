package orchestration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	fromt "github.com/vultisig/frost-zm/go/fromt"
	"github.com/vultisig/frost-zm/client/shared/relay"
)

func RunKeyImport(ctx context.Context, client *relay.RelayClient, sessionID, partyID string, identifier, maxSigners, minSigners uint16, allParties []string, spendKey, expectedVK []byte, birthday uint64) (*KeygenResult, error) {
	secret1, round1Pkg, err := fromt.KeyImportPart1(identifier, maxSigners, minSigners, spendKey)
	if err != nil {
		return nil, fmt.Errorf("key import part1: %w", err)
	}

	msg := RoundMessage{
		SenderID: identifier,
		Data:     base64.StdEncoding.EncodeToString(round1Pkg),
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal round1 msg: %w", err)
	}

	recipients := OtherParties(allParties, partyID)
	err = client.SendMessage(ctx, sessionID, "import-round1", relay.Message{
		SessionID: sessionID,
		From:      partyID,
		To:        recipients,
		Body:      string(msgBytes),
	})
	if err != nil {
		return nil, fmt.Errorf("send round1: %w", err)
	}

	_, err = client.WaitForBarrier(ctx, sessionID, "import-round1", partyID, 1, len(allParties))
	if err != nil {
		return nil, fmt.Errorf("barrier import-round1: %w", err)
	}

	round1Messages, err := collectMessages(ctx, client, sessionID, partyID, "import-round1", len(allParties)-1)
	if err != nil {
		return nil, fmt.Errorf("collect round1: %w", err)
	}

	round1Map, err := buildRoundMap(round1Messages)
	if err != nil {
		return nil, fmt.Errorf("build round1 map: %w", err)
	}
	round1Encoded := fromt.EncodeMap(round1Map)

	secret2, round2Pkgs, err := fromt.DkgPart2(secret1, round1Encoded)
	if err != nil {
		return nil, fmt.Errorf("dkg part2: %w", err)
	}

	round2Map, err := fromt.DecodeMap(round2Pkgs)
	if err != nil {
		return nil, fmt.Errorf("decode round2 packages: %w", err)
	}
	err = sendPerRecipient(ctx, client, sessionID, partyID, "import-round2", identifier, round2Map, allParties)
	if err != nil {
		return nil, fmt.Errorf("send round2: %w", err)
	}

	_, err = client.WaitForBarrier(ctx, sessionID, "import-round2", partyID, 1, len(allParties))
	if err != nil {
		return nil, fmt.Errorf("barrier import-round2: %w", err)
	}

	round2Messages, err := collectMessages(ctx, client, sessionID, partyID, "import-round2", len(allParties)-1)
	if err != nil {
		return nil, fmt.Errorf("collect round2: %w", err)
	}

	round2RecvMap, err := buildRoundMap(round2Messages)
	if err != nil {
		return nil, fmt.Errorf("build round2 map: %w", err)
	}
	round2Encoded := fromt.EncodeMap(round2RecvMap)

	const networkMainnet uint8 = 0
	keyShare, pubKey, err := fromt.KeyImportPart3(secret2, round1Encoded, round2Encoded, expectedVK, networkMainnet, birthday)
	if err != nil {
		return nil, fmt.Errorf("key import part3: %w", err)
	}

	return &KeygenResult{
		KeyShare: keyShare,
		PubKey:   pubKey,
	}, nil
}
