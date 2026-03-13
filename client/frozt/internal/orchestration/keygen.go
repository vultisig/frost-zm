package orchestration

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	frozt "github.com/vultisig/frost-zm/go/frozt"
	"github.com/vultisig/frost-zm/client/shared/relay"
	"github.com/vultisig/frost-zm/client/shared/session"
)

type KeygenResult struct {
	KeyPackage    []byte
	PubKeyPackage []byte
	SaplingExtras []byte
	Birthday      uint64
}

type RoundMessage struct {
	SenderID   uint16 `json:"sender_id"`
	Data       string `json:"data"`
	ReceiverID uint16 `json:"receiver_id,omitempty"`
}

func RunKeygen(ctx context.Context, client *relay.RelayClient, sessionID, partyID string, maxSigners, minSigners uint16, allParties []string, birthday uint64) ([]byte, error) {
	parties := BuildPartyInfo(allParties)

	setupBytes, err := frozt.DkgSetupMsgNew(maxSigners, minSigners, parties, birthday)
	if err != nil {
		return nil, fmt.Errorf("dkg setup: %w", err)
	}

	sess, err := frozt.DkgSessionFromSetup(setupBytes, []byte(partyID))
	if err != nil {
		return nil, fmt.Errorf("dkg session: %w", err)
	}
	defer frozt.DkgSessionFree(sess)

	err = session.RunSession(ctx, client, sessionID, partyID, allParties, session.SessionFuncs{
		TakeMsg:     func() ([]byte, error) { return frozt.DkgSessionTakeMsg(sess) },
		Feed:        func(msg []byte) (bool, error) { return frozt.DkgSessionFeed(sess, msg) },
		MsgReceiver: func(msg []byte, i int) ([]byte, error) { return frozt.DkgSessionMsgReceiver(sess, msg, i) },
	})
	if err != nil {
		return nil, fmt.Errorf("dkg session run: %w", err)
	}

	bundle, err := frozt.DkgSessionResult(sess)
	if err != nil {
		return nil, fmt.Errorf("dkg result: %w", err)
	}
	return bundle, nil
}

func BuildPartyInfo(parties []string) []frozt.PartyInfo {
	sorted := make([]string, len(parties))
	copy(sorted, parties)
	sort.Strings(sorted)

	infos := make([]frozt.PartyInfo, len(sorted))
	for i, name := range sorted {
		infos[i] = frozt.PartyInfo{
			FrostID: uint16(i + 1),
			Name:    []byte(name),
		}
	}
	return infos
}

func collectMessages(ctx context.Context, client *relay.RelayClient, sessionID, partyID, messageID string, expected int) ([]RoundMessage, error) {
	var collected []RoundMessage
	seen := make(map[uint16]bool)

	for len(collected) < expected {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		msgs, err := client.GetMessages(ctx, sessionID, partyID, messageID)
		if err != nil {
			return nil, err
		}

		for _, m := range msgs {
			body, decErr := client.DecryptAndVerify(m)
			if decErr != nil {
				return nil, fmt.Errorf("decrypt round message: %w", decErr)
			}
			var rm RoundMessage
			err = json.Unmarshal([]byte(body), &rm)
			if err != nil {
				return nil, fmt.Errorf("unmarshal round message: %w", err)
			}
			if !seen[rm.SenderID] {
				seen[rm.SenderID] = true
				collected = append(collected, rm)
			}
		}

		if len(collected) < expected {
			time.Sleep(client.MessagePollInterval)
		}
	}

	return collected, nil
}

func buildRoundMap(messages []RoundMessage) ([]frozt.MapEntry, error) {
	entries := make([]frozt.MapEntry, 0, len(messages))
	for _, m := range messages {
		data, err := base64.StdEncoding.DecodeString(m.Data)
		if err != nil {
			return nil, fmt.Errorf("decode base64 from sender %d: %w", m.SenderID, err)
		}
		entries = append(entries, frozt.MapEntry{
			ID:    m.SenderID,
			Value: data,
		})
	}
	return entries, nil
}

func sendPerRecipient(ctx context.Context, client *relay.RelayClient, sessionID, partyID, messageID string, senderIdentifier uint16, mapEntries []frozt.MapEntry, allParties []string) error {
	partyMap := buildPartyIdentifierMap(allParties)

	for _, entry := range mapEntries {
		recipientID := entry.ID

		recipientPartyID, ok := partyMap[recipientID]
		if !ok {
			return fmt.Errorf("no party found for identifier %d", recipientID)
		}

		msg := RoundMessage{
			SenderID:   senderIdentifier,
			ReceiverID: recipientID,
			Data:       base64.StdEncoding.EncodeToString(entry.Value),
		}
		msgBytes, err := json.Marshal(msg)
		if err != nil {
			return err
		}

		err = client.SendMessage(ctx, sessionID, messageID, relay.Message{
			SessionID: sessionID,
			From:      partyID,
			To:        []string{recipientPartyID},
			Body:      string(msgBytes),
		})
		if err != nil {
			return fmt.Errorf("send to %s: %w", recipientPartyID, err)
		}
	}

	return nil
}

func OtherParties(all []string, self string) []string {
	var others []string
	for _, p := range all {
		if p != self {
			others = append(others, p)
		}
	}
	return others
}

func IsCoordinatorParty(partyID string, parties []string) bool {
	return partyID == getCoordinatorPartyID(parties)
}

func getCoordinatorPartyID(parties []string) string {
	sorted := make([]string, len(parties))
	copy(sorted, parties)
	sort.Strings(sorted)
	return sorted[0]
}

func buildPartyIdentifierMap(parties []string) map[uint16]string {
	sorted := make([]string, len(parties))
	copy(sorted, parties)
	sort.Strings(sorted)

	m := make(map[uint16]string, len(sorted))
	for i, p := range sorted {
		m[uint16(i+1)] = p
	}
	return m
}

func verifyMetadataConsistency(ctx context.Context, client *relay.RelayClient, sessionID, partyID string, identifier uint16, metadata []byte, allParties []string) error {
	hashBytes, hashErr := frozt.KeygenMetadataHash(metadata)
	if hashErr != nil {
		return fmt.Errorf("compute metadata hash: %w", hashErr)
	}
	myHash := hex.EncodeToString(hashBytes)

	msg := RoundMessage{
		SenderID: identifier,
		Data:     myHash,
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal hash: %w", err)
	}

	recipients := OtherParties(allParties, partyID)
	err = client.SendMessage(ctx, sessionID, "keygen-metadata-hash", relay.Message{
		SessionID: sessionID,
		From:      partyID,
		To:        recipients,
		Body:      string(msgBytes),
	})
	if err != nil {
		return fmt.Errorf("send hash: %w", err)
	}

	_, err = client.WaitForBarrier(ctx, sessionID, "keygen-metadata-hash", partyID, 1, len(allParties))
	if err != nil {
		return fmt.Errorf("barrier: %w", err)
	}

	messages, err := collectMessages(ctx, client, sessionID, partyID, "keygen-metadata-hash", len(allParties)-1)
	if err != nil {
		return fmt.Errorf("collect hashes: %w", err)
	}

	for _, m := range messages {
		if m.Data != myHash {
			return fmt.Errorf("party %d has different sapling extras hash", m.SenderID)
		}
	}

	return nil
}

func WaitForMessage(ctx context.Context, client *relay.RelayClient, sessionID, partyID, messageID string, parse func(string) error) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msgs, err := client.GetMessages(ctx, sessionID, partyID, messageID)
		if err != nil {
			return err
		}

		if len(msgs) > 0 {
			body, decErr := client.DecryptAndVerify(msgs[0])
			if decErr != nil {
				return fmt.Errorf("decrypt message: %w", decErr)
			}
			return parse(body)
		}

		time.Sleep(client.MessagePollInterval)
	}
}
