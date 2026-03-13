package orchestration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	fromt "github.com/vultisig/frost-zm/go/fromt"
	"github.com/vultisig/frost-zm/client/shared/relay"
	"github.com/vultisig/frost-zm/client/shared/session"
)

type KeygenResult struct {
	KeyShare []byte
	PubKey   []byte
}

type RoundMessage struct {
	SenderID   uint16 `json:"sender_id"`
	Data       string `json:"data"`
	ReceiverID uint16 `json:"receiver_id,omitempty"`
}

func RunKeygen(ctx context.Context, client *relay.RelayClient, sessionID, partyID string, maxSigners, minSigners uint16, allParties []string, network uint8, birthday uint64) ([]byte, error) {
	parties := BuildPartyInfo(allParties)

	setupBytes, err := fromt.DkgSetupMsgNew(maxSigners, minSigners, parties, network, birthday)
	if err != nil {
		return nil, fmt.Errorf("dkg setup: %w", err)
	}

	sess, err := fromt.DkgSessionFromSetup(setupBytes, []byte(partyID))
	if err != nil {
		return nil, fmt.Errorf("dkg session: %w", err)
	}
	defer fromt.DkgSessionFree(sess)

	err = session.RunSession(ctx, client, sessionID, partyID, allParties, session.SessionFuncs{
		TakeMsg:     func() ([]byte, error) { return fromt.DkgSessionTakeMsg(sess) },
		Feed:        func(msg []byte) (bool, error) { return fromt.DkgSessionFeed(sess, msg) },
		MsgReceiver: func(msg []byte, i int) ([]byte, error) { return fromt.DkgSessionMsgReceiver(sess, msg, i) },
	})
	if err != nil {
		return nil, fmt.Errorf("dkg session run: %w", err)
	}

	bundle, err := fromt.DkgSessionResult(sess)
	if err != nil {
		return nil, fmt.Errorf("dkg result: %w", err)
	}
	return bundle, nil
}

func BuildPartyInfo(parties []string) []fromt.PartyInfo {
	sorted := make([]string, len(parties))
	copy(sorted, parties)
	sort.Strings(sorted)

	infos := make([]fromt.PartyInfo, len(sorted))
	for i, name := range sorted {
		infos[i] = fromt.PartyInfo{
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

func buildRoundMap(messages []RoundMessage) ([]fromt.MapEntry, error) {
	entries := make([]fromt.MapEntry, 0, len(messages))
	for _, m := range messages {
		idBytes, err := fromt.EncodeIdentifier(m.SenderID)
		if err != nil {
			return nil, fmt.Errorf("encode identifier %d: %w", m.SenderID, err)
		}
		data, err := base64.StdEncoding.DecodeString(m.Data)
		if err != nil {
			return nil, fmt.Errorf("decode base64 from sender %d: %w", m.SenderID, err)
		}
		entries = append(entries, fromt.MapEntry{
			ID:    idBytes,
			Value: data,
		})
	}
	return entries, nil
}

func sendPerRecipient(ctx context.Context, client *relay.RelayClient, sessionID, partyID, messageID string, senderIdentifier uint16, mapEntries []fromt.MapEntry, allParties []string) error {
	partyMap := buildPartyIdentifierMap(allParties)

	for _, entry := range mapEntries {
		recipientID, err := fromt.DecodeIdentifier(entry.ID)
		if err != nil {
			return fmt.Errorf("decode recipient id: %w", err)
		}

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
