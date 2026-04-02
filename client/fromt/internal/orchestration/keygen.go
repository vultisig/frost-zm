package orchestration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"

	orch "github.com/vultisig/frosty-lib/client/shared/orchestration"
	"github.com/vultisig/frosty-lib/client/shared/relay"
	"github.com/vultisig/frosty-lib/client/shared/session"
	fromt "github.com/vultisig/frosty-lib/go/fromt"
)

type KeygenResult struct {
	KeyShare []byte
	PubKey   []byte
}

type CeremonyResult = orch.CeremonyResult

type RoundMessage = orch.RoundMessage

func RunKeygen(ctx context.Context, client *relay.RelayClient, sessionID, partyID string, maxSigners, minSigners uint16, allParties []string, network uint8, birthday uint64) ([]byte, *CeremonyResult, error) {
	parties := BuildPartyInfo(allParties)

	setupBytes, err := fromt.DkgSetupMsgNew(maxSigners, minSigners, parties, network, birthday)
	if err != nil {
		return nil, nil, fmt.Errorf("dkg setup: %w", err)
	}

	sess, err := fromt.DkgSessionFromSetup(setupBytes, []byte(partyID))
	if err != nil {
		return nil, nil, fmt.Errorf("dkg session: %w", err)
	}
	defer fromt.DkgSessionFree(sess)

	err = session.RunSession(ctx, client, sessionID, partyID, allParties, session.SessionFuncs{
		TakeMsg:     func() ([]byte, error) { return fromt.DkgSessionTakeMsg(sess) },
		Feed:        func(msg []byte) (bool, error) { return fromt.DkgSessionFeed(sess, msg) },
		MsgReceiver: func(msg []byte, i int) ([]byte, error) { return fromt.DkgSessionMsgReceiver(sess, msg, i) },
	})
	if err != nil {
		blame := handleBlame(client, sessionID, partyID, allParties, err)
		return nil, blame, fmt.Errorf("dkg session run: %w", err)
	}

	bundle, err := fromt.DkgSessionResult(sess)
	if err != nil {
		return nil, nil, fmt.Errorf("dkg result: %w", err)
	}
	return bundle, nil, nil
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

var collectMessages = orch.CollectMessages

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

var OtherParties = orch.OtherParties

var IsCoordinatorParty = orch.IsCoordinatorParty

var getCoordinatorPartyID = orch.GetCoordinatorPartyID

var buildPartyIdentifierMap = orch.BuildPartyIdentifierMap

var WaitForMessage = orch.WaitForMessage

func handleBlame(client *relay.RelayClient, sessionID, partyID string, allParties []string, sessionErr error) *CeremonyResult {
	return orch.HandleBlame(client, sessionID, partyID, allParties, sessionErr, fromt.LastBlamedParty)
}
