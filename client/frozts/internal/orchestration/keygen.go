package orchestration

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	orch "github.com/vultisig/frosty-lib/client/shared/orchestration"
	"github.com/vultisig/frosty-lib/client/shared/relay"
	"github.com/vultisig/frosty-lib/client/shared/session"
	frozts "github.com/vultisig/frosty-lib/go/frozts"
)

type KeygenResult struct {
	KeyPackage    []byte
	PubKeyPackage []byte
	SaplingExtras []byte
	Birthday      uint64
}

type CeremonyResult = orch.CeremonyResult

type RoundMessage = orch.RoundMessage

func RunKeygen(ctx context.Context, client *relay.RelayClient, sessionID, partyID string, maxSigners, minSigners uint16, allParties []string, birthday uint64) ([]byte, *CeremonyResult, error) {
	parties := BuildPartyInfo(allParties)

	setupBytes, err := frozts.DkgSetupMsgNew(maxSigners, minSigners, parties, birthday)
	if err != nil {
		return nil, nil, fmt.Errorf("dkg setup: %w", err)
	}

	sess, err := frozts.DkgSessionFromSetup(setupBytes, []byte(partyID))
	if err != nil {
		return nil, nil, fmt.Errorf("dkg session: %w", err)
	}
	defer frozts.DkgSessionFree(sess)

	err = session.RunSession(ctx, client, sessionID, partyID, allParties, session.SessionFuncs{
		TakeMsg:     func() ([]byte, error) { return frozts.DkgSessionTakeMsg(sess) },
		Feed:        func(msg []byte) (bool, error) { return frozts.DkgSessionFeed(sess, msg) },
		MsgReceiver: func(msg []byte, i int) ([]byte, error) { return frozts.DkgSessionMsgReceiver(sess, msg, i) },
	})
	if err != nil {
		blame := handleBlame(client, sessionID, partyID, allParties, err)
		return nil, blame, fmt.Errorf("dkg session run: %w", err)
	}

	bundle, err := frozts.DkgSessionResult(sess)
	if err != nil {
		return nil, nil, fmt.Errorf("dkg result: %w", err)
	}
	return bundle, nil, nil
}

func BuildPartyInfo(parties []string) []frozts.PartyInfo {
	sorted := make([]string, len(parties))
	copy(sorted, parties)
	sort.Strings(sorted)

	infos := make([]frozts.PartyInfo, len(sorted))
	for i, name := range sorted {
		infos[i] = frozts.PartyInfo{
			FrostID: uint16(i + 1),
			Name:    []byte(name),
		}
	}
	return infos
}

var collectMessages = orch.CollectMessages

func buildRoundMap(messages []RoundMessage) ([]frozts.MapEntry, error) {
	entries := make([]frozts.MapEntry, 0, len(messages))
	for _, m := range messages {
		data, err := base64.StdEncoding.DecodeString(m.Data)
		if err != nil {
			return nil, fmt.Errorf("decode base64 from sender %d: %w", m.SenderID, err)
		}
		entries = append(entries, frozts.MapEntry{
			ID:    m.SenderID,
			Value: data,
		})
	}
	return entries, nil
}

func sendPerRecipient(ctx context.Context, client *relay.RelayClient, sessionID, partyID, messageID string, senderIdentifier uint16, mapEntries []frozts.MapEntry, allParties []string) error {
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

var OtherParties = orch.OtherParties

var IsCoordinatorParty = orch.IsCoordinatorParty

var getCoordinatorPartyID = orch.GetCoordinatorPartyID

var buildPartyIdentifierMap = orch.BuildPartyIdentifierMap

func verifyMetadataConsistency(ctx context.Context, client *relay.RelayClient, sessionID, partyID string, identifier uint16, metadata []byte, allParties []string) error {
	hashBytes, hashErr := frozts.KeygenMetadataHash(metadata)
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

var WaitForMessage = orch.WaitForMessage

func handleBlame(client *relay.RelayClient, sessionID, partyID string, allParties []string, sessionErr error) *CeremonyResult {
	return orch.HandleBlame(client, sessionID, partyID, allParties, sessionErr, frozts.LastBlamedParty)
}
