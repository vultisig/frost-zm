package orchestration

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/vultisig/frosty-lib/client/shared/relay"
	"github.com/vultisig/frosty-lib/client/shared/session"
)

type CeremonyResult struct {
	Blame *session.BlameResult
}

type RoundMessage struct {
	SenderID   uint16 `json:"sender_id"`
	Data       string `json:"data"`
	ReceiverID uint16 `json:"receiver_id,omitempty"`
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
	return partyID == GetCoordinatorPartyID(parties)
}

func GetCoordinatorPartyID(parties []string) string {
	sorted := make([]string, len(parties))
	copy(sorted, parties)
	sort.Strings(sorted)
	return sorted[0]
}

func BuildPartyIdentifierMap(parties []string) map[uint16]string {
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

func CollectMessages(ctx context.Context, client *relay.RelayClient, sessionID, partyID, messageID string, expected int) ([]RoundMessage, error) {
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

func HandleBlame(client *relay.RelayClient, sessionID, partyID string, allParties []string, sessionErr error, lastBlamedParty func() uint16) *CeremonyResult {
	idToName := BuildPartyIdentifierMap(allParties)

	var report session.BlameReport
	report.Reporter = partyID

	blamedID := lastBlamedParty()
	if blamedID > 0 {
		report.BlameType = session.BlameCrypto
		report.BlamedID = blamedID
		name, ok := idToName[blamedID]
		if ok {
			report.BlamedParty = name
		}
	} else if strings.Contains(sessionErr.Error(), "context") {
		report.BlameType = session.BlameAbsent
	} else {
		report.BlameType = session.BlameUnknown
	}

	blameCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	blameResult, err := session.ExchangeBlame(blameCtx, client, sessionID, partyID, allParties, report)
	if err != nil {
		log.Printf("[blame:%s] exchange failed: %v", partyID, err)
		return &CeremonyResult{Blame: &session.BlameResult{Reports: []session.BlameReport{report}}}
	}

	return &CeremonyResult{Blame: blameResult}
}
