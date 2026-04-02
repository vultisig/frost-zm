package session

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vultisig/frosty-lib/client/shared/relay"
)

type BlameType string

const (
	BlameCrypto  BlameType = "crypto"
	BlameAbsent  BlameType = "absent"
	BlameUnknown BlameType = "unknown"

	blameMessageID       = "blame"
	blameBarrierPhase    = "blame"
	blameExchangeTimeout = 30 * time.Second
)

type BlameReport struct {
	Reporter    string    `json:"reporter"`
	BlameType   BlameType `json:"blame_type"`
	BlamedParty string    `json:"blamed_party"`
	BlamedID    uint16    `json:"blamed_id"`
	Round       string    `json:"round"`
	ErrorCode   int       `json:"error_code"`
}

type BlameResult struct {
	Agreed      bool          `json:"agreed"`
	BlamedParty string        `json:"blamed_party"`
	BlameType   BlameType     `json:"blame_type"`
	Reports     []BlameReport `json:"reports"`
}

func ExchangeBlame(
	ctx context.Context,
	client *relay.RelayClient,
	sessionID, partyID string,
	allParties []string,
	myReport BlameReport,
) (*BlameResult, error) {
	blameCtx, cancel := context.WithTimeout(ctx, blameExchangeTimeout)
	defer cancel()

	reportBytes, err := json.Marshal(myReport)
	if err != nil {
		return nil, fmt.Errorf("marshal blame report: %w", err)
	}

	var recipients []string
	for _, p := range allParties {
		if p != partyID {
			recipients = append(recipients, p)
		}
	}

	err = client.SendMessage(blameCtx, sessionID, blameMessageID, relay.Message{
		SessionID: sessionID,
		From:      partyID,
		To:        recipients,
		Body:      string(reportBytes),
	})
	if err != nil {
		return nil, fmt.Errorf("send blame report: %w", err)
	}

	expectedResponders := len(allParties) - 1
	if myReport.BlameType == BlameAbsent && myReport.BlamedParty != "" {
		expectedResponders = len(allParties) - 2
		if expectedResponders < 1 {
			expectedResponders = 1
		}
	}

	_, err = client.WaitForBarrier(blameCtx, sessionID, blameBarrierPhase, partyID, 1, expectedResponders+1)
	if err != nil {
		return nil, fmt.Errorf("blame barrier: %w", err)
	}

	reports := []BlameReport{myReport}

	for {
		select {
		case <-blameCtx.Done():
			return tallyBlame(reports), nil
		default:
		}

		msgs, err := client.GetMessages(blameCtx, sessionID, partyID, blameMessageID)
		if err != nil {
			return tallyBlame(reports), nil
		}

		for _, m := range msgs {
			body, decErr := client.DecryptAndVerify(m)
			if decErr != nil {
				continue
			}
			var r BlameReport
			if json.Unmarshal([]byte(body), &r) == nil {
				reports = append(reports, r)
			}
		}

		if len(reports) >= expectedResponders+1 {
			break
		}

		time.Sleep(client.MessagePollInterval)
	}

	return tallyBlame(reports), nil
}

func tallyBlame(reports []BlameReport) *BlameResult {
	result := &BlameResult{
		Reports: reports,
	}

	counts := make(map[string]int)
	typeForParty := make(map[string]BlameType)
	for _, r := range reports {
		if r.BlamedParty != "" {
			counts[r.BlamedParty]++
			typeForParty[r.BlamedParty] = r.BlameType
		}
	}

	majority := len(reports)/2 + 1
	for party, count := range counts {
		if count >= majority {
			result.Agreed = true
			result.BlamedParty = party
			result.BlameType = typeForParty[party]
			return result
		}
	}

	return result
}
