package session

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/vultisig/frosty-lib/client/shared/relay"
)

type SessionFuncs struct {
	TakeMsg     func() ([]byte, error)
	Feed        func([]byte) (bool, error)
	MsgReceiver func([]byte, int) ([]byte, error)
	Free        func() error
}

type seenKey struct {
	from string
	seq  uint64
}

func RunSession(ctx context.Context, client *relay.RelayClient, sessionID, partyID string, allParties []string, s SessionFuncs) error {
	nameToFrostID := buildNameToFrostID(allParties)
	seen := make(map[seenKey]bool)
	messageID := "session"

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		sentAny, err := drainOutbox(ctx, client, sessionID, partyID, messageID, s)
		if err != nil {
			return fmt.Errorf("drain outbox: %w", err)
		}

		finished, gotAny, err := pollInbox(ctx, client, sessionID, partyID, messageID, nameToFrostID, seen, s)
		if err != nil {
			return fmt.Errorf("poll inbox: %w", err)
		}
		if finished {
			_, drainErr := drainOutbox(ctx, client, sessionID, partyID, messageID, s)
			if drainErr != nil {
				log.Printf("[session:%s] Warning: final drain outbox: %v", partyID, drainErr)
			}
			return nil
		}

		if !sentAny && !gotAny {
			time.Sleep(client.MessagePollInterval)
		}
	}
}

func drainOutbox(ctx context.Context, client *relay.RelayClient, sessionID, partyID, messageID string, s SessionFuncs) (bool, error) {
	sentAny := false
	for {
		msg, err := s.TakeMsg()
		if err != nil {
			return sentAny, fmt.Errorf("take_msg: %w", err)
		}
		if msg == nil {
			return sentAny, nil
		}

		payload := msg[2:]
		encoded := base64.StdEncoding.EncodeToString(payload)

		for i := 0; ; i++ {
			name, err := s.MsgReceiver(msg, i)
			if err != nil {
				return sentAny, fmt.Errorf("msg_receiver: %w", err)
			}
			if name == nil {
				break
			}

			err = client.SendMessage(ctx, sessionID, messageID, relay.Message{
				SessionID: sessionID,
				From:      partyID,
				To:        []string{string(name)},
				Body:      encoded,
			})
			if err != nil {
				return sentAny, fmt.Errorf("send to %s: %w", string(name), err)
			}
			sentAny = true
		}
	}
}

func pollInbox(ctx context.Context, client *relay.RelayClient, sessionID, partyID, messageID string, nameToFrostID map[string]uint16, seen map[seenKey]bool, s SessionFuncs) (finished bool, gotAny bool, err error) {
	msgs, err := client.GetMessages(ctx, sessionID, partyID, messageID)
	if err != nil {
		return false, false, fmt.Errorf("get messages: %w", err)
	}

	for _, m := range msgs {
		k := seenKey{m.From, m.SequenceNo}
		if seen[k] {
			continue
		}
		seen[k] = true

		body, err := client.DecryptAndVerify(m)
		if err != nil {
			return false, gotAny, fmt.Errorf("decrypt message from %s: %w", m.From, err)
		}

		payload, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			return false, gotAny, fmt.Errorf("base64 decode from %s: %w", m.From, err)
		}

		senderID, ok := nameToFrostID[m.From]
		if !ok {
			return false, gotAny, fmt.Errorf("unknown sender: %s", m.From)
		}

		frame := make([]byte, 2+len(payload))
		binary.LittleEndian.PutUint16(frame, senderID)
		copy(frame[2:], payload)

		done, err := s.Feed(frame)
		if err != nil {
			return false, gotAny, fmt.Errorf("feed from %s: %w", m.From, err)
		}
		gotAny = true

		if done {
			return true, true, nil
		}
	}
	return false, gotAny, nil
}

func buildNameToFrostID(parties []string) map[string]uint16 {
	sorted := make([]string, len(parties))
	copy(sorted, parties)
	sort.Strings(sorted)

	m := make(map[string]uint16, len(sorted))
	for i, name := range sorted {
		m[name] = uint16(i + 1)
	}
	return m
}
