package orchestration

import (
	"context"
	"fmt"

	fromt "github.com/vultisig/frosty-lib/go/fromt"
	"github.com/vultisig/frosty-lib/client/shared/relay"
	"github.com/vultisig/frosty-lib/client/shared/session"
)

type ReshareResult struct {
	KeyShare []byte
	PubKey   []byte
}

func RunReshare(
	ctx context.Context,
	client *relay.RelayClient,
	sessionID, partyID string,
	maxSigners, minSigners uint16,
	oldKeyShare []byte,
	oldIdentifiers []uint16,
	expectedVK []byte,
	allParties []string,
) (*ReshareResult, *CeremonyResult, error) {
	parties := BuildPartyInfo(allParties)

	setupBytes, err := fromt.ReshareSetupMsgNew(maxSigners, minSigners, parties, oldIdentifiers, expectedVK)
	if err != nil {
		return nil, nil, fmt.Errorf("reshare setup: %w", err)
	}

	sess, err := fromt.ReshareSessionFromSetup(setupBytes, []byte(partyID), oldKeyShare)
	if err != nil {
		return nil, nil, fmt.Errorf("reshare session: %w", err)
	}
	defer fromt.ReshareSessionFree(sess)

	err = session.RunSession(ctx, client, sessionID, partyID, allParties, session.SessionFuncs{
		TakeMsg:     func() ([]byte, error) { return fromt.ReshareSessionTakeMsg(sess) },
		Feed:        func(msg []byte) (bool, error) { return fromt.ReshareSessionFeed(sess, msg) },
		MsgReceiver: func(msg []byte, i int) ([]byte, error) { return fromt.ReshareSessionMsgReceiver(sess, msg, i) },
	})
	if err != nil {
		blame := handleBlame(ctx, client, sessionID, partyID, allParties, err)
		return nil, blame, fmt.Errorf("reshare session run: %w", err)
	}

	kp, pk, err := fromt.ReshareSessionResult(sess)
	if err != nil {
		return nil, nil, fmt.Errorf("reshare result: %w", err)
	}

	return &ReshareResult{
		KeyShare: kp,
		PubKey:   pk,
	}, nil, nil
}
