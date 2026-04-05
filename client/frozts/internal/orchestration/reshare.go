package orchestration

import (
	"context"
	"fmt"

	frozts "github.com/vultisig/frosty-lib/go/frozts"
	"github.com/vultisig/frosty-lib/client/shared/relay"
	"github.com/vultisig/frosty-lib/client/shared/session"
)

type ReshareResult struct {
	KeyPackage    []byte
	PubKeyPackage []byte
}

func RunReshare(
	ctx context.Context,
	client *relay.RelayClient,
	sessionID, partyID string,
	maxSigners, minSigners uint16,
	oldKeyPackage []byte,
	oldIdentifiers []uint16,
	expectedVerifyingKey []byte,
	allParties []string,
) (*ReshareResult, *CeremonyResult, error) {
	parties := BuildPartyInfo(allParties)

	setupBytes, err := frozts.ReshareSetupMsgNew(maxSigners, minSigners, parties, oldIdentifiers, expectedVerifyingKey)
	if err != nil {
		return nil, nil, fmt.Errorf("reshare setup: %w", err)
	}

	sess, err := frozts.ReshareSessionFromSetup(setupBytes, []byte(partyID), oldKeyPackage)
	if err != nil {
		return nil, nil, fmt.Errorf("reshare session: %w", err)
	}
	defer frozts.ReshareSessionFree(sess)

	err = session.RunSession(ctx, client, sessionID, partyID, allParties, session.SessionFuncs{
		TakeMsg:     func() ([]byte, error) { return frozts.ReshareSessionTakeMsg(sess) },
		Feed:        func(msg []byte) (bool, error) { return frozts.ReshareSessionFeed(sess, msg) },
		MsgReceiver: func(msg []byte, i int) ([]byte, error) { return frozts.ReshareSessionMsgReceiver(sess, msg, i) },
	})
	if err != nil {
		blame := handleBlame(client, sessionID, partyID, allParties, err)
		return nil, blame, fmt.Errorf("reshare session run: %w", err)
	}

	kp, pkp, err := frozts.ReshareSessionResult(sess)
	if err != nil {
		return nil, nil, fmt.Errorf("reshare result: %w", err)
	}

	return &ReshareResult{
		KeyPackage:    kp,
		PubKeyPackage: pkp,
	}, nil, nil
}
