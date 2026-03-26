package froeth

// Session-based async ceremony wrappers for froeth (Ethereum).
// TODO: The Rust session FFI (froeth-lib/src/session.rs) is not yet implemented.
// Once implemented, add the following session functions here:
//
// DKG Session:
//   - DkgSetupMsgNew(maxSigners, minSigners uint16, parties []PartyInfo, birthday uint64) ([]byte, error)
//   - DkgSessionFromSetup(setup, myPartyName []byte) (SessionHandle, error)
//   - DkgSessionFeed(session SessionHandle, msg []byte) (bool, error)
//   - DkgSessionTakeMsg(session SessionHandle) ([]byte, error)
//   - DkgSessionMsgReceiver(session SessionHandle, msg []byte, index int) ([]byte, error)
//   - DkgSessionResult(session SessionHandle) ([]byte, error)
//   - DkgSessionFree(session SessionHandle) error
//
// Key Import Session:
//   - KeyImportSetupMsgNew(maxSigners, minSigners uint16, parties []PartyInfo, birthday uint64, seedHolderID uint16, seed []byte, accountIndex uint32) ([]byte, error)
//   - KeyImportSessionFromSetup(setup, myPartyName []byte) (SessionHandle, error)
//   - KeyImportSessionFeed(session SessionHandle, msg []byte) (bool, error)
//   - KeyImportSessionTakeMsg(session SessionHandle) ([]byte, error)
//   - KeyImportSessionMsgReceiver(session SessionHandle, msg []byte, index int) ([]byte, error)
//   - KeyImportSessionResult(session SessionHandle) ([]byte, error)
//   - KeyImportSessionFree(session SessionHandle) error
//
// Sign Session:
//   - SignSetupMsgNew(msgToSign []byte, parties []PartyInfo) ([]byte, error)
//   - SignSessionFromSetup(setup, myPartyName, keyShare []byte) (SessionHandle, error)
//   - SignSessionFeed(session SessionHandle, msg []byte) (bool, error)
//   - SignSessionTakeMsg(session SessionHandle) ([]byte, error)
//   - SignSessionMsgReceiver(session SessionHandle, msg []byte, index int) ([]byte, error)
//   - SignSessionResult(session SessionHandle) ([]byte, error)
//   - SignSessionFree(session SessionHandle) error
//
// Reshare Session:
//   - ReshareSetupMsgNew(maxSigners, minSigners uint16, parties []PartyInfo, oldIdentifiers []uint16, expectedVK []byte) ([]byte, error)
//   - ReshareSessionFromSetup(setup, myPartyName, oldKeyShare []byte) (SessionHandle, error)
//   - ReshareSessionFeed(session SessionHandle, msg []byte) (bool, error)
//   - ReshareSessionTakeMsg(session SessionHandle) ([]byte, error)
//   - ReshareSessionMsgReceiver(session SessionHandle, msg []byte, index int) ([]byte, error)
//   - ReshareSessionResult(session SessionHandle) (keyShare []byte, pubKey []byte, err error)
//   - ReshareSessionFree(session SessionHandle) error

type SessionHandle Handle

func (h SessionHandle) Close() error { return HandleFree(Handle(h)) }

type PartyInfo struct {
	FrostID uint16
	Name    []byte
}

func encodeParties(parties []PartyInfo) []byte {
	size := 2
	for _, p := range parties {
		size += 4 + len(p.Name)
	}
	buf := make([]byte, 0, size)
	n := uint16(len(parties))
	buf = append(buf, byte(n), byte(n>>8))
	for _, p := range parties {
		buf = append(buf, byte(p.FrostID), byte(p.FrostID>>8))
		nl := uint16(len(p.Name))
		buf = append(buf, byte(nl), byte(nl>>8))
		buf = append(buf, p.Name...)
	}
	return buf
}

func encodeU16List(ids []uint16) []byte {
	buf := make([]byte, 2+len(ids)*2)
	n := uint16(len(ids))
	buf[0] = byte(n)
	buf[1] = byte(n >> 8)
	for i, id := range ids {
		buf[2+i*2] = byte(id)
		buf[2+i*2+1] = byte(id >> 8)
	}
	return buf
}
