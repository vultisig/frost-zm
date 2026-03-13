package fromt

/*
#include "includes/fromt-lib.h"
*/
import "C"

type SessionHandle struct {
	h C.Handle
}

func (h *SessionHandle) Close() error {
	return toError(int(C.fromt_handle_free(h.h)))
}

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

// DKG Session

func DkgSetupMsgNew(maxSigners, minSigners uint16, parties []PartyInfo, network uint8, birthday uint64) ([]byte, error) {
	pd := encodeParties(parties)
	pdSlice, p := cGoSlice(pd)
	defer p.Unpin()

	var out C.tss_buffer

	rc := C.fromt_dkg_setupmsg_new(C.uint16_t(maxSigners), C.uint16_t(minSigners), &pdSlice, C.uint8_t(network), C.uint64_t(birthday), &out)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
}

func DkgSessionFromSetup(setup []byte, myPartyName []byte) (*SessionHandle, error) {
	setupSlice, p1 := cGoSlice(setup)
	defer p1.Unpin()
	nameSlice, p2 := cGoSlice(myPartyName)
	defer p2.Unpin()

	var handle C.Handle

	rc := C.fromt_dkg_session_from_setup(&setupSlice, &nameSlice, &handle)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return &SessionHandle{h: handle}, nil
}

func DkgSessionFeed(session *SessionHandle, msg []byte) (bool, error) {
	msgSlice, p := cGoSlice(msg)
	defer p.Unpin()
	var finished C.int32_t

	rc := C.fromt_dkg_session_feed(session.h, &msgSlice, &finished)
	err := toError(int(rc))
	if err != nil {
		return false, err
	}
	return finished != 0, nil
}

func DkgSessionTakeMsg(session *SessionHandle) ([]byte, error) {
	var out C.tss_buffer

	rc := C.fromt_dkg_session_take_msg(session.h, &out)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
}

func DkgSessionMsgReceiver(session *SessionHandle, msg []byte, index int) ([]byte, error) {
	msgSlice, p := cGoSlice(msg)
	defer p.Unpin()
	var out C.tss_buffer

	rc := C.fromt_dkg_session_msg_receiver(session.h, &msgSlice, C.uint32_t(index), &out)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
}

func DkgSessionResult(session *SessionHandle) (bundle []byte, err error) {
	var out C.tss_buffer

	rc := C.fromt_dkg_session_result(session.h, &out)
	err = toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
}

func DkgSessionFree(session *SessionHandle) error {
	return toError(int(C.fromt_dkg_session_free(session.h)))
}

// Key Import Session

func KeyImportSetupMsgNew(maxSigners, minSigners uint16, parties []PartyInfo, network uint8, birthday uint64, seedHolderID uint16, spendKey []byte) ([]byte, error) {
	pd := encodeParties(parties)
	pdSlice, p1 := cGoSlice(pd)
	defer p1.Unpin()
	skSlice, p2 := cGoSlice(spendKey)
	defer p2.Unpin()

	var out C.tss_buffer

	rc := C.fromt_key_import_setupmsg_new(C.uint16_t(maxSigners), C.uint16_t(minSigners), &pdSlice, C.uint8_t(network), C.uint64_t(birthday), C.uint16_t(seedHolderID), &skSlice, &out)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
}

func KeyImportSessionFromSetup(setup []byte, myPartyName []byte) (*SessionHandle, error) {
	setupSlice, p1 := cGoSlice(setup)
	defer p1.Unpin()
	nameSlice, p2 := cGoSlice(myPartyName)
	defer p2.Unpin()

	var handle C.Handle

	rc := C.fromt_key_import_session_from_setup(&setupSlice, &nameSlice, &handle)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return &SessionHandle{h: handle}, nil
}

func KeyImportSessionFeed(session *SessionHandle, msg []byte) (bool, error) {
	msgSlice, p := cGoSlice(msg)
	defer p.Unpin()
	var finished C.int32_t

	rc := C.fromt_key_import_session_feed(session.h, &msgSlice, &finished)
	err := toError(int(rc))
	if err != nil {
		return false, err
	}
	return finished != 0, nil
}

func KeyImportSessionTakeMsg(session *SessionHandle) ([]byte, error) {
	var out C.tss_buffer

	rc := C.fromt_key_import_session_take_msg(session.h, &out)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
}

func KeyImportSessionMsgReceiver(session *SessionHandle, msg []byte, index int) ([]byte, error) {
	msgSlice, p := cGoSlice(msg)
	defer p.Unpin()
	var out C.tss_buffer

	rc := C.fromt_key_import_session_msg_receiver(session.h, &msgSlice, C.uint32_t(index), &out)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
}

func KeyImportSessionResult(session *SessionHandle) (bundle []byte, err error) {
	var out C.tss_buffer

	rc := C.fromt_key_import_session_result(session.h, &out)
	err = toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
}

func KeyImportSessionFree(session *SessionHandle) error {
	return toError(int(C.fromt_key_import_session_free(session.h)))
}

// Sign Session

func SignSetupMsgNew(msgToSign []byte, parties []PartyInfo) ([]byte, error) {
	msgSlice, p1 := cGoSlice(msgToSign)
	defer p1.Unpin()
	pd := encodeParties(parties)
	pdSlice, p2 := cGoSlice(pd)
	defer p2.Unpin()

	var out C.tss_buffer

	rc := C.fromt_sign_setupmsg_new(&msgSlice, &pdSlice, &out)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
}

func SignSessionFromSetup(setup, myPartyName, keyPackage, pubKeyPackage []byte) (*SessionHandle, error) {
	setupSlice, p1 := cGoSlice(setup)
	defer p1.Unpin()
	nameSlice, p2 := cGoSlice(myPartyName)
	defer p2.Unpin()
	kpSlice, p3 := cGoSlice(keyPackage)
	defer p3.Unpin()
	pkpSlice, p4 := cGoSlice(pubKeyPackage)
	defer p4.Unpin()

	var handle C.Handle

	rc := C.fromt_sign_session_from_setup(&setupSlice, &nameSlice, &kpSlice, &pkpSlice, &handle)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return &SessionHandle{h: handle}, nil
}

func SignSessionFeed(session *SessionHandle, msg []byte) (bool, error) {
	msgSlice, p := cGoSlice(msg)
	defer p.Unpin()
	var finished C.int32_t

	rc := C.fromt_sign_session_feed(session.h, &msgSlice, &finished)
	err := toError(int(rc))
	if err != nil {
		return false, err
	}
	return finished != 0, nil
}

func SignSessionTakeMsg(session *SessionHandle) ([]byte, error) {
	var out C.tss_buffer

	rc := C.fromt_sign_session_take_msg(session.h, &out)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
}

func SignSessionMsgReceiver(session *SessionHandle, msg []byte, index int) ([]byte, error) {
	msgSlice, p := cGoSlice(msg)
	defer p.Unpin()
	var out C.tss_buffer

	rc := C.fromt_sign_session_msg_receiver(session.h, &msgSlice, C.uint32_t(index), &out)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
}

func SignSessionResult(session *SessionHandle) ([]byte, error) {
	var out C.tss_buffer

	rc := C.fromt_sign_session_result(session.h, &out)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
}

func SignSessionFree(session *SessionHandle) error {
	return toError(int(C.fromt_sign_session_free(session.h)))
}

// Reshare Session

func ReshareSetupMsgNew(maxSigners, minSigners uint16, parties []PartyInfo, oldIdentifiers []uint16, expectedVK []byte) ([]byte, error) {
	pd := encodeParties(parties)
	pdSlice, p1 := cGoSlice(pd)
	defer p1.Unpin()
	oi := encodeU16List(oldIdentifiers)
	oiSlice, p2 := cGoSlice(oi)
	defer p2.Unpin()
	vkSlice, p3 := cGoSlice(expectedVK)
	defer p3.Unpin()

	var out C.tss_buffer

	rc := C.fromt_reshare_setupmsg_new(C.uint16_t(maxSigners), C.uint16_t(minSigners), &pdSlice, &oiSlice, &vkSlice, &out)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
}

func ReshareSessionFromSetup(setup, myPartyName, oldKeyPackage []byte) (*SessionHandle, error) {
	setupSlice, p1 := cGoSlice(setup)
	defer p1.Unpin()
	nameSlice, p2 := cGoSlice(myPartyName)
	defer p2.Unpin()
	okpSlice, p3 := cGoSlice(oldKeyPackage)
	defer p3.Unpin()

	var handle C.Handle

	rc := C.fromt_reshare_session_from_setup(&setupSlice, &nameSlice, &okpSlice, &handle)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return &SessionHandle{h: handle}, nil
}

func ReshareSessionFeed(session *SessionHandle, msg []byte) (bool, error) {
	msgSlice, p := cGoSlice(msg)
	defer p.Unpin()
	var finished C.int32_t

	rc := C.fromt_reshare_session_feed(session.h, &msgSlice, &finished)
	err := toError(int(rc))
	if err != nil {
		return false, err
	}
	return finished != 0, nil
}

func ReshareSessionTakeMsg(session *SessionHandle) ([]byte, error) {
	var out C.tss_buffer

	rc := C.fromt_reshare_session_take_msg(session.h, &out)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
}

func ReshareSessionMsgReceiver(session *SessionHandle, msg []byte, index int) ([]byte, error) {
	msgSlice, p := cGoSlice(msg)
	defer p.Unpin()
	var out C.tss_buffer

	rc := C.fromt_reshare_session_msg_receiver(session.h, &msgSlice, C.uint32_t(index), &out)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
}

func ReshareSessionResult(session *SessionHandle) (keyPackage []byte, pubKeyPackage []byte, err error) {
	var kpBuf C.tss_buffer
	var pkpBuf C.tss_buffer

	rc := C.fromt_reshare_session_result(session.h, &kpBuf, &pkpBuf)
	err = toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return copyBuffer(&kpBuf), copyBuffer(&pkpBuf), nil
}

func ReshareSessionFree(session *SessionHandle) error {
	return toError(int(C.fromt_reshare_session_free(session.h)))
}

// Key Image Session

func KeyImageSetupMsgNew(parties []PartyInfo, outputs []byte) ([]byte, error) {
	pd := encodeParties(parties)
	pdSlice, p1 := cGoSlice(pd)
	defer p1.Unpin()
	outSlice, p2 := cGoSlice(outputs)
	defer p2.Unpin()

	var out C.tss_buffer

	rc := C.fromt_key_image_setupmsg_new(&pdSlice, &outSlice, &out)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
}

func KeyImageSessionFromSetup(setup, myPartyName, keyShare []byte) (*SessionHandle, error) {
	setupSlice, p1 := cGoSlice(setup)
	defer p1.Unpin()
	nameSlice, p2 := cGoSlice(myPartyName)
	defer p2.Unpin()
	ksSlice, p3 := cGoSlice(keyShare)
	defer p3.Unpin()

	var handle C.Handle

	rc := C.fromt_key_image_session_from_setup(&setupSlice, &nameSlice, &ksSlice, &handle)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return &SessionHandle{h: handle}, nil
}

func KeyImageSessionFeed(session *SessionHandle, msg []byte) (bool, error) {
	msgSlice, p := cGoSlice(msg)
	defer p.Unpin()
	var finished C.int32_t

	rc := C.fromt_key_image_session_feed(session.h, &msgSlice, &finished)
	err := toError(int(rc))
	if err != nil {
		return false, err
	}
	return finished != 0, nil
}

func KeyImageSessionTakeMsg(session *SessionHandle) ([]byte, error) {
	var out C.tss_buffer

	rc := C.fromt_key_image_session_take_msg(session.h, &out)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
}

func KeyImageSessionMsgReceiver(session *SessionHandle, msg []byte, index int) ([]byte, error) {
	msgSlice, p := cGoSlice(msg)
	defer p.Unpin()
	var out C.tss_buffer

	rc := C.fromt_key_image_session_msg_receiver(session.h, &msgSlice, C.uint32_t(index), &out)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
}

func KeyImageSessionResult(session *SessionHandle) ([]byte, error) {
	var out C.tss_buffer

	rc := C.fromt_key_image_session_result(session.h, &out)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
}

func KeyImageSessionFree(session *SessionHandle) error {
	return toError(int(C.fromt_key_image_session_free(session.h)))
}
