package frozt

/*
#include "includes/frozt-lib.h"
*/
import "C"

import (
	"runtime"
)

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

// DKG Session

func DkgSetupMsgNew(maxSigners, minSigners uint16, parties []PartyInfo, birthday uint64) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	pd := encodeParties(parties)
	pdSlice := cGoSlice(pd, pinner)

	var out C.tss_buffer
	defer C.tss_buffer_free(&out)

	res := C.frozt_dkg_setupmsg_new(C.uint16_t(maxSigners), C.uint16_t(minSigners), pdSlice, C.uint64_t(birthday), &out)
	if res != 0 {
		return nil, mapLibError(int(res))
	}
	return copyBuffer(&out), nil
}

func DkgSessionFromSetup(setup []byte, myPartyName []byte) (SessionHandle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	setupSlice := cGoSlice(setup, pinner)
	nameSlice := cGoSlice(myPartyName, pinner)

	var handle C.Handle

	res := C.frozt_dkg_session_from_setup(setupSlice, nameSlice, &handle)
	if res != 0 {
		return 0, mapLibError(int(res))
	}
	return SessionHandle(handle._0), nil
}

func DkgSessionFeed(session SessionHandle, msg []byte) (bool, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	msgSlice := cGoSlice(msg, pinner)
	var finished C.int32_t

	res := C.frozt_dkg_session_feed(cHandle(Handle(session)), msgSlice, &finished)
	if res != 0 {
		return false, mapLibError(int(res))
	}
	return finished != 0, nil
}

func DkgSessionTakeMsg(session SessionHandle) ([]byte, error) {
	var out C.tss_buffer
	defer C.tss_buffer_free(&out)

	res := C.frozt_dkg_session_take_msg(cHandle(Handle(session)), &out)
	if res != 0 {
		return nil, mapLibError(int(res))
	}
	return copyBuffer(&out), nil
}

func DkgSessionMsgReceiver(session SessionHandle, msg []byte, index int) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	msgSlice := cGoSlice(msg, pinner)
	var out C.tss_buffer
	defer C.tss_buffer_free(&out)

	res := C.frozt_dkg_session_msg_receiver(cHandle(Handle(session)), msgSlice, C.uint32_t(index), &out)
	if res != 0 {
		return nil, mapLibError(int(res))
	}
	return copyBuffer(&out), nil
}

func DkgSessionResult(session SessionHandle) (bundle []byte, err error) {
	var out C.tss_buffer
	defer C.tss_buffer_free(&out)

	res := C.frozt_dkg_session_result(cHandle(Handle(session)), &out)
	if res != 0 {
		return nil, mapLibError(int(res))
	}
	return copyBuffer(&out), nil
}

func DkgSessionFree(session SessionHandle) error {
	res := C.frozt_dkg_session_free(cHandle(Handle(session)))
	if res != 0 {
		return mapLibError(int(res))
	}
	return nil
}

// Key Import Session

func KeyImportSetupMsgNew(maxSigners, minSigners uint16, parties []PartyInfo, birthday uint64, seedHolderID uint16, seed []byte, accountIndex uint32) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	pd := encodeParties(parties)
	pdSlice := cGoSlice(pd, pinner)
	seedSlice := cGoSlice(seed, pinner)

	var out C.tss_buffer
	defer C.tss_buffer_free(&out)

	res := C.frozt_key_import_setupmsg_new(C.uint16_t(maxSigners), C.uint16_t(minSigners), pdSlice, C.uint64_t(birthday), C.uint16_t(seedHolderID), seedSlice, C.uint32_t(accountIndex), &out)
	if res != 0 {
		return nil, mapLibError(int(res))
	}
	return copyBuffer(&out), nil
}

func KeyImportSessionFromSetup(setup []byte, myPartyName []byte) (SessionHandle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	setupSlice := cGoSlice(setup, pinner)
	nameSlice := cGoSlice(myPartyName, pinner)

	var handle C.Handle

	res := C.frozt_key_import_session_from_setup(setupSlice, nameSlice, &handle)
	if res != 0 {
		return 0, mapLibError(int(res))
	}
	return SessionHandle(handle._0), nil
}

func KeyImportSessionFeed(session SessionHandle, msg []byte) (bool, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	msgSlice := cGoSlice(msg, pinner)
	var finished C.int32_t

	res := C.frozt_key_import_session_feed(cHandle(Handle(session)), msgSlice, &finished)
	if res != 0 {
		return false, mapLibError(int(res))
	}
	return finished != 0, nil
}

func KeyImportSessionTakeMsg(session SessionHandle) ([]byte, error) {
	var out C.tss_buffer
	defer C.tss_buffer_free(&out)

	res := C.frozt_key_import_session_take_msg(cHandle(Handle(session)), &out)
	if res != 0 {
		return nil, mapLibError(int(res))
	}
	return copyBuffer(&out), nil
}

func KeyImportSessionMsgReceiver(session SessionHandle, msg []byte, index int) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	msgSlice := cGoSlice(msg, pinner)
	var out C.tss_buffer
	defer C.tss_buffer_free(&out)

	res := C.frozt_key_import_session_msg_receiver(cHandle(Handle(session)), msgSlice, C.uint32_t(index), &out)
	if res != 0 {
		return nil, mapLibError(int(res))
	}
	return copyBuffer(&out), nil
}

func KeyImportSessionResult(session SessionHandle) (bundle []byte, err error) {
	var out C.tss_buffer
	defer C.tss_buffer_free(&out)

	res := C.frozt_key_import_session_result(cHandle(Handle(session)), &out)
	if res != 0 {
		return nil, mapLibError(int(res))
	}
	return copyBuffer(&out), nil
}

func KeyImportSessionFree(session SessionHandle) error {
	res := C.frozt_key_import_session_free(cHandle(Handle(session)))
	if res != 0 {
		return mapLibError(int(res))
	}
	return nil
}

// Sign Session

func SignSetupMsgNew(msgToSign []byte, parties []PartyInfo) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	msgSlice := cGoSlice(msgToSign, pinner)
	pd := encodeParties(parties)
	pdSlice := cGoSlice(pd, pinner)

	var out C.tss_buffer
	defer C.tss_buffer_free(&out)

	res := C.frozt_sign_setupmsg_new(msgSlice, pdSlice, &out)
	if res != 0 {
		return nil, mapLibError(int(res))
	}
	return copyBuffer(&out), nil
}

func SignSessionFromSetup(setup, myPartyName, keyPackage, pubKeyPackage []byte) (SessionHandle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	setupSlice := cGoSlice(setup, pinner)
	nameSlice := cGoSlice(myPartyName, pinner)
	kpSlice := cGoSlice(keyPackage, pinner)
	pkpSlice := cGoSlice(pubKeyPackage, pinner)

	var handle C.Handle

	res := C.frozt_sign_session_from_setup(setupSlice, nameSlice, kpSlice, pkpSlice, &handle)
	if res != 0 {
		return 0, mapLibError(int(res))
	}
	return SessionHandle(handle._0), nil
}

func SignSessionFromSetupWithAlpha(setup, myPartyName, keyPackage, pubKeyPackage, alpha []byte) (SessionHandle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	setupSlice := cGoSlice(setup, pinner)
	nameSlice := cGoSlice(myPartyName, pinner)
	kpSlice := cGoSlice(keyPackage, pinner)
	pkpSlice := cGoSlice(pubKeyPackage, pinner)
	alphaSlice := cGoSlice(alpha, pinner)

	var handle C.Handle

	res := C.frozt_sign_session_from_setup_with_alpha(
		setupSlice,
		nameSlice,
		kpSlice,
		pkpSlice,
		alphaSlice,
		&handle,
	)
	if res != 0 {
		return 0, mapLibError(int(res))
	}
	return SessionHandle(handle._0), nil
}

func SignSessionFeed(session SessionHandle, msg []byte) (bool, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	msgSlice := cGoSlice(msg, pinner)
	var finished C.int32_t

	res := C.frozt_sign_session_feed(cHandle(Handle(session)), msgSlice, &finished)
	if res != 0 {
		return false, mapLibError(int(res))
	}
	return finished != 0, nil
}

func SignSessionTakeMsg(session SessionHandle) ([]byte, error) {
	var out C.tss_buffer
	defer C.tss_buffer_free(&out)

	res := C.frozt_sign_session_take_msg(cHandle(Handle(session)), &out)
	if res != 0 {
		return nil, mapLibError(int(res))
	}
	return copyBuffer(&out), nil
}

func SignSessionMsgReceiver(session SessionHandle, msg []byte, index int) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	msgSlice := cGoSlice(msg, pinner)
	var out C.tss_buffer
	defer C.tss_buffer_free(&out)

	res := C.frozt_sign_session_msg_receiver(cHandle(Handle(session)), msgSlice, C.uint32_t(index), &out)
	if res != 0 {
		return nil, mapLibError(int(res))
	}
	return copyBuffer(&out), nil
}

func SignSessionResult(session SessionHandle) ([]byte, error) {
	var out C.tss_buffer
	defer C.tss_buffer_free(&out)

	res := C.frozt_sign_session_result(cHandle(Handle(session)), &out)
	if res != 0 {
		return nil, mapLibError(int(res))
	}
	return copyBuffer(&out), nil
}

func SignSessionFree(session SessionHandle) error {
	res := C.frozt_sign_session_free(cHandle(Handle(session)))
	if res != 0 {
		return mapLibError(int(res))
	}
	return nil
}

// Reshare Session

func ReshareSetupMsgNew(maxSigners, minSigners uint16, parties []PartyInfo, oldIdentifiers []uint16, expectedVK []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	pd := encodeParties(parties)
	pdSlice := cGoSlice(pd, pinner)
	oi := encodeU16List(oldIdentifiers)
	oiSlice := cGoSlice(oi, pinner)
	vkSlice := cGoSlice(expectedVK, pinner)

	var out C.tss_buffer
	defer C.tss_buffer_free(&out)

	res := C.frozt_reshare_setupmsg_new(C.uint16_t(maxSigners), C.uint16_t(minSigners), pdSlice, oiSlice, vkSlice, &out)
	if res != 0 {
		return nil, mapLibError(int(res))
	}
	return copyBuffer(&out), nil
}

func ReshareSessionFromSetup(setup, myPartyName, oldKeyPackage []byte) (SessionHandle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	setupSlice := cGoSlice(setup, pinner)
	nameSlice := cGoSlice(myPartyName, pinner)
	okpSlice := cGoSlice(oldKeyPackage, pinner)

	var handle C.Handle

	res := C.frozt_reshare_session_from_setup(setupSlice, nameSlice, okpSlice, &handle)
	if res != 0 {
		return 0, mapLibError(int(res))
	}
	return SessionHandle(handle._0), nil
}

func ReshareSessionFeed(session SessionHandle, msg []byte) (bool, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	msgSlice := cGoSlice(msg, pinner)
	var finished C.int32_t

	res := C.frozt_reshare_session_feed(cHandle(Handle(session)), msgSlice, &finished)
	if res != 0 {
		return false, mapLibError(int(res))
	}
	return finished != 0, nil
}

func ReshareSessionTakeMsg(session SessionHandle) ([]byte, error) {
	var out C.tss_buffer
	defer C.tss_buffer_free(&out)

	res := C.frozt_reshare_session_take_msg(cHandle(Handle(session)), &out)
	if res != 0 {
		return nil, mapLibError(int(res))
	}
	return copyBuffer(&out), nil
}

func ReshareSessionMsgReceiver(session SessionHandle, msg []byte, index int) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	msgSlice := cGoSlice(msg, pinner)
	var out C.tss_buffer
	defer C.tss_buffer_free(&out)

	res := C.frozt_reshare_session_msg_receiver(cHandle(Handle(session)), msgSlice, C.uint32_t(index), &out)
	if res != 0 {
		return nil, mapLibError(int(res))
	}
	return copyBuffer(&out), nil
}

func ReshareSessionResult(session SessionHandle) (keyPackage []byte, pubKeyPackage []byte, err error) {
	var kpBuf C.tss_buffer
	var pkpBuf C.tss_buffer
	defer C.tss_buffer_free(&kpBuf)
	defer C.tss_buffer_free(&pkpBuf)

	res := C.frozt_reshare_session_result(cHandle(Handle(session)), &kpBuf, &pkpBuf)
	if res != 0 {
		return nil, nil, mapLibError(int(res))
	}
	return copyBuffer(&kpBuf), copyBuffer(&pkpBuf), nil
}

func ReshareSessionFree(session SessionHandle) error {
	res := C.frozt_reshare_session_free(cHandle(Handle(session)))
	if res != 0 {
		return mapLibError(int(res))
	}
	return nil
}
