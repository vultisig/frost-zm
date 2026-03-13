package fromt

/*
#cgo CFLAGS: -I${SRCDIR}/includes
#include "fromt-lib.h"
#include <stdlib.h>
*/
import "C"

import (
	"runtime"
	"unsafe"
)

type DkgSecretHandle struct {
	h C.Handle
}

func (h *DkgSecretHandle) Close() error {
	return toError(int(C.fromt_handle_free(h.h)))
}

type NoncesHandle struct {
	h C.Handle
}

func (h *NoncesHandle) Close() error {
	return toError(int(C.fromt_handle_free(h.h)))
}

type CkdStateHandle struct {
	h C.Handle
}

func (h *CkdStateHandle) Close() error {
	return toError(int(C.fromt_handle_free(h.h)))
}

func cGoSlice(data []byte) (C.go_slice, *runtime.Pinner) {
	var pinner runtime.Pinner
	if len(data) == 0 {
		return C.go_slice{}, &pinner
	}
	pinner.Pin(&data[0])
	return C.go_slice{
		ptr: (*C.uint8_t)(unsafe.Pointer(&data[0])),
		len: C.size_t(len(data)),
		cap: C.size_t(cap(data)),
	}, &pinner
}

func copyBuffer(buf *C.tss_buffer) []byte {
	if buf.ptr == nil || buf.len == 0 {
		return nil
	}
	out := C.GoBytes(unsafe.Pointer(buf.ptr), C.int(buf.len))
	C.tss_buffer_free(buf)
	return out
}

func HandleFree(h C.Handle) error {
	return toError(int(C.fromt_handle_free(h)))
}

func DkgPart1(id, maxSigners, minSigners uint16) (*DkgSecretHandle, []byte, error) {
	var secret C.Handle
	var pkg C.tss_buffer
	rc := C.fromt_dkg_part1(C.uint16_t(id), C.uint16_t(maxSigners), C.uint16_t(minSigners), &secret, &pkg)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return &DkgSecretHandle{h: secret}, copyBuffer(&pkg), nil
}

func DkgPart2(secret *DkgSecretHandle, round1Packages []byte) (*DkgSecretHandle, []byte, error) {
	r1, pinner := cGoSlice(round1Packages)
	defer pinner.Unpin()
	var secret2 C.Handle
	var pkgs C.tss_buffer
	rc := C.fromt_dkg_part2(secret.h, &r1, &secret2, &pkgs)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return &DkgSecretHandle{h: secret2}, copyBuffer(&pkgs), nil
}

func DkgPart3(secret *DkgSecretHandle, round1Packages, round2Packages []byte, network uint8, birthday uint64) ([]byte, []byte, error) {
	r1, p1 := cGoSlice(round1Packages)
	defer p1.Unpin()
	r2, p2 := cGoSlice(round2Packages)
	defer p2.Unpin()
	var keyShare C.tss_buffer
	var pubKey C.tss_buffer
	rc := C.fromt_dkg_part3(secret.h, &r1, &r2, C.uint8_t(network), C.uint64_t(birthday), &keyShare, &pubKey)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return copyBuffer(&keyShare), copyBuffer(&pubKey), nil
}

func KeyImportPart1(id, maxSigners, minSigners uint16, spendKey []byte) (*DkgSecretHandle, []byte, error) {
	var skSlice *C.go_slice
	var sk C.go_slice
	var pinner *runtime.Pinner
	if len(spendKey) > 0 {
		sk, pinner = cGoSlice(spendKey)
		defer pinner.Unpin()
		skSlice = &sk
	}
	var secret C.Handle
	var pkg C.tss_buffer
	rc := C.fromt_key_import_part1(C.uint16_t(id), C.uint16_t(maxSigners), C.uint16_t(minSigners), skSlice, &secret, &pkg)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return &DkgSecretHandle{h: secret}, copyBuffer(&pkg), nil
}

func KeyImportPart3(secret *DkgSecretHandle, round1Packages, round2Packages, expectedVK []byte, network uint8, birthday uint64) ([]byte, []byte, error) {
	r1, p1 := cGoSlice(round1Packages)
	defer p1.Unpin()
	r2, p2 := cGoSlice(round2Packages)
	defer p2.Unpin()
	vk, p3 := cGoSlice(expectedVK)
	defer p3.Unpin()
	var keyShare C.tss_buffer
	var pubKey C.tss_buffer
	rc := C.fromt_key_import_part3(secret.h, &r1, &r2, &vk, C.uint8_t(network), C.uint64_t(birthday), &keyShare, &pubKey)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return copyBuffer(&keyShare), copyBuffer(&pubKey), nil
}

func DeriveKeysFromSeed(seed []byte) ([]byte, []byte, error) {
	s, p := cGoSlice(seed)
	defer p.Unpin()
	var sk C.tss_buffer
	var vk C.tss_buffer
	rc := C.fromt_derive_keys_from_seed(&s, &sk, &vk)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return copyBuffer(&sk), copyBuffer(&vk), nil
}

func SpendKeyToPublic(spendKey []byte) ([]byte, error) {
	sk, p := cGoSlice(spendKey)
	defer p.Unpin()
	var pk C.tss_buffer
	rc := C.fromt_spend_key_to_public(&sk, &pk)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&pk), nil
}

func SignCommit(keyShare []byte) (*NoncesHandle, []byte, error) {
	ks, p := cGoSlice(keyShare)
	defer p.Unpin()
	var nonces C.Handle
	var commitments C.tss_buffer
	rc := C.fromt_sign_commit(&ks, &nonces, &commitments)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return &NoncesHandle{h: nonces}, copyBuffer(&commitments), nil
}

func SignCreatePackage(message, commitmentsMap []byte) ([]byte, error) {
	msg, p1 := cGoSlice(message)
	defer p1.Unpin()
	cm, p2 := cGoSlice(commitmentsMap)
	defer p2.Unpin()
	var sp C.tss_buffer
	rc := C.fromt_sign_create_package(&msg, &cm, &sp)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&sp), nil
}

func Sign(signingPackage []byte, nonces *NoncesHandle, keyShare []byte) ([]byte, error) {
	sp, p1 := cGoSlice(signingPackage)
	defer p1.Unpin()
	ks, p2 := cGoSlice(keyShare)
	defer p2.Unpin()
	var share C.tss_buffer
	rc := C.fromt_sign(&sp, nonces.h, &ks, &share)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&share), nil
}

func SignAggregate(signingPackage, sharesMap, keyShare []byte) ([]byte, error) {
	sp, p1 := cGoSlice(signingPackage)
	defer p1.Unpin()
	sm, p2 := cGoSlice(sharesMap)
	defer p2.Unpin()
	ks, p3 := cGoSlice(keyShare)
	defer p3.Unpin()
	var sig C.tss_buffer
	rc := C.fromt_sign_aggregate(&sp, &sm, &ks, &sig)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&sig), nil
}

func VerifySignature(message, signature, keyShare []byte) error {
	msg, p1 := cGoSlice(message)
	defer p1.Unpin()
	sig, p2 := cGoSlice(signature)
	defer p2.Unpin()
	ks, p3 := cGoSlice(keyShare)
	defer p3.Unpin()

	rc := C.fromt_verify_signature(&msg, &sig, &ks)
	return toError(int(rc))
}

func ResharePart1(id, maxSigners, minSigners uint16, oldKeyShare, oldIdentifiers []byte) (*DkgSecretHandle, []byte, error) {
	var oksSlice *C.go_slice
	var oidsSlice *C.go_slice
	var oks C.go_slice
	var oids C.go_slice
	var p1, p2 *runtime.Pinner
	if len(oldKeyShare) > 0 {
		oks, p1 = cGoSlice(oldKeyShare)
		defer p1.Unpin()
		oksSlice = &oks
	}
	if len(oldIdentifiers) > 0 {
		oids, p2 = cGoSlice(oldIdentifiers)
		defer p2.Unpin()
		oidsSlice = &oids
	}
	var secret C.Handle
	var pkg C.tss_buffer
	rc := C.fromt_reshare_part1(C.uint16_t(id), C.uint16_t(maxSigners), C.uint16_t(minSigners), oksSlice, oidsSlice, &secret, &pkg)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return &DkgSecretHandle{h: secret}, copyBuffer(&pkg), nil
}

func ResharePart3(secret *DkgSecretHandle, round1Packages, round2Packages, expectedVK []byte, network uint8, birthday uint64) ([]byte, []byte, error) {
	r1, p1 := cGoSlice(round1Packages)
	defer p1.Unpin()
	r2, p2 := cGoSlice(round2Packages)
	defer p2.Unpin()
	vk, p3 := cGoSlice(expectedVK)
	defer p3.Unpin()
	var keyShare C.tss_buffer
	var pubKey C.tss_buffer
	rc := C.fromt_reshare_part3(secret.h, &r1, &r2, &vk, C.uint8_t(network), C.uint64_t(birthday), &keyShare, &pubKey)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return copyBuffer(&keyShare), copyBuffer(&pubKey), nil
}

func CkdPart1(keyShare []byte, account, index uint32, signerIDs []byte) (*CkdStateHandle, []byte, error) {
	ks, p1 := cGoSlice(keyShare)
	defer p1.Unpin()
	ids, p2 := cGoSlice(signerIDs)
	defer p2.Unpin()
	var state C.Handle
	var pkg C.tss_buffer
	rc := C.fromt_ckd_part1(&ks, C.uint32_t(account), C.uint32_t(index), &ids, &state, &pkg)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return &CkdStateHandle{h: state}, copyBuffer(&pkg), nil
}

func CkdPart2(state *CkdStateHandle, r1Packages []byte) ([]byte, error) {
	r1, p := cGoSlice(r1Packages)
	defer p.Unpin()
	var child C.tss_buffer
	rc := C.fromt_ckd_part2(state.h, &r1, &child)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&child), nil
}

type KeyImageStateHandle struct {
	h C.Handle
}

func (h *KeyImageStateHandle) Close() error {
	return toError(int(C.fromt_handle_free(h.h)))
}

func KeyImagePart1(keyShare, outputs, signerIDs []byte) (*KeyImageStateHandle, []byte, error) {
	ks, p1 := cGoSlice(keyShare)
	defer p1.Unpin()
	out, p2 := cGoSlice(outputs)
	defer p2.Unpin()
	ids, p3 := cGoSlice(signerIDs)
	defer p3.Unpin()
	var state C.Handle
	var partials C.tss_buffer
	rc := C.fromt_key_image_part1(&ks, &out, &ids, &state, &partials)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return &KeyImageStateHandle{h: state}, copyBuffer(&partials), nil
}

func KeyImagePart2(state *KeyImageStateHandle, r1Packages []byte) ([]byte, error) {
	r1, p := cGoSlice(r1Packages)
	defer p.Unpin()
	var keyImages C.tss_buffer
	rc := C.fromt_key_image_part2(state.h, &r1, &keyImages)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&keyImages), nil
}

func DeriveAddress(keyShare []byte) (string, error) {
	ks, p := cGoSlice(keyShare)
	defer p.Unpin()
	var addr C.tss_buffer
	rc := C.fromt_derive_address(&ks, &addr)
	err := toError(int(rc))
	if err != nil {
		return "", err
	}
	return string(copyBuffer(&addr)), nil
}

func DeriveSubaddress(keyShare []byte, account, index uint32) (string, error) {
	ks, p := cGoSlice(keyShare)
	defer p.Unpin()
	var addr C.tss_buffer
	rc := C.fromt_derive_subaddress(&ks, C.uint32_t(account), C.uint32_t(index), &addr)
	err := toError(int(rc))
	if err != nil {
		return "", err
	}
	return string(copyBuffer(&addr)), nil
}

func KeySharePublicKey(keyShare []byte) ([]byte, error) {
	ks, p := cGoSlice(keyShare)
	defer p.Unpin()
	var pk C.tss_buffer
	rc := C.fromt_keyshare_public_key(&ks, &pk)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&pk), nil
}

func KeyShareViewKey(keyShare []byte) ([]byte, error) {
	ks, p := cGoSlice(keyShare)
	defer p.Unpin()
	var vk C.tss_buffer
	rc := C.fromt_keyshare_view_key(&ks, &vk)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&vk), nil
}

func KeyShareBirthday(keyShare []byte) (uint64, error) {
	ks, p := cGoSlice(keyShare)
	defer p.Unpin()
	var birthday C.uint64_t
	rc := C.fromt_keyshare_birthday(&ks, &birthday)
	err := toError(int(rc))
	if err != nil {
		return 0, err
	}
	return uint64(birthday), nil
}

func KeyShareIdentifier(keyShare []byte) (uint16, error) {
	ks, p := cGoSlice(keyShare)
	defer p.Unpin()
	var id C.uint16_t
	rc := C.fromt_keyshare_identifier(&ks, &id)
	err := toError(int(rc))
	if err != nil {
		return 0, err
	}
	return uint16(id), nil
}

func EncodeIdentifier(id uint16) ([]byte, error) {
	var buf C.tss_buffer
	rc := C.fromt_encode_identifier(C.uint16_t(id), &buf)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&buf), nil
}

type SpendSignHandle struct {
	h C.Handle
}

func (h *SpendSignHandle) Close() error {
	return toError(int(C.fromt_handle_free(h.h)))
}

type SpendSigHandle struct {
	h C.Handle
}

func (h *SpendSigHandle) Close() error {
	return toError(int(C.fromt_handle_free(h.h)))
}


func SpendPreprocess(keyShare, signableTx []byte) (*SpendSignHandle, []byte, error) {
	ks, p1 := cGoSlice(keyShare)
	defer p1.Unpin()
	st, p2 := cGoSlice(signableTx)
	defer p2.Unpin()
	var handle C.Handle
	var preprocess C.tss_buffer
	rc := C.fromt_spend_preprocess(&ks, &st, &handle, &preprocess)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return &SpendSignHandle{h: handle}, copyBuffer(&preprocess), nil
}

func SpendSign(handle *SpendSignHandle, preprocessesMap []byte) (*SpendSigHandle, []byte, error) {
	pp, p1 := cGoSlice(preprocessesMap)
	defer p1.Unpin()
	var newHandle C.Handle
	var share C.tss_buffer
	rc := C.fromt_spend_sign(handle.h, &pp, &newHandle, &share)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return &SpendSigHandle{h: newHandle}, copyBuffer(&share), nil
}

func SpendComplete(handle *SpendSigHandle, sharesMap []byte) ([]byte, error) {
	sm, p1 := cGoSlice(sharesMap)
	defer p1.Unpin()
	var rawTx C.tss_buffer
	rc := C.fromt_spend_complete(handle.h, &sm, &rawTx)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&rawTx), nil
}

func DecodeIdentifier(idBytes []byte) (uint16, error) {
	s, p := cGoSlice(idBytes)
	defer p.Unpin()
	var id C.uint16_t
	rc := C.fromt_decode_identifier(&s, &id)
	err := toError(int(rc))
	if err != nil {
		return 0, err
	}
	return uint16(id), nil
}
