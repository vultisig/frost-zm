package frosst

/*
#cgo CFLAGS: -I${SRCDIR}/includes
#include "frosst-lib.h"
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
	return toError(int(C.frosst_handle_free(h.h)))
}

type NoncesHandle struct {
	h C.Handle
}

func (h *NoncesHandle) Close() error {
	return toError(int(C.frosst_handle_free(h.h)))
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

// DKG

func DkgPart1(id, maxSigners, minSigners uint16) (*DkgSecretHandle, []byte, error) {
	var secret C.Handle
	var pkg C.tss_buffer
	rc := C.frosst_dkg_part1(C.uint16_t(id), C.uint16_t(maxSigners), C.uint16_t(minSigners), &secret, &pkg)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return &DkgSecretHandle{h: secret}, copyBuffer(&pkg), nil
}

func DkgPart2(secret *DkgSecretHandle, round1Packages []byte) (*DkgSecretHandle, []byte, error) {
	r1, p1 := cGoSlice(round1Packages)
	defer p1.Unpin()
	var secret2 C.Handle
	var pkgs C.tss_buffer
	rc := C.frosst_dkg_part2(secret.h, &r1, &secret2, &pkgs)
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
	rc := C.frosst_dkg_part3(secret.h, &r1, &r2, C.uint8_t(network), C.uint64_t(birthday), &keyShare, &pubKey)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return copyBuffer(&keyShare), copyBuffer(&pubKey), nil
}

// Signing

func SignCommit(keyShare []byte) (*NoncesHandle, []byte, error) {
	ks, p1 := cGoSlice(keyShare)
	defer p1.Unpin()
	var nonces C.Handle
	var commitments C.tss_buffer
	rc := C.frosst_sign_commit(&ks, &nonces, &commitments)
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
	var pkg C.tss_buffer
	rc := C.frosst_sign_create_package(&msg, &cm, &pkg)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&pkg), nil
}

func Sign(signingPackage []byte, nonces *NoncesHandle, keyShare []byte) ([]byte, error) {
	sp, p1 := cGoSlice(signingPackage)
	defer p1.Unpin()
	ks, p2 := cGoSlice(keyShare)
	defer p2.Unpin()
	var share C.tss_buffer
	rc := C.frosst_sign(&sp, nonces.h, &ks, &share)
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
	rc := C.frosst_sign_aggregate(&sp, &sm, &ks, &sig)
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
	rc := C.frosst_verify_signature(&msg, &sig, &ks)
	return toError(int(rc))
}

// Reshare

func ResharePart1(id, maxSigners, minSigners uint16, oldKeyShare, oldIdentifiers []byte) (*DkgSecretHandle, []byte, error) {
	var oldKsSlice *C.go_slice
	var oks C.go_slice
	var p1 *runtime.Pinner
	if len(oldKeyShare) > 0 {
		oks, p1 = cGoSlice(oldKeyShare)
		defer p1.Unpin()
		oldKsSlice = &oks
	}
	var oldIdsSlice *C.go_slice
	var oids C.go_slice
	var p2 *runtime.Pinner
	if len(oldIdentifiers) > 0 {
		oids, p2 = cGoSlice(oldIdentifiers)
		defer p2.Unpin()
		oldIdsSlice = &oids
	}
	var secret C.Handle
	var pkg C.tss_buffer
	rc := C.frosst_reshare_part1(C.uint16_t(id), C.uint16_t(maxSigners), C.uint16_t(minSigners), oldKsSlice, oldIdsSlice, &secret, &pkg)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return &DkgSecretHandle{h: secret}, copyBuffer(&pkg), nil
}

func ResharePart3(secret *DkgSecretHandle, round1Packages, round2Packages, expectedVk []byte, network uint8, birthday uint64) ([]byte, []byte, error) {
	r1, p1 := cGoSlice(round1Packages)
	defer p1.Unpin()
	r2, p2 := cGoSlice(round2Packages)
	defer p2.Unpin()
	vk, p3 := cGoSlice(expectedVk)
	defer p3.Unpin()
	var keyShare C.tss_buffer
	var pubKey C.tss_buffer
	rc := C.frosst_reshare_part3(secret.h, &r1, &r2, &vk, C.uint8_t(network), C.uint64_t(birthday), &keyShare, &pubKey)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return copyBuffer(&keyShare), copyBuffer(&pubKey), nil
}

// Key Import

func DeriveFromSeed(seed []byte, accountIndex uint32) ([]byte, []byte, []byte, error) {
	s, p1 := cGoSlice(seed)
	defer p1.Unpin()
	var sk C.tss_buffer
	var cc C.tss_buffer
	var pk C.tss_buffer
	rc := C.frosst_derive_from_seed(&s, C.uint32_t(accountIndex), &sk, &cc, &pk)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, nil, err
	}
	return copyBuffer(&sk), copyBuffer(&cc), copyBuffer(&pk), nil
}

func KeyImportPart1(id, maxSigners, minSigners uint16, privateKey, chainCode []byte) (*DkgSecretHandle, []byte, error) {
	var skSlice *C.go_slice
	var sk C.go_slice
	var p1 *runtime.Pinner
	if len(privateKey) > 0 {
		sk, p1 = cGoSlice(privateKey)
		defer p1.Unpin()
		skSlice = &sk
	}
	var ccSlice *C.go_slice
	var cc C.go_slice
	var p2 *runtime.Pinner
	if len(chainCode) > 0 {
		cc, p2 = cGoSlice(chainCode)
		defer p2.Unpin()
		ccSlice = &cc
	}
	var secret C.Handle
	var pkg C.tss_buffer
	rc := C.frosst_key_import_part1(C.uint16_t(id), C.uint16_t(maxSigners), C.uint16_t(minSigners), skSlice, ccSlice, &secret, &pkg)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return &DkgSecretHandle{h: secret}, copyBuffer(&pkg), nil
}

func KeyImportPart3(secret *DkgSecretHandle, round1Packages, round2Packages, expectedVk []byte, network uint8, birthday uint64) ([]byte, []byte, error) {
	r1, p1 := cGoSlice(round1Packages)
	defer p1.Unpin()
	r2, p2 := cGoSlice(round2Packages)
	defer p2.Unpin()
	vk, p3 := cGoSlice(expectedVk)
	defer p3.Unpin()
	var keyShare C.tss_buffer
	var pubKey C.tss_buffer
	rc := C.frosst_key_import_part3(secret.h, &r1, &r2, &vk, C.uint8_t(network), C.uint64_t(birthday), &keyShare, &pubKey)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return copyBuffer(&keyShare), copyBuffer(&pubKey), nil
}

// Address

func DeriveAddress(keyShare []byte) (string, error) {
	ks, p1 := cGoSlice(keyShare)
	defer p1.Unpin()
	var addr C.tss_buffer
	rc := C.frosst_derive_address(&ks, &addr)
	err := toError(int(rc))
	if err != nil {
		return "", err
	}
	return string(copyBuffer(&addr)), nil
}

func PubkeyToAddress(pubkey []byte) (string, error) {
	pk, p1 := cGoSlice(pubkey)
	defer p1.Unpin()
	var addr C.tss_buffer
	rc := C.frosst_pubkey_to_address(&pk, &addr)
	err := toError(int(rc))
	if err != nil {
		return "", err
	}
	return string(copyBuffer(&addr)), nil
}

// KeyShare helpers

func KeySharePublicKey(keyShare []byte) ([]byte, error) {
	ks, p1 := cGoSlice(keyShare)
	defer p1.Unpin()
	var pk C.tss_buffer
	rc := C.frosst_keyshare_public_key(&ks, &pk)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&pk), nil
}

func KeyShareChainCode(keyShare []byte) ([]byte, error) {
	ks, p1 := cGoSlice(keyShare)
	defer p1.Unpin()
	var cc C.tss_buffer
	rc := C.frosst_keyshare_chain_code(&ks, &cc)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&cc), nil
}

func KeyShareBirthday(keyShare []byte) (uint64, error) {
	ks, p1 := cGoSlice(keyShare)
	defer p1.Unpin()
	var birthday C.uint64_t
	rc := C.frosst_keyshare_birthday(&ks, &birthday)
	err := toError(int(rc))
	if err != nil {
		return 0, err
	}
	return uint64(birthday), nil
}

func KeyShareIdentifier(keyShare []byte) (uint16, error) {
	ks, p1 := cGoSlice(keyShare)
	defer p1.Unpin()
	var id C.uint16_t
	rc := C.frosst_keyshare_identifier(&ks, &id)
	err := toError(int(rc))
	if err != nil {
		return 0, err
	}
	return uint16(id), nil
}

func PrivateKeyToPublic(privateKey []byte) ([]byte, error) {
	sk, p1 := cGoSlice(privateKey)
	defer p1.Unpin()
	var pk C.tss_buffer
	rc := C.frosst_private_key_to_public(&sk, &pk)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&pk), nil
}

func EncodeIdentifier(id uint16) ([]byte, error) {
	var out C.tss_buffer
	rc := C.frosst_encode_identifier(C.uint16_t(id), &out)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
}

func DecodeIdentifier(idBytes []byte) (uint16, error) {
	ib, p1 := cGoSlice(idBytes)
	defer p1.Unpin()
	var id C.uint16_t
	rc := C.frosst_decode_identifier(&ib, &id)
	err := toError(int(rc))
	if err != nil {
		return 0, err
	}
	return uint16(id), nil
}
