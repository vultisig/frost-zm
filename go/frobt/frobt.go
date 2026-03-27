package frobt

/*
#cgo CFLAGS: -I${SRCDIR}/includes
#include "frobt-lib.h"
#include <stdlib.h>
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"unsafe"
)

type DkgSecretHandle struct {
	h C.Handle
}

func (h *DkgSecretHandle) Close() error {
	return toError(int(C.frobt_handle_free(h.h)))
}

type NoncesHandle struct {
	h C.Handle
}

func (h *NoncesHandle) Close() error {
	return toError(int(C.frobt_handle_free(h.h)))
}

const (
	frobtBundleVersion = 1
	frobtChainCodeSize = 32
)

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
	return toError(int(C.frobt_handle_free(h)))
}

func DkgPart1(id, maxSigners, minSigners uint16) (*DkgSecretHandle, []byte, error) {
	var secret C.Handle
	var pkg C.tss_buffer
	rc := C.frobt_dkg_part1(C.uint16_t(id), C.uint16_t(maxSigners), C.uint16_t(minSigners), &secret, &pkg)
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
	rc := C.frobt_dkg_part2(secret.h, &r1, &secret2, &pkgs)
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
	rc := C.frobt_dkg_part3(secret.h, &r1, &r2, C.uint8_t(network), C.uint64_t(birthday), &keyShare, &pubKey)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return copyBuffer(&keyShare), copyBuffer(&pubKey), nil
}

func DeriveFromSeed(seed []byte, accountIndex uint32) ([]byte, []byte, []byte, error) {
	s, p := cGoSlice(seed)
	defer p.Unpin()
	var sk C.tss_buffer
	var cc C.tss_buffer
	var pk C.tss_buffer
	rc := C.frobt_derive_from_seed(&s, C.uint32_t(accountIndex), &sk, &cc, &pk)
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
	rc := C.frobt_key_import_part1(C.uint16_t(id), C.uint16_t(maxSigners), C.uint16_t(minSigners), skSlice, ccSlice, &secret, &pkg)
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
	rc := C.frobt_key_import_part3(secret.h, &r1, &r2, &vk, C.uint8_t(network), C.uint64_t(birthday), &keyShare, &pubKey)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return copyBuffer(&keyShare), copyBuffer(&pubKey), nil
}

func PrivateKeyToPublic(privateKey []byte) ([]byte, error) {
	sk, p := cGoSlice(privateKey)
	defer p.Unpin()
	var pk C.tss_buffer
	rc := C.frobt_private_key_to_public(&sk, &pk)
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
	rc := C.frobt_sign_commit(&ks, &nonces, &commitments)
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
	rc := C.frobt_sign_create_package(&msg, &cm, &sp)
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
	rc := C.frobt_sign(&sp, nonces.h, &ks, &share)
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
	rc := C.frobt_sign_aggregate(&sp, &sm, &ks, &sig)
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

	rc := C.frobt_verify_signature(&msg, &sig, &ks)
	return toError(int(rc))
}

func SignTaproot(signingPackage []byte, nonces *NoncesHandle, keyShare, merkleRoot []byte) ([]byte, error) {
	sp, p1 := cGoSlice(signingPackage)
	defer p1.Unpin()
	ks, p2 := cGoSlice(keyShare)
	defer p2.Unpin()
	var mrSlice *C.go_slice
	var mr C.go_slice
	var p3 *runtime.Pinner
	if len(merkleRoot) > 0 {
		mr, p3 = cGoSlice(merkleRoot)
		defer p3.Unpin()
		mrSlice = &mr
	}
	var share C.tss_buffer
	rc := C.frobt_sign_taproot(&sp, nonces.h, &ks, mrSlice, &share)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&share), nil
}

func SignAggregateTaproot(signingPackage, sharesMap, keyShare, merkleRoot []byte) ([]byte, error) {
	sp, p1 := cGoSlice(signingPackage)
	defer p1.Unpin()
	sm, p2 := cGoSlice(sharesMap)
	defer p2.Unpin()
	ks, p3 := cGoSlice(keyShare)
	defer p3.Unpin()
	var mrSlice *C.go_slice
	var mr C.go_slice
	var p4 *runtime.Pinner
	if len(merkleRoot) > 0 {
		mr, p4 = cGoSlice(merkleRoot)
		defer p4.Unpin()
		mrSlice = &mr
	}
	var sig C.tss_buffer
	rc := C.frobt_sign_aggregate_taproot(&sp, &sm, &ks, mrSlice, &sig)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&sig), nil
}

func VerifyTaprootSignature(message, signature, keyShare, merkleRoot []byte) error {
	msg, p1 := cGoSlice(message)
	defer p1.Unpin()
	sig, p2 := cGoSlice(signature)
	defer p2.Unpin()
	ks, p3 := cGoSlice(keyShare)
	defer p3.Unpin()
	var mrSlice *C.go_slice
	var mr C.go_slice
	var p4 *runtime.Pinner
	if len(merkleRoot) > 0 {
		mr, p4 = cGoSlice(merkleRoot)
		defer p4.Unpin()
		mrSlice = &mr
	}

	rc := C.frobt_verify_taproot_signature(&msg, &sig, &ks, mrSlice)
	return toError(int(rc))
}

func ComputeTaprootOutputKey(verifyingKey, merkleRoot []byte) ([]byte, error) {
	vk, p1 := cGoSlice(verifyingKey)
	defer p1.Unpin()
	var mrSlice *C.go_slice
	var mr C.go_slice
	var p2 *runtime.Pinner
	if len(merkleRoot) > 0 {
		mr, p2 = cGoSlice(merkleRoot)
		defer p2.Unpin()
		mrSlice = &mr
	}
	var out C.tss_buffer
	rc := C.frobt_compute_taproot_output_key(&vk, mrSlice, &out)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&out), nil
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
	rc := C.frobt_reshare_part1(C.uint16_t(id), C.uint16_t(maxSigners), C.uint16_t(minSigners), oksSlice, oidsSlice, &secret, &pkg)
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
	rc := C.frobt_reshare_part3(secret.h, &r1, &r2, &vk, C.uint8_t(network), C.uint64_t(birthday), &keyShare, &pubKey)
	err := toError(int(rc))
	if err != nil {
		return nil, nil, err
	}
	return copyBuffer(&keyShare), copyBuffer(&pubKey), nil
}

func CkdDerive(keyShare []byte, change, index uint32) ([]byte, error) {
	ks, p := cGoSlice(keyShare)
	defer p.Unpin()
	var child C.tss_buffer
	rc := C.frobt_ckd_derive(&ks, C.uint32_t(change), C.uint32_t(index), &child)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&child), nil
}

func DeriveChildPubkey(keyShare []byte, change, index uint32) ([]byte, error) {
	ks, p := cGoSlice(keyShare)
	defer p.Unpin()
	var pk C.tss_buffer
	rc := C.frobt_derive_child_pubkey(&ks, C.uint32_t(change), C.uint32_t(index), &pk)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&pk), nil
}

func DeriveP2TRAddress(pubkey []byte, network uint8) (string, error) {
	pk, p := cGoSlice(pubkey)
	defer p.Unpin()
	var addr C.tss_buffer
	rc := C.frobt_derive_address_from_pubkey(&pk, C.uint8_t(network), &addr)
	err := toError(int(rc))
	if err != nil {
		return "", err
	}
	return string(copyBuffer(&addr)), nil
}

func DeriveAddress(keyShare []byte, change, index uint32) (string, error) {
	ks, p := cGoSlice(keyShare)
	defer p.Unpin()
	var addr C.tss_buffer
	rc := C.frobt_derive_address(&ks, C.uint32_t(change), C.uint32_t(index), &addr)
	err := toError(int(rc))
	if err != nil {
		return "", err
	}
	return string(copyBuffer(&addr)), nil
}

func DeriveRootAddress(keyShare []byte) (string, error) {
	ks, p := cGoSlice(keyShare)
	defer p.Unpin()
	var addr C.tss_buffer
	rc := C.frobt_derive_root_address(&ks, &addr)
	err := toError(int(rc))
	if err != nil {
		return "", err
	}
	return string(copyBuffer(&addr)), nil
}

func ComputeSighash(rawTx, prevouts []byte, inputIndex uint32, sighashType uint8) ([]byte, error) {
	tx, p1 := cGoSlice(rawTx)
	defer p1.Unpin()
	prev, p2 := cGoSlice(prevouts)
	defer p2.Unpin()
	var hash C.tss_buffer
	rc := C.frobt_compute_sighash(&tx, &prev, C.uint32_t(inputIndex), C.uint8_t(sighashType), &hash)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&hash), nil
}

func AttachWitness(rawTx []byte, inputIndex uint32, signature []byte) ([]byte, error) {
	tx, p1 := cGoSlice(rawTx)
	defer p1.Unpin()
	sig, p2 := cGoSlice(signature)
	defer p2.Unpin()
	var signed C.tss_buffer
	rc := C.frobt_attach_witness(&tx, C.uint32_t(inputIndex), &sig, &signed)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&signed), nil
}

func KeySharePublicKey(keyShare []byte) ([]byte, error) {
	ks, p := cGoSlice(keyShare)
	defer p.Unpin()
	var pk C.tss_buffer
	rc := C.frobt_keyshare_public_key(&ks, &pk)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&pk), nil
}

func KeyShareChainCode(keyShare []byte) ([]byte, error) {
	ks, p := cGoSlice(keyShare)
	defer p.Unpin()
	var cc C.tss_buffer
	rc := C.frobt_keyshare_chain_code(&ks, &cc)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&cc), nil
}

func KeyShareBirthday(keyShare []byte) (uint64, error) {
	ks, p := cGoSlice(keyShare)
	defer p.Unpin()
	var birthday C.uint64_t
	rc := C.frobt_keyshare_birthday(&ks, &birthday)
	err := toError(int(rc))
	if err != nil {
		return 0, err
	}
	return uint64(birthday), nil
}

func KeyShareNetwork(keyShare []byte) (uint8, error) {
	if len(keyShare) < 2 {
		return 0, fmt.Errorf("frobt keyshare too short")
	}
	version := keyShare[0]
	if version != frobtBundleVersion {
		return 0, fmt.Errorf("frobt keyshare unknown version %d", version)
	}
	return keyShare[1], nil
}

func KeyShareIdentifier(keyShare []byte) (uint16, error) {
	ks, p := cGoSlice(keyShare)
	defer p.Unpin()
	var id C.uint16_t
	rc := C.frobt_keyshare_identifier(&ks, &id)
	err := toError(int(rc))
	if err != nil {
		return 0, err
	}
	return uint16(id), nil
}

func KeyShareBundleKeyPackage(keyShare []byte) ([]byte, error) {
	version, _, _, _, keyPackage, _, err := decodeKeyShareBundle(keyShare)
	if err != nil {
		return nil, err
	}
	if version != frobtBundleVersion {
		return nil, fmt.Errorf("frobt keyshare unknown version %d", version)
	}
	return keyPackage, nil
}

func KeyShareBundlePubKeyPackage(keyShare []byte) ([]byte, error) {
	version, _, _, _, _, pubKeyPackage, err := decodeKeyShareBundle(keyShare)
	if err != nil {
		return nil, err
	}
	if version != frobtBundleVersion {
		return nil, fmt.Errorf("frobt keyshare unknown version %d", version)
	}
	return pubKeyPackage, nil
}

func KeyShareBundlePack(keyPackage, pubKeyPackage, chainCode []byte, network uint8, birthday uint64) ([]byte, error) {
	if len(chainCode) != frobtChainCodeSize {
		return nil, fmt.Errorf("frobt chain code must be %d bytes", frobtChainCodeSize)
	}
	total := 1 + 1 + frobtChainCodeSize + 8 + 4 + len(keyPackage) + 4 + len(pubKeyPackage)
	buf := make([]byte, total)
	pos := 0
	buf[pos] = frobtBundleVersion
	pos++
	buf[pos] = network
	pos++
	copy(buf[pos:pos+frobtChainCodeSize], chainCode)
	pos += frobtChainCodeSize
	binary.LittleEndian.PutUint64(buf[pos:pos+8], birthday)
	pos += 8
	binary.LittleEndian.PutUint32(buf[pos:pos+4], uint32(len(keyPackage)))
	pos += 4
	copy(buf[pos:pos+len(keyPackage)], keyPackage)
	pos += len(keyPackage)
	binary.LittleEndian.PutUint32(buf[pos:pos+4], uint32(len(pubKeyPackage)))
	pos += 4
	copy(buf[pos:pos+len(pubKeyPackage)], pubKeyPackage)
	return buf, nil
}

func decodeKeyShareBundle(data []byte) (version uint8, network uint8, chainCode []byte, birthday uint64, keyPackage []byte, pubKeyPackage []byte, err error) {
	if len(data) < 1+1+frobtChainCodeSize+8+4 {
		return 0, 0, nil, 0, nil, nil, fmt.Errorf("frobt keyshare too short")
	}
	pos := 0
	version = data[pos]
	pos++
	if version != frobtBundleVersion {
		return 0, 0, nil, 0, nil, nil, fmt.Errorf("frobt keyshare unknown version %d", version)
	}
	network = data[pos]
	pos++
	chainCode = append([]byte(nil), data[pos:pos+frobtChainCodeSize]...)
	pos += frobtChainCodeSize
	if pos+8 > len(data) {
		return 0, 0, nil, 0, nil, nil, fmt.Errorf("frobt keyshare truncated at birthday")
	}
	birthday = binary.LittleEndian.Uint64(data[pos : pos+8])
	pos += 8
	if pos+4 > len(data) {
		return 0, 0, nil, 0, nil, nil, fmt.Errorf("frobt keyshare truncated at key package length")
	}
	keyPackageLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4
	if pos+keyPackageLen > len(data) {
		return 0, 0, nil, 0, nil, nil, fmt.Errorf("frobt keyshare truncated at key package")
	}
	keyPackage = append([]byte(nil), data[pos:pos+keyPackageLen]...)
	pos += keyPackageLen
	if pos+4 > len(data) {
		return 0, 0, nil, 0, nil, nil, fmt.Errorf("frobt keyshare truncated at pubkey package length")
	}
	pubKeyPackageLen := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4
	if pos+pubKeyPackageLen > len(data) {
		return 0, 0, nil, 0, nil, nil, fmt.Errorf("frobt keyshare truncated at pubkey package")
	}
	pubKeyPackage = append([]byte(nil), data[pos:pos+pubKeyPackageLen]...)
	return version, network, chainCode, birthday, keyPackage, pubKeyPackage, nil
}

func EncodeIdentifier(id uint16) ([]byte, error) {
	var buf C.tss_buffer
	rc := C.frobt_encode_identifier(C.uint16_t(id), &buf)
	err := toError(int(rc))
	if err != nil {
		return nil, err
	}
	return copyBuffer(&buf), nil
}

func DecodeIdentifier(idBytes []byte) (uint16, error) {
	s, p := cGoSlice(idBytes)
	defer p.Unpin()
	var id C.uint16_t
	rc := C.frobt_decode_identifier(&s, &id)
	err := toError(int(rc))
	if err != nil {
		return 0, err
	}
	return uint16(id), nil
}
