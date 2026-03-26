package froeth

/*
#include "includes/froeth-lib.h"
#include <stdlib.h>
*/
import "C"

import (
	"runtime"
	"unsafe"
)

type Handle int32

type DkgSecretHandle Handle
type NoncesHandle Handle

func (h DkgSecretHandle) Close() error { return HandleFree(Handle(h)) }
func (h NoncesHandle) Close() error    { return HandleFree(Handle(h)) }

func cHandle(h Handle) C.Handle {
	return C.Handle{_0: C.int32_t(h)}
}

func cGoSlice(data []byte, pinner *runtime.Pinner) *C.go_slice {
	if data == nil || len(data) == 0 {
		return nil
	}
	pinner.Pin(&data[0])
	return (*C.go_slice)(unsafe.Pointer(&data))
}

func copyBuffer(buf *C.tss_buffer) []byte {
	if buf.len == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(buf.ptr), C.int(buf.len))
}

func HandleFree(h Handle) error {
	res := C.froeth_handle_free(cHandle(h))
	if res != 0 {
		return mapLibError(int(res))
	}
	return nil
}

// DKG

func DkgPart1(identifier, maxSigners, minSigners uint16) (DkgSecretHandle, []byte, error) {
	var outSecret C.Handle
	var outPackage C.tss_buffer
	defer C.tss_buffer_free(&outPackage)

	res := C.froeth_dkg_part1(
		C.uint16_t(identifier),
		C.uint16_t(maxSigners),
		C.uint16_t(minSigners),
		&outSecret,
		&outPackage,
	)
	if res != 0 {
		return 0, nil, mapLibError(int(res))
	}

	return DkgSecretHandle(outSecret._0), copyBuffer(&outPackage), nil
}

func DkgPart2(secret DkgSecretHandle, round1Packages []byte) (DkgSecretHandle, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	r1 := cGoSlice(round1Packages, pinner)

	var outSecret C.Handle
	var outPackages C.tss_buffer
	defer C.tss_buffer_free(&outPackages)

	res := C.froeth_dkg_part2(
		cHandle(Handle(secret)),
		r1,
		&outSecret,
		&outPackages,
	)
	if res != 0 {
		return 0, nil, mapLibError(int(res))
	}

	return DkgSecretHandle(outSecret._0), copyBuffer(&outPackages), nil
}

func DkgPart3(secret DkgSecretHandle, round1Packages, round2Packages []byte, network uint8, birthday uint64) ([]byte, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	r1 := cGoSlice(round1Packages, pinner)
	r2 := cGoSlice(round2Packages, pinner)

	var outKS C.tss_buffer
	var outPK C.tss_buffer
	defer C.tss_buffer_free(&outKS)
	defer C.tss_buffer_free(&outPK)

	res := C.froeth_dkg_part3(
		cHandle(Handle(secret)),
		r1,
		r2,
		C.uint8_t(network),
		C.uint64_t(birthday),
		&outKS,
		&outPK,
	)
	if res != 0 {
		return nil, nil, mapLibError(int(res))
	}

	return copyBuffer(&outKS), copyBuffer(&outPK), nil
}

// Reshare

func ResharePart1(identifier, maxSigners, minSigners uint16, oldKeyShare []byte, oldIdentifiers []uint16) (DkgSecretHandle, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	oldKS := cGoSlice(oldKeyShare, pinner)

	var oldIDs *C.go_slice
	if len(oldIdentifiers) > 0 {
		idBytes := make([]byte, len(oldIdentifiers)*2)
		for i, id := range oldIdentifiers {
			idBytes[i*2] = byte(id)
			idBytes[i*2+1] = byte(id >> 8)
		}
		oldIDs = cGoSlice(idBytes, pinner)
	}

	var outSecret C.Handle
	var outPackage C.tss_buffer
	defer C.tss_buffer_free(&outPackage)

	res := C.froeth_reshare_part1(
		C.uint16_t(identifier),
		C.uint16_t(maxSigners),
		C.uint16_t(minSigners),
		oldKS,
		oldIDs,
		&outSecret,
		&outPackage,
	)
	if res != 0 {
		return 0, nil, mapLibError(int(res))
	}

	return DkgSecretHandle(outSecret._0), copyBuffer(&outPackage), nil
}

func ResharePart3(secret DkgSecretHandle, round1Packages, round2Packages, expectedVK []byte, network uint8, birthday uint64) ([]byte, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	r1 := cGoSlice(round1Packages, pinner)
	r2 := cGoSlice(round2Packages, pinner)
	vk := cGoSlice(expectedVK, pinner)

	var outKS C.tss_buffer
	var outPK C.tss_buffer
	defer C.tss_buffer_free(&outKS)
	defer C.tss_buffer_free(&outPK)

	res := C.froeth_reshare_part3(
		cHandle(Handle(secret)),
		r1,
		r2,
		vk,
		C.uint8_t(network),
		C.uint64_t(birthday),
		&outKS,
		&outPK,
	)
	if res != 0 {
		return nil, nil, mapLibError(int(res))
	}

	return copyBuffer(&outKS), copyBuffer(&outPK), nil
}

// Signing

func SignCommit(keyShare []byte) (NoncesHandle, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	ks := cGoSlice(keyShare, pinner)

	var outNonces C.Handle
	var outCommitments C.tss_buffer
	defer C.tss_buffer_free(&outCommitments)

	res := C.froeth_sign_commit(ks, &outNonces, &outCommitments)
	if res != 0 {
		return 0, nil, mapLibError(int(res))
	}

	return NoncesHandle(outNonces._0), copyBuffer(&outCommitments), nil
}

func SignCreatePackage(message, commitmentsMap []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	msg := cGoSlice(message, pinner)
	cm := cGoSlice(commitmentsMap, pinner)

	var outPkg C.tss_buffer
	defer C.tss_buffer_free(&outPkg)

	res := C.froeth_sign_create_package(msg, cm, &outPkg)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outPkg), nil
}

func Sign(signingPackage []byte, nonces NoncesHandle, keyShare []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	sp := cGoSlice(signingPackage, pinner)
	ks := cGoSlice(keyShare, pinner)

	var outShare C.tss_buffer
	defer C.tss_buffer_free(&outShare)

	res := C.froeth_sign(sp, cHandle(Handle(nonces)), ks, &outShare)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outShare), nil
}

func SignAggregate(signingPackage, sharesMap, keyShare []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	sp := cGoSlice(signingPackage, pinner)
	sm := cGoSlice(sharesMap, pinner)
	ks := cGoSlice(keyShare, pinner)

	var outSig C.tss_buffer
	defer C.tss_buffer_free(&outSig)

	res := C.froeth_sign_aggregate(sp, sm, ks, &outSig)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outSig), nil
}

func VerifySignature(message, signature, keyShare []byte) error {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	msg := cGoSlice(message, pinner)
	sig := cGoSlice(signature, pinner)
	ks := cGoSlice(keyShare, pinner)

	res := C.froeth_verify_signature(msg, sig, ks)
	if res != 0 {
		return mapLibError(int(res))
	}

	return nil
}

// Key Import

func DeriveFromSeed(seed []byte, accountIndex uint32) (privateKey, chainCode, publicKey []byte, err error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	s := cGoSlice(seed, pinner)

	var outSK C.tss_buffer
	var outCC C.tss_buffer
	var outPK C.tss_buffer
	defer C.tss_buffer_free(&outSK)
	defer C.tss_buffer_free(&outCC)
	defer C.tss_buffer_free(&outPK)

	res := C.froeth_derive_from_seed(s, C.uint32_t(accountIndex), &outSK, &outCC, &outPK)
	if res != 0 {
		return nil, nil, nil, mapLibError(int(res))
	}

	return copyBuffer(&outSK), copyBuffer(&outCC), copyBuffer(&outPK), nil
}

func KeyImportPart1(identifier, maxSigners, minSigners uint16, privateKey, chainCode []byte) (DkgSecretHandle, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	sk := cGoSlice(privateKey, pinner)
	cc := cGoSlice(chainCode, pinner)

	var outSecret C.Handle
	var outPackage C.tss_buffer
	defer C.tss_buffer_free(&outPackage)

	res := C.froeth_key_import_part1(
		C.uint16_t(identifier),
		C.uint16_t(maxSigners),
		C.uint16_t(minSigners),
		sk,
		cc,
		&outSecret,
		&outPackage,
	)
	if res != 0 {
		return 0, nil, mapLibError(int(res))
	}

	return DkgSecretHandle(outSecret._0), copyBuffer(&outPackage), nil
}

func KeyImportPart3(secret DkgSecretHandle, round1Packages, round2Packages, expectedVK []byte, network uint8, birthday uint64) ([]byte, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	r1 := cGoSlice(round1Packages, pinner)
	r2 := cGoSlice(round2Packages, pinner)
	vk := cGoSlice(expectedVK, pinner)

	var outKS C.tss_buffer
	var outPK C.tss_buffer
	defer C.tss_buffer_free(&outKS)
	defer C.tss_buffer_free(&outPK)

	res := C.froeth_key_import_part3(
		cHandle(Handle(secret)),
		r1,
		r2,
		vk,
		C.uint8_t(network),
		C.uint64_t(birthday),
		&outKS,
		&outPK,
	)
	if res != 0 {
		return nil, nil, mapLibError(int(res))
	}

	return copyBuffer(&outKS), copyBuffer(&outPK), nil
}

// CKD

func CkdDerive(keyShare []byte, change, index uint32) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	ks := cGoSlice(keyShare, pinner)

	var outChild C.tss_buffer
	defer C.tss_buffer_free(&outChild)

	res := C.froeth_ckd_derive(ks, C.uint32_t(change), C.uint32_t(index), &outChild)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outChild), nil
}

func DeriveChildPubkey(keyShare []byte, change, index uint32) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	ks := cGoSlice(keyShare, pinner)

	var outPK C.tss_buffer
	defer C.tss_buffer_free(&outPK)

	res := C.froeth_derive_child_pubkey(ks, C.uint32_t(change), C.uint32_t(index), &outPK)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outPK), nil
}

// Address

func DeriveAddress(keyShare []byte, change, index uint32) (string, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	ks := cGoSlice(keyShare, pinner)

	var outAddr C.tss_buffer
	defer C.tss_buffer_free(&outAddr)

	res := C.froeth_derive_address(ks, C.uint32_t(change), C.uint32_t(index), &outAddr)
	if res != 0 {
		return "", mapLibError(int(res))
	}

	return string(copyBuffer(&outAddr)), nil
}

func DeriveRootAddress(keyShare []byte) (string, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	ks := cGoSlice(keyShare, pinner)

	var outAddr C.tss_buffer
	defer C.tss_buffer_free(&outAddr)

	res := C.froeth_derive_root_address(ks, &outAddr)
	if res != 0 {
		return "", mapLibError(int(res))
	}

	return string(copyBuffer(&outAddr)), nil
}

func EthAddress(verifyingKey []byte) (string, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	vk := cGoSlice(verifyingKey, pinner)

	var outAddr C.tss_buffer
	defer C.tss_buffer_free(&outAddr)

	res := C.froeth_eth_address(vk, &outAddr)
	if res != 0 {
		return "", mapLibError(int(res))
	}

	return string(copyBuffer(&outAddr)), nil
}

// KeyShare helpers

func KeySharePublicKey(keyShare []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()
	ks := cGoSlice(keyShare, pinner)
	var outPK C.tss_buffer
	defer C.tss_buffer_free(&outPK)
	res := C.froeth_keyshare_public_key(ks, &outPK)
	if res != 0 {
		return nil, mapLibError(int(res))
	}
	return copyBuffer(&outPK), nil
}

func KeyShareChainCode(keyShare []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()
	ks := cGoSlice(keyShare, pinner)
	var outCC C.tss_buffer
	defer C.tss_buffer_free(&outCC)
	res := C.froeth_keyshare_chain_code(ks, &outCC)
	if res != 0 {
		return nil, mapLibError(int(res))
	}
	return copyBuffer(&outCC), nil
}

func KeyShareBirthday(keyShare []byte) (uint64, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()
	ks := cGoSlice(keyShare, pinner)
	var birthday C.uint64_t
	res := C.froeth_keyshare_birthday(ks, &birthday)
	if res != 0 {
		return 0, mapLibError(int(res))
	}
	return uint64(birthday), nil
}

func KeyShareIdentifier(keyShare []byte) (uint16, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()
	ks := cGoSlice(keyShare, pinner)
	var id C.uint16_t
	res := C.froeth_keyshare_identifier(ks, &id)
	if res != 0 {
		return 0, mapLibError(int(res))
	}
	return uint16(id), nil
}

func PrivateKeyToPublic(privateKey []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()
	sk := cGoSlice(privateKey, pinner)
	var outPK C.tss_buffer
	defer C.tss_buffer_free(&outPK)
	res := C.froeth_private_key_to_public(sk, &outPK)
	if res != 0 {
		return nil, mapLibError(int(res))
	}
	return copyBuffer(&outPK), nil
}

func EncodeIdentifier(id uint16) ([]byte, error) {
	var out C.tss_buffer
	defer C.tss_buffer_free(&out)
	res := C.froeth_encode_identifier(C.uint16_t(id), &out)
	if res != 0 {
		return nil, mapLibError(int(res))
	}
	return copyBuffer(&out), nil
}

func DecodeIdentifier(idBytes []byte) (uint16, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()
	ib := cGoSlice(idBytes, pinner)
	var id C.uint16_t
	res := C.froeth_decode_identifier(ib, &id)
	if res != 0 {
		return 0, mapLibError(int(res))
	}
	return uint16(id), nil
}
