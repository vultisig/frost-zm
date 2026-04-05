package frozto

/*
#include "includes/frozto-lib.h"
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
type TreeHandle Handle

func (h DkgSecretHandle) Close() error { return HandleFree(Handle(h)) }
func (h NoncesHandle) Close() error    { return HandleFree(Handle(h)) }
func (h TreeHandle) Close() error      { return HandleFree(Handle(h)) }

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
	res := C.frozto_handle_free(cHandle(h))
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

	res := C.frozto_dkg_part1(
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

	res := C.frozto_dkg_part2(
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

func DkgPart3(secret DkgSecretHandle, round1Packages, round2Packages []byte) ([]byte, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	r1 := cGoSlice(round1Packages, pinner)
	r2 := cGoSlice(round2Packages, pinner)

	var outKP C.tss_buffer
	var outPKP C.tss_buffer
	defer C.tss_buffer_free(&outKP)
	defer C.tss_buffer_free(&outPKP)

	res := C.frozto_dkg_part3(
		cHandle(Handle(secret)),
		r1,
		r2,
		&outKP,
		&outPKP,
	)
	if res != 0 {
		return nil, nil, mapLibError(int(res))
	}

	return copyBuffer(&outKP), copyBuffer(&outPKP), nil
}

// Reshare

func ResharePart1(identifier, maxSigners, minSigners uint16, oldKeyPackage []byte, oldIdentifiers []uint16) (DkgSecretHandle, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	oldKP := cGoSlice(oldKeyPackage, pinner)

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

	res := C.frozto_reshare_part1(
		C.uint16_t(identifier),
		C.uint16_t(maxSigners),
		C.uint16_t(minSigners),
		oldKP,
		oldIDs,
		&outSecret,
		&outPackage,
	)
	if res != 0 {
		return 0, nil, mapLibError(int(res))
	}

	return DkgSecretHandle(outSecret._0), copyBuffer(&outPackage), nil
}

func ResharePart3(secret DkgSecretHandle, round1Packages, round2Packages, expectedVerifyingKey []byte) ([]byte, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	r1 := cGoSlice(round1Packages, pinner)
	r2 := cGoSlice(round2Packages, pinner)
	vk := cGoSlice(expectedVerifyingKey, pinner)

	var outKP C.tss_buffer
	var outPKP C.tss_buffer
	defer C.tss_buffer_free(&outKP)
	defer C.tss_buffer_free(&outPKP)

	res := C.frozto_reshare_part3(
		cHandle(Handle(secret)),
		r1,
		r2,
		vk,
		&outKP,
		&outPKP,
	)
	if res != 0 {
		return nil, nil, mapLibError(int(res))
	}

	return copyBuffer(&outKP), copyBuffer(&outPKP), nil
}

// Signing

func SignCommit(keyPackage []byte) (NoncesHandle, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	kp := cGoSlice(keyPackage, pinner)

	var outNonces C.Handle
	var outCommitments C.tss_buffer
	defer C.tss_buffer_free(&outCommitments)

	res := C.frozto_sign_commit(kp, &outNonces, &outCommitments)
	if res != 0 {
		return 0, nil, mapLibError(int(res))
	}

	return NoncesHandle(outNonces._0), copyBuffer(&outCommitments), nil
}

func SignNewPackage(message, commitmentsMap, pubKeyPackage []byte) ([]byte, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	msg := cGoSlice(message, pinner)
	cm := cGoSlice(commitmentsMap, pinner)
	pkp := cGoSlice(pubKeyPackage, pinner)

	var outSP C.tss_buffer
	var outRandomizer C.tss_buffer
	defer C.tss_buffer_free(&outSP)
	defer C.tss_buffer_free(&outRandomizer)

	res := C.frozto_sign_new_package(msg, cm, pkp, &outSP, &outRandomizer)
	if res != 0 {
		return nil, nil, mapLibError(int(res))
	}

	return copyBuffer(&outSP), copyBuffer(&outRandomizer), nil
}

func Sign(signingPackage []byte, nonces NoncesHandle, keyPackage, randomizer []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	sp := cGoSlice(signingPackage, pinner)
	kp := cGoSlice(keyPackage, pinner)
	r := cGoSlice(randomizer, pinner)

	var outShare C.tss_buffer
	defer C.tss_buffer_free(&outShare)

	res := C.frozto_sign(sp, cHandle(Handle(nonces)), kp, r, &outShare)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outShare), nil
}

func SignAggregate(signingPackage, sharesMap, pubKeyPackage, randomizer []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	sp := cGoSlice(signingPackage, pinner)
	sm := cGoSlice(sharesMap, pinner)
	pkp := cGoSlice(pubKeyPackage, pinner)
	r := cGoSlice(randomizer, pinner)

	var outSig C.tss_buffer
	defer C.tss_buffer_free(&outSig)

	res := C.frozto_sign_aggregate(sp, sm, pkp, r, &outSig)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outSig), nil
}

func VerifySignature(message, signature, pubKeyPackage, randomizer []byte) error {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	msg := cGoSlice(message, pinner)
	sig := cGoSlice(signature, pinner)
	pkp := cGoSlice(pubKeyPackage, pinner)
	r := cGoSlice(randomizer, pinner)

	res := C.frozto_verify_signature(msg, sig, pkp, r)
	if res != 0 {
		return mapLibError(int(res))
	}

	return nil
}

func encodeIdentifier(id uint16) ([]byte, error) {
	var outBytes C.tss_buffer
	defer C.tss_buffer_free(&outBytes)

	res := C.frozto_encode_identifier(C.uint16_t(id), &outBytes)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outBytes), nil
}

func decodeIdentifier(idBytes []byte) (uint16, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	data := cGoSlice(idBytes, pinner)

	var outID C.uint16_t

	res := C.frozto_decode_identifier(data, &outID)
	if res != 0 {
		return 0, mapLibError(int(res))
	}

	return uint16(outID), nil
}

// Key inspection

func KeyPackageIdentifier(keyPackage []byte) (uint16, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	kp := cGoSlice(keyPackage, pinner)

	var outID C.uint16_t

	res := C.frozto_keypackage_identifier(kp, &outID)
	if res != 0 {
		return 0, mapLibError(int(res))
	}

	return uint16(outID), nil
}

func PubKeyPackageVerifyingKey(pubKeyPackage []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	pkp := cGoSlice(pubKeyPackage, pinner)

	var outKey C.tss_buffer
	defer C.tss_buffer_free(&outKey)

	res := C.frozto_pubkeypackage_verifying_key(pkp, &outKey)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outKey), nil
}

// Key Share Bundle

func KeyShareBundlePack(keyPackage, pubKeyPackage, orchardExtras []byte, birthday uint64) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	kp := cGoSlice(keyPackage, pinner)
	pkp := cGoSlice(pubKeyPackage, pinner)
	extras := cGoSlice(orchardExtras, pinner)

	var outBundle C.tss_buffer
	defer C.tss_buffer_free(&outBundle)

	res := C.frozto_keyshare_bundle_pack(kp, pkp, extras, C.uint64_t(birthday), &outBundle)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outBundle), nil
}

func KeyShareBundleBirthday(bundle []byte) (uint64, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	data := cGoSlice(bundle, pinner)

	var outBirthday C.uint64_t

	res := C.frozto_keyshare_bundle_birthday(data, &outBirthday)
	if res != 0 {
		return 0, mapLibError(int(res))
	}

	return uint64(outBirthday), nil
}

func KeyShareBundleKeyPackage(bundle []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	data := cGoSlice(bundle, pinner)

	var outKP C.tss_buffer
	defer C.tss_buffer_free(&outKP)

	res := C.frozto_keyshare_bundle_key_package(data, &outKP)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outKP), nil
}

func KeyShareBundlePubKeyPackage(bundle []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	data := cGoSlice(bundle, pinner)

	var outPKP C.tss_buffer
	defer C.tss_buffer_free(&outPKP)

	res := C.frozto_keyshare_bundle_pub_key_package(data, &outPKP)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outPKP), nil
}

func KeyShareBundleOrchardExtras(bundle []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	data := cGoSlice(bundle, pinner)

	var outExtras C.tss_buffer
	defer C.tss_buffer_free(&outExtras)

	res := C.frozto_keyshare_bundle_orchard_extras(data, &outExtras)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outExtras), nil
}

// Key Import

func KeyImportPart1(identifier, maxSigners, minSigners uint16, spendingKey []byte) (DkgSecretHandle, []byte, []byte, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	s := cGoSlice(spendingKey, pinner)

	var outSecret C.Handle
	var outPackage C.tss_buffer
	var outVK C.tss_buffer
	var outExtras C.tss_buffer
	defer C.tss_buffer_free(&outPackage)
	defer C.tss_buffer_free(&outVK)
	defer C.tss_buffer_free(&outExtras)

	res := C.frozto_key_import_part1(
		C.uint16_t(identifier),
		C.uint16_t(maxSigners),
		C.uint16_t(minSigners),
		s,
		&outSecret,
		&outPackage,
		&outVK,
		&outExtras,
	)
	if res != 0 {
		return 0, nil, nil, nil, mapLibError(int(res))
	}

	return DkgSecretHandle(outSecret._0), copyBuffer(&outPackage), copyBuffer(&outVK), copyBuffer(&outExtras), nil
}

func KeyImportPart3(secret DkgSecretHandle, round1Packages, round2Packages, expectedVK []byte) ([]byte, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	r1 := cGoSlice(round1Packages, pinner)
	r2 := cGoSlice(round2Packages, pinner)
	vk := cGoSlice(expectedVK, pinner)

	var outKP C.tss_buffer
	var outPKP C.tss_buffer
	defer C.tss_buffer_free(&outKP)
	defer C.tss_buffer_free(&outPKP)

	res := C.frozto_key_import_part3(
		cHandle(Handle(secret)),
		r1,
		r2,
		vk,
		&outKP,
		&outPKP,
	)
	if res != 0 {
		return nil, nil, mapLibError(int(res))
	}

	return copyBuffer(&outKP), copyBuffer(&outPKP), nil
}

// Ceremony Metadata

func KeygenMetadataCreate(birthday uint64) (extras []byte, metadata []byte, err error) {
	var outExtras C.tss_buffer
	var outMetadata C.tss_buffer
	defer C.tss_buffer_free(&outExtras)
	defer C.tss_buffer_free(&outMetadata)

	res := C.frozto_keygen_metadata_create(C.uint64_t(birthday), &outExtras, &outMetadata)
	if res != 0 {
		return nil, nil, mapLibError(int(res))
	}

	return copyBuffer(&outExtras), copyBuffer(&outMetadata), nil
}

func KeygenMetadataCreateWithExtras(extras []byte, birthday uint64) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	extrasSlice := cGoSlice(extras, pinner)

	var outMetadata C.tss_buffer
	defer C.tss_buffer_free(&outMetadata)

	res := C.frozto_keygen_metadata_create_with_extras(extrasSlice, C.uint64_t(birthday), &outMetadata)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outMetadata), nil
}

func KeygenMetadataParse(metadata []byte) (extras []byte, birthday uint64, err error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	metaSlice := cGoSlice(metadata, pinner)

	var outExtras C.tss_buffer
	defer C.tss_buffer_free(&outExtras)
	var outBirthday C.uint64_t

	res := C.frozto_keygen_metadata_parse(metaSlice, &outExtras, &outBirthday)
	if res != 0 {
		return nil, 0, mapLibError(int(res))
	}

	return copyBuffer(&outExtras), uint64(outBirthday), nil
}

func KeygenMetadataHash(metadata []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	metaSlice := cGoSlice(metadata, pinner)

	var outHash C.tss_buffer
	defer C.tss_buffer_free(&outHash)

	res := C.frozto_keygen_metadata_hash(metaSlice, &outHash)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outHash), nil
}

// Orchard

func OrchardGenerateExtras() ([]byte, error) {
	var outExtras C.tss_buffer
	defer C.tss_buffer_free(&outExtras)

	res := C.frozto_orchard_generate_extras(&outExtras)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outExtras), nil
}

type OrchardKeys struct {
	Address []byte
	Ivk     []byte
}

func OrchardDeriveKeys(pubKeyPackage, orchardExtras []byte) (*OrchardKeys, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	pkp := cGoSlice(pubKeyPackage, pinner)
	extras := cGoSlice(orchardExtras, pinner)

	var outAddr C.tss_buffer
	var outIvk C.tss_buffer
	defer C.tss_buffer_free(&outAddr)
	defer C.tss_buffer_free(&outIvk)

	res := C.frozto_orchard_derive_keys(pkp, extras, &outAddr, &outIvk)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return &OrchardKeys{
		Address: copyBuffer(&outAddr),
		Ivk:     copyBuffer(&outIvk),
	}, nil
}

func OrchardDecryptNoteFull(ivk, nullifier, cmx, epk, encCiphertext []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	ivkSlice := cGoSlice(ivk, pinner)
	nfSlice := cGoSlice(nullifier, pinner)
	cmxSlice := cGoSlice(cmx, pinner)
	epkSlice := cGoSlice(epk, pinner)
	ctSlice := cGoSlice(encCiphertext, pinner)

	var outNoteData C.tss_buffer
	defer C.tss_buffer_free(&outNoteData)

	res := C.frozto_orchard_decrypt_note_full(ivkSlice, nfSlice, cmxSlice, epkSlice, ctSlice, &outNoteData)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outNoteData), nil
}

func OrchardComputeNullifier(pubKeyPackage, orchardExtras, noteData []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	pkpSlice := cGoSlice(pubKeyPackage, pinner)
	extrasSlice := cGoSlice(orchardExtras, pinner)
	ndSlice := cGoSlice(noteData, pinner)

	var outNullifier C.tss_buffer
	defer C.tss_buffer_free(&outNullifier)

	res := C.frozto_orchard_compute_nullifier(pkpSlice, extrasSlice, ndSlice, &outNullifier)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outNullifier), nil
}

func OrchardTryDecryptCompact(ivk, nullifier, cmx, epk, ciphertext []byte) (uint64, bool, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	ivkSlice := cGoSlice(ivk, pinner)
	nfSlice := cGoSlice(nullifier, pinner)
	cmxSlice := cGoSlice(cmx, pinner)
	epkSlice := cGoSlice(epk, pinner)
	ctSlice := cGoSlice(ciphertext, pinner)

	var outValue C.uint64_t

	res := C.frozto_orchard_try_decrypt_compact(ivkSlice, nfSlice, cmxSlice, epkSlice, ctSlice, &outValue)
	if res == C.LIB_ORCHARD_ERROR {
		return 0, false, nil
	}
	if res != 0 {
		return 0, false, mapLibError(int(res))
	}

	return uint64(outValue), true, nil
}

func OrchardBuildFvk(pubKeyPackage, orchardExtras []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	pkp := cGoSlice(pubKeyPackage, pinner)
	extras := cGoSlice(orchardExtras, pinner)

	var outFvk C.tss_buffer
	defer C.tss_buffer_free(&outFvk)

	res := C.frozto_orchard_build_fvk(pkp, extras, &outFvk)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outFvk), nil
}

// Tree

func TreeNew() (TreeHandle, error) {
	var outTree C.Handle

	res := C.frozto_tree_new(&outTree)
	if res != 0 {
		return 0, mapLibError(int(res))
	}

	return TreeHandle(outTree._0), nil
}

func TreeAppend(tree TreeHandle, cmx []byte) error {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cmxSlice := cGoSlice(cmx, pinner)

	res := C.frozto_tree_append(cHandle(Handle(tree)), cmxSlice)
	if res != 0 {
		return mapLibError(int(res))
	}

	return nil
}

func TreeSerialize(tree TreeHandle) ([]byte, error) {
	var outData C.tss_buffer
	defer C.tss_buffer_free(&outData)

	res := C.frozto_tree_serialize(cHandle(Handle(tree)), &outData)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	return copyBuffer(&outData), nil
}

func TreeDeserialize(data []byte) (TreeHandle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	dataSlice := cGoSlice(data, pinner)

	var outTree C.Handle

	res := C.frozto_tree_deserialize(dataSlice, &outTree)
	if res != 0 {
		return 0, mapLibError(int(res))
	}

	return TreeHandle(outTree._0), nil
}

func TreeFree(tree TreeHandle) error {
	res := C.frozto_tree_free(cHandle(Handle(tree)))
	if res != 0 {
		return mapLibError(int(res))
	}
	return nil
}
