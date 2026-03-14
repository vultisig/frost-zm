package fromt

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

func moneroSeed32(t *testing.T) []byte {
	t.Helper()
	seed, err := hex.DecodeString(
		"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1")
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	return seed
}

func u16LEBytes(ids ...uint16) []byte {
	buf := make([]byte, len(ids)*2)
	for i, id := range ids {
		binary.LittleEndian.PutUint16(buf[i*2:], id)
	}
	return buf
}

func encodeID(t *testing.T, id uint16) []byte {
	t.Helper()
	b, err := EncodeIdentifier(id)
	if err != nil {
		t.Fatalf("EncodeIdentifier(%d): %v", id, err)
	}
	return b
}

func runDKG(t *testing.T, n, threshold uint16) (keyShares [][]byte, pubKeys [][]byte) {
	t.Helper()

	type party struct {
		id     uint16
		idB    []byte
		secret *DkgSecretHandle
		r1Pkg  []byte
	}

	parties := make([]party, n)
	for i := uint16(0); i < n; i++ {
		id := i + 1
		secret, pkg, err := DkgPart1(id, n, threshold)
		if err != nil {
			t.Fatalf("DkgPart1 party %d: %v", id, err)
		}
		parties[i] = party{id: id, idB: encodeID(t, id), secret: secret, r1Pkg: pkg}
	}

	type r2Result struct {
		secret *DkgSecretHandle
		r2Pkgs []MapEntry
	}
	r2Results := make([]r2Result, n)

	for i := uint16(0); i < n; i++ {
		var others []MapEntry
		for j := uint16(0); j < n; j++ {
			if j == i {
				continue
			}
			others = append(others, MapEntry{
				ID:    parties[j].idB,
				Value: parties[j].r1Pkg,
			})
		}

		secret, pkgsBytes, err := DkgPart2(parties[i].secret, EncodeMap(others))
		if err != nil {
			t.Fatalf("DkgPart2 party %d: %v", parties[i].id, err)
		}

		entries, decErr := DecodeMap(pkgsBytes)
		if decErr != nil {
			t.Fatalf("DecodeMap r2 party %d: %v", parties[i].id, decErr)
		}
		r2Results[i] = r2Result{secret: secret, r2Pkgs: entries}
	}

	keyShares = make([][]byte, n)
	pubKeys = make([][]byte, n)
	const networkMainnet uint8 = 0

	for i := uint16(0); i < n; i++ {
		var r1Others []MapEntry
		for j := uint16(0); j < n; j++ {
			if j == i {
				continue
			}
			r1Others = append(r1Others, MapEntry{
				ID:    parties[j].idB,
				Value: parties[j].r1Pkg,
			})
		}

		var r2ForMe []MapEntry
		for senderIdx := uint16(0); senderIdx < n; senderIdx++ {
			if senderIdx == i {
				continue
			}
			for _, entry := range r2Results[senderIdx].r2Pkgs {
				decoded, decErr := DecodeIdentifier(entry.ID)
				if decErr != nil {
					t.Fatalf("DecodeIdentifier: %v", decErr)
				}
				if decoded == parties[i].id {
					r2ForMe = append(r2ForMe, MapEntry{
						ID:    parties[senderIdx].idB,
						Value: entry.Value,
					})
				}
			}
		}

		ks, pk, err := DkgPart3(
			r2Results[i].secret,
			EncodeMap(r1Others),
			EncodeMap(r2ForMe),
			networkMainnet,
			0,
		)
		if err != nil {
			t.Fatalf("DkgPart3 party %d: %v", i+1, err)
		}
		keyShares[i] = ks
		pubKeys[i] = pk
	}

	return keyShares, pubKeys
}

func runSign(t *testing.T, keyShares [][]byte, signerIndices []int, message []byte) []byte {
	t.Helper()

	type signerState struct {
		idx    int
		id     uint16
		idB    []byte
		nonces *NoncesHandle
		commit []byte
	}

	signers := make([]signerState, len(signerIndices))
	for i, idx := range signerIndices {
		id := uint16(idx + 1)
		nonces, commitments, err := SignCommit(keyShares[idx])
		if err != nil {
			t.Fatalf("SignCommit signer %d: %v", id, err)
		}
		signers[i] = signerState{idx: idx, id: id, idB: encodeID(t, id), nonces: nonces, commit: commitments}
	}

	var commitEntries []MapEntry
	for _, s := range signers {
		commitEntries = append(commitEntries, MapEntry{
			ID:    s.idB,
			Value: s.commit,
		})
	}

	signingPackage, err := SignCreatePackage(message, EncodeMap(commitEntries))
	if err != nil {
		t.Fatalf("SignCreatePackage: %v", err)
	}

	var shareEntries []MapEntry
	for _, s := range signers {
		share, signErr := Sign(signingPackage, s.nonces, keyShares[s.idx])
		if signErr != nil {
			t.Fatalf("Sign signer %d: %v", s.id, signErr)
		}
		shareEntries = append(shareEntries, MapEntry{
			ID:    s.idB,
			Value: share,
		})
	}

	signature, err := SignAggregate(signingPackage, EncodeMap(shareEntries), keyShares[signerIndices[0]])
	if err != nil {
		t.Fatalf("SignAggregate: %v", err)
	}

	return signature
}

type keyImportResult struct {
	keyShares [][]byte
	pubKeys   [][]byte
	vk        []byte
}

func runKeyImport(t *testing.T, n, threshold uint16, spendKey []byte) keyImportResult {
	t.Helper()

	type party struct {
		id     uint16
		idB    []byte
		secret *DkgSecretHandle
		r1Pkg  []byte
	}

	parties := make([]party, n)
	for i := uint16(0); i < n; i++ {
		id := i + 1
		var sk []byte
		if id == 1 {
			sk = spendKey
		}
		secret, pkg, err := KeyImportPart1(id, n, threshold, sk)
		if err != nil {
			t.Fatalf("KeyImportPart1 party %d: %v", id, err)
		}
		parties[i] = party{id: id, idB: encodeID(t, id), secret: secret, r1Pkg: pkg}
	}

	type r2Result struct {
		secret *DkgSecretHandle
		r2Pkgs []MapEntry
	}
	r2Results := make([]r2Result, n)

	for i := uint16(0); i < n; i++ {
		var others []MapEntry
		for j := uint16(0); j < n; j++ {
			if j == i {
				continue
			}
			others = append(others, MapEntry{
				ID:    parties[j].idB,
				Value: parties[j].r1Pkg,
			})
		}

		secret, pkgsBytes, err := DkgPart2(parties[i].secret, EncodeMap(others))
		if err != nil {
			t.Fatalf("DkgPart2 party %d: %v", parties[i].id, err)
		}

		entries, decErr := DecodeMap(pkgsBytes)
		if decErr != nil {
			t.Fatalf("DecodeMap r2 party %d: %v", parties[i].id, decErr)
		}
		r2Results[i] = r2Result{secret: secret, r2Pkgs: entries}
	}

	vk, err := SpendKeyToPublic(spendKey)
	if err != nil {
		t.Fatalf("SpendKeyToPublic: %v", err)
	}

	kss := make([][]byte, n)
	pks := make([][]byte, n)
	const networkMainnet uint8 = 0

	for i := uint16(0); i < n; i++ {
		var r1Others []MapEntry
		for j := uint16(0); j < n; j++ {
			if j == i {
				continue
			}
			r1Others = append(r1Others, MapEntry{
				ID:    parties[j].idB,
				Value: parties[j].r1Pkg,
			})
		}

		var r2ForMe []MapEntry
		for senderIdx := uint16(0); senderIdx < n; senderIdx++ {
			if senderIdx == i {
				continue
			}
			for _, entry := range r2Results[senderIdx].r2Pkgs {
				decoded, decErr := DecodeIdentifier(entry.ID)
				if decErr != nil {
					t.Fatalf("DecodeIdentifier: %v", decErr)
				}
				if decoded == parties[i].id {
					r2ForMe = append(r2ForMe, MapEntry{
						ID:    parties[senderIdx].idB,
						Value: entry.Value,
					})
				}
			}
		}

		ks, pk, importErr := KeyImportPart3(
			r2Results[i].secret,
			EncodeMap(r1Others),
			EncodeMap(r2ForMe),
			vk,
			networkMainnet,
			0,
		)
		if importErr != nil {
			t.Fatalf("KeyImportPart3 party %d: %v", i+1, importErr)
		}
		kss[i] = ks
		pks[i] = pk
	}

	return keyImportResult{keyShares: kss, pubKeys: pks, vk: vk}
}

func runReshare(t *testing.T, oldKSs [][]byte, newN, newT uint16, oldIDs []uint16) (keyShares [][]byte, pubKeys [][]byte) {
	t.Helper()

	pk, err := KeySharePublicKey(oldKSs[0])
	if err != nil {
		t.Fatalf("KeySharePublicKey: %v", err)
	}

	oldIDBytes := u16LEBytes(oldIDs...)

	type party struct {
		id     uint16
		idB    []byte
		secret *DkgSecretHandle
		r1Pkg  []byte
	}

	parties := make([]party, newN)
	for i := uint16(0); i < newN; i++ {
		id := i + 1
		var oldKS []byte
		if containsU16(oldIDs, id) {
			oldKS = oldKSs[id-1]
		}
		secret, pkg, reshareErr := ResharePart1(id, newN, newT, oldKS, oldIDBytes)
		if reshareErr != nil {
			t.Fatalf("ResharePart1 party %d: %v", id, reshareErr)
		}
		parties[i] = party{id: id, idB: encodeID(t, id), secret: secret, r1Pkg: pkg}
	}

	type r2Result struct {
		secret *DkgSecretHandle
		r2Pkgs []MapEntry
	}
	r2Results := make([]r2Result, newN)

	for i := uint16(0); i < newN; i++ {
		var others []MapEntry
		for j := uint16(0); j < newN; j++ {
			if j == i {
				continue
			}
			others = append(others, MapEntry{
				ID:    parties[j].idB,
				Value: parties[j].r1Pkg,
			})
		}

		secret, pkgsBytes, dkgErr := DkgPart2(parties[i].secret, EncodeMap(others))
		if dkgErr != nil {
			t.Fatalf("DkgPart2 party %d: %v", parties[i].id, dkgErr)
		}

		entries, decErr := DecodeMap(pkgsBytes)
		if decErr != nil {
			t.Fatalf("DecodeMap r2 party %d: %v", parties[i].id, decErr)
		}
		r2Results[i] = r2Result{secret: secret, r2Pkgs: entries}
	}

	keyShares = make([][]byte, newN)
	pubKeys = make([][]byte, newN)
	const networkMainnet uint8 = 0

	for i := uint16(0); i < newN; i++ {
		var r1Others []MapEntry
		for j := uint16(0); j < newN; j++ {
			if j == i {
				continue
			}
			r1Others = append(r1Others, MapEntry{
				ID:    parties[j].idB,
				Value: parties[j].r1Pkg,
			})
		}

		var r2ForMe []MapEntry
		for senderIdx := uint16(0); senderIdx < newN; senderIdx++ {
			if senderIdx == i {
				continue
			}
			for _, entry := range r2Results[senderIdx].r2Pkgs {
				decoded, decErr := DecodeIdentifier(entry.ID)
				if decErr != nil {
					t.Fatalf("DecodeIdentifier: %v", decErr)
				}
				if decoded == parties[i].id {
					r2ForMe = append(r2ForMe, MapEntry{
						ID:    parties[senderIdx].idB,
						Value: entry.Value,
					})
				}
			}
		}

		ks, pubkey, reshareErr := ResharePart3(
			r2Results[i].secret,
			EncodeMap(r1Others),
			EncodeMap(r2ForMe),
			pk,
			networkMainnet,
			0,
		)
		if reshareErr != nil {
			t.Fatalf("ResharePart3 party %d: %v", i+1, reshareErr)
		}
		keyShares[i] = ks
		pubKeys[i] = pubkey
	}

	return keyShares, pubKeys
}

func containsU16(slice []uint16, val uint16) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func TestFullFlow(t *testing.T) {
	n := uint16(3)
	threshold := uint16(2)

	t.Log("=== DKG ===")
	keyShares, _ := runDKG(t, n, threshold)

	pk, err := KeySharePublicKey(keyShares[0])
	if err != nil {
		t.Fatalf("KeySharePublicKey: %v", err)
	}
	t.Logf("group public key: %x", pk)

	for i, ks := range keyShares {
		id, idErr := KeyShareIdentifier(ks)
		if idErr != nil {
			t.Fatalf("KeyShareIdentifier %d: %v", i, idErr)
		}
		t.Logf("party %d identifier: %d", i, id)
	}

	t.Log("=== Sign (parties 0,1) ===")
	msg := []byte("hello monero fromt")
	sig := runSign(t, keyShares, []int{0, 1}, msg)
	t.Logf("signature: %x (%d bytes)", sig, len(sig))

	t.Log("=== Sign (parties 1,2) ===")
	sig2 := runSign(t, keyShares, []int{1, 2}, msg)
	t.Logf("signature: %x (%d bytes)", sig2, len(sig2))

	t.Log("=== All operations successful ===")
}

func TestKeyImportBachelor(t *testing.T) {
	seedHex := os.Getenv("FROMT_SEED_HEX")
	if seedHex == "" {
		t.Skip("FROMT_SEED_HEX not set")
	}
	expectedAddr := os.Getenv("FROMT_EXPECTED_ADDRESS")

	importSeed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}

	sk, vk, err := DeriveKeysFromSeed(importSeed)
	if err != nil {
		t.Fatalf("DeriveKeysFromSeed: %v", err)
	}
	t.Logf("spend key: %x", sk)
	t.Logf("view key:  %x", vk)

	result := runKeyImport(t, 3, 2, sk)

	addr, addrErr := DeriveAddress(result.keyShares[0])
	if addrErr != nil {
		t.Fatalf("DeriveAddress: %v", addrErr)
	}
	t.Logf("threshold address: %s", addr)

	if expectedAddr != "" && addr != expectedAddr {
		t.Fatalf("address mismatch:\n  got:    %s\n  expect: %s", addr, expectedAddr)
	}
	t.Log("threshold address matches expected")
}

func TestKeyImport(t *testing.T) {
	seed := moneroSeed32(t)

	sk, vk, err := DeriveKeysFromSeed(seed)
	if err != nil {
		t.Fatalf("DeriveKeysFromSeed: %v", err)
	}
	t.Logf("spend key: %x (%d bytes)", sk, len(sk))
	t.Logf("view key:  %x (%d bytes)", vk, len(vk))

	t.Log("=== Key Import 2-of-3 ===")
	result := runKeyImport(t, 3, 2, sk)

	importedPK, err := KeySharePublicKey(result.keyShares[0])
	if err != nil {
		t.Fatalf("KeySharePublicKey: %v", err)
	}
	expectedPK, err := SpendKeyToPublic(sk)
	if err != nil {
		t.Fatalf("SpendKeyToPublic: %v", err)
	}
	if !bytes.Equal(importedPK, expectedPK) {
		t.Fatal("public key mismatch after import")
	}

	t.Log("=== Derive address ===")
	addr, err := DeriveAddress(result.keyShares[0])
	if err != nil {
		t.Fatalf("DeriveAddress: %v", err)
	}
	t.Logf("monero address: %s", addr)
	if len(addr) < 10 {
		t.Fatalf("address too short: %s", addr)
	}

	t.Log("=== Sign (parties 0,1) ===")
	msg := []byte("hello monero key import")
	runSign(t, result.keyShares, []int{0, 1}, msg)

	t.Log("=== Sign (parties 1,2) ===")
	runSign(t, result.keyShares, []int{1, 2}, msg)

	t.Log("=== All key import operations successful ===")
}

func TestReshare(t *testing.T) {
	msg := []byte("hello monero reshare")

	t.Log("=== DKG 2-of-2 ===")
	kss2, _ := runDKG(t, 2, 2)

	pk2, err := KeySharePublicKey(kss2[0])
	if err != nil {
		t.Fatalf("KeySharePublicKey: %v", err)
	}

	t.Log("=== Sign 2-of-2 (parties 0,1) ===")
	runSign(t, kss2, []int{0, 1}, msg)

	t.Log("=== Reshare 2-of-2 → 2-of-3 ===")
	kss3, _ := runReshare(t, kss2, 3, 2, []uint16{1, 2})

	pk3, err := KeySharePublicKey(kss3[0])
	if err != nil {
		t.Fatalf("KeySharePublicKey: %v", err)
	}
	if !bytes.Equal(pk2, pk3) {
		t.Fatal("public key changed after reshare 2-of-2 → 2-of-3")
	}

	t.Log("=== Sign 2-of-3 (parties 0,1) ===")
	runSign(t, kss3, []int{0, 1}, msg)
	t.Log("=== Sign 2-of-3 (parties 1,2) ===")
	runSign(t, kss3, []int{1, 2}, msg)

	t.Log("=== Reshare 2-of-3 → 3-of-4 ===")
	kss4, _ := runReshare(t, kss3, 4, 3, []uint16{1, 2, 3})

	pk4, err := KeySharePublicKey(kss4[0])
	if err != nil {
		t.Fatalf("KeySharePublicKey: %v", err)
	}
	if !bytes.Equal(pk2, pk4) {
		t.Fatal("public key changed after reshare 2-of-3 → 3-of-4")
	}

	t.Log("=== Sign 3-of-4 (parties 0,1,2) ===")
	runSign(t, kss4, []int{0, 1, 2}, msg)
	t.Log("=== Sign 3-of-4 (parties 1,2,3) ===")
	runSign(t, kss4, []int{1, 2, 3}, msg)

	t.Log("=== All reshare operations successful ===")
}

func TestKeyShareBundleHelpers(t *testing.T) {
	keyShares, _ := runDKG(t, 3, 2)

	keyPackage, err := KeyShareBundleKeyPackage(keyShares[0])
	if err != nil {
		t.Fatalf("KeyShareBundleKeyPackage: %v", err)
	}
	pubKeyPackage, err := KeyShareBundlePubKeyPackage(keyShares[0])
	if err != nil {
		t.Fatalf("KeyShareBundlePubKeyPackage: %v", err)
	}
	viewKey, err := KeyShareViewKey(keyShares[0])
	if err != nil {
		t.Fatalf("KeyShareViewKey: %v", err)
	}
	network, err := KeyShareNetwork(keyShares[0])
	if err != nil {
		t.Fatalf("KeyShareNetwork: %v", err)
	}
	birthday, err := KeyShareBirthday(keyShares[0])
	if err != nil {
		t.Fatalf("KeyShareBirthday: %v", err)
	}

	repacked, err := KeyShareBundlePack(keyPackage, pubKeyPackage, viewKey, network, birthday)
	if err != nil {
		t.Fatalf("KeyShareBundlePack: %v", err)
	}
	if !bytes.Equal(repacked, keyShares[0]) {
		t.Fatal("repacked keyshare bundle mismatch")
	}
}

func TestAddressDerivation(t *testing.T) {
	keyShares, _ := runDKG(t, 3, 2)

	addr, err := DeriveAddress(keyShares[0])
	if err != nil {
		t.Fatalf("DeriveAddress: %v", err)
	}
	t.Logf("main address: %s", addr)

	addr2, err := DeriveAddress(keyShares[1])
	if err != nil {
		t.Fatalf("DeriveAddress party 2: %v", err)
	}
	if addr != addr2 {
		t.Fatal("addresses should be the same for different key shares of the same group")
	}

	subAddr, err := DeriveSubaddress(keyShares[0], 0, 1)
	if err != nil {
		t.Fatalf("DeriveSubaddress: %v", err)
	}
	t.Logf("subaddress(0,1): %s", subAddr)
	if subAddr == addr {
		t.Fatal("subaddress should differ from main address")
	}
}

type ckdEntry struct {
	id   uint16
	data []byte
}

func encodeCkdPackages(entries []ckdEntry) []byte {
	var buf []byte
	countBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(countBytes, uint32(len(entries)))
	buf = append(buf, countBytes...)
	for _, e := range entries {
		idBytes := make([]byte, 2)
		binary.LittleEndian.PutUint16(idBytes, e.id)
		buf = append(buf, idBytes...)
		lenBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBytes, uint32(len(e.data)))
		buf = append(buf, lenBytes...)
		buf = append(buf, e.data...)
	}
	return buf
}

func encodeKeyImageOutputs(outputs [][64]byte) []byte {
	var buf []byte
	countBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(countBytes, uint32(len(outputs)))
	buf = append(buf, countBytes...)
	for _, o := range outputs {
		buf = append(buf, o[:]...)
	}
	return buf
}

func makeTestOutput(seed byte) [64]byte {
	var out [64]byte
	var seedArr [32]byte
	seedArr[0] = seed
	copy(out[0:32], seedArr[:])
	copy(out[32:64], seedArr[:])
	out[32] = seed + 42
	return out
}

func runKeyImageSession(t *testing.T, keyShares [][]byte, signerIndices []int, outputsData []byte) [][]byte {
	t.Helper()

	parties := make([]PartyInfo, len(signerIndices))
	for i, idx := range signerIndices {
		parties[i] = PartyInfo{
			FrostID: uint16(idx + 1),
			Name:    []byte(fmt.Sprintf("party-%d", idx+1)),
		}
	}

	setup, err := KeyImageSetupMsgNew(parties, outputsData)
	if err != nil {
		t.Fatalf("KeyImageSetupMsgNew: %v", err)
	}

	sessions := make([]*SessionHandle, len(signerIndices))
	for i, idx := range signerIndices {
		name := []byte(fmt.Sprintf("party-%d", idx+1))
		s, sessionErr := KeyImageSessionFromSetup(setup, name, keyShares[idx])
		if sessionErr != nil {
			t.Fatalf("KeyImageSessionFromSetup party %d: %v", idx+1, sessionErr)
		}
		sessions[i] = s
	}

	finished := make([]bool, len(sessions))
	for round := 0; round < 50; round++ {
		allDone := true
		for _, f := range finished {
			if !f {
				allDone = false
				break
			}
		}
		if allDone {
			break
		}

		type outMsg struct {
			senderIdx int
			msg       []byte
		}
		var outgoing []outMsg

		for i, s := range sessions {
			for {
				msg, takeErr := KeyImageSessionTakeMsg(s)
				if takeErr != nil {
					t.Fatalf("KeyImageSessionTakeMsg: %v", takeErr)
				}
				if len(msg) == 0 {
					break
				}
				outgoing = append(outgoing, outMsg{senderIdx: i, msg: msg})
			}
		}

		for _, om := range outgoing {
			senderID := uint16(signerIndices[om.senderIdx] + 1)
			recipient := binary.LittleEndian.Uint16(om.msg[:2])
			payload := om.msg[2:]

			for targetIdx := range sessions {
				if targetIdx == om.senderIdx {
					continue
				}
				targetID := uint16(signerIndices[targetIdx] + 1)
				if recipient != 0 && recipient != targetID {
					continue
				}
				if finished[targetIdx] {
					continue
				}

				input := make([]byte, 2+len(payload))
				binary.LittleEndian.PutUint16(input[:2], senderID)
				copy(input[2:], payload)

				done, feedErr := KeyImageSessionFeed(sessions[targetIdx], input)
				if feedErr != nil {
					t.Fatalf("KeyImageSessionFeed: %v", feedErr)
				}
				if done {
					finished[targetIdx] = true
				}
			}
		}
	}

	for i, f := range finished {
		if !f {
			t.Fatalf("party %d did not finish key image session", signerIndices[i]+1)
		}
	}

	var results [][]byte
	for i, s := range sessions {
		ki, resErr := KeyImageSessionResult(s)
		if resErr != nil {
			t.Fatalf("KeyImageSessionResult party %d: %v", signerIndices[i]+1, resErr)
		}
		results = append(results, ki)
	}

	return results
}

func TestKeyImage(t *testing.T) {
	keyShares, _ := runDKG(t, 3, 2)

	out1 := makeTestOutput(7)
	out2 := makeTestOutput(13)
	outputsData := encodeKeyImageOutputs([][64]byte{out1, out2})

	t.Log("=== Key image session (parties 1,2) ===")
	results12 := runKeyImageSession(t, keyShares, []int{0, 1}, outputsData)
	if len(results12[0]) != 64 {
		t.Fatalf("expected 64 bytes (2 key images), got %d", len(results12[0]))
	}
	if !bytes.Equal(results12[0], results12[1]) {
		t.Fatal("key images from different parties should match")
	}
	t.Logf("key image 1: %x", results12[0][:32])
	t.Logf("key image 2: %x", results12[0][32:])

	t.Log("=== Key image session (parties 2,3) ===")
	results23 := runKeyImageSession(t, keyShares, []int{1, 2}, outputsData)
	if !bytes.Equal(results12[0], results23[0]) {
		t.Fatal("key images should be the same regardless of signer set")
	}

	t.Log("=== Key image session passed ===")
}

func TestCKD(t *testing.T) {
	keyShares, _ := runDKG(t, 3, 2)

	signerIDs := u16LEBytes(1, 2)

	state1, pkg1, err := CkdPart1(keyShares[0], 0, 1, signerIDs)
	if err != nil {
		t.Fatalf("CkdPart1 party 1: %v", err)
	}

	state2, pkg2, err := CkdPart1(keyShares[1], 0, 1, signerIDs)
	if err != nil {
		t.Fatalf("CkdPart1 party 2: %v", err)
	}

	r1For1 := encodeCkdPackages([]ckdEntry{{id: 2, data: pkg2}})
	r1For2 := encodeCkdPackages([]ckdEntry{{id: 1, data: pkg1}})

	child1, err := CkdPart2(state1, r1For1)
	if err != nil {
		t.Fatalf("CkdPart2 party 1: %v", err)
	}

	child2, err := CkdPart2(state2, r1For2)
	if err != nil {
		t.Fatalf("CkdPart2 party 2: %v", err)
	}

	if len(child1) == 0 || len(child2) == 0 {
		t.Fatal("child key shares should not be empty")
	}

	t.Logf("child key share 1: %d bytes", len(child1))
	t.Logf("child key share 2: %d bytes", len(child2))
}

func TestKeyShareInspection(t *testing.T) {
	keyShares, _ := runDKG(t, 3, 2)

	pk, err := KeySharePublicKey(keyShares[0])
	if err != nil {
		t.Fatalf("KeySharePublicKey: %v", err)
	}
	if len(pk) == 0 {
		t.Fatal("public key should not be empty")
	}
	t.Logf("public key: %x (%d bytes)", pk, len(pk))

	vk, err := KeyShareViewKey(keyShares[0])
	if err != nil {
		t.Fatalf("KeyShareViewKey: %v", err)
	}
	if len(vk) == 0 {
		t.Fatal("view key should not be empty")
	}
	t.Logf("view key: %x (%d bytes)", vk, len(vk))

	birthday, err := KeyShareBirthday(keyShares[0])
	if err != nil {
		t.Fatalf("KeyShareBirthday: %v", err)
	}
	t.Logf("birthday: %d", birthday)

	id, err := KeyShareIdentifier(keyShares[0])
	if err != nil {
		t.Fatalf("KeyShareIdentifier: %v", err)
	}
	if id != 1 {
		t.Fatalf("expected identifier 1, got %d", id)
	}

	pk2, err := KeySharePublicKey(keyShares[1])
	if err != nil {
		t.Fatalf("KeySharePublicKey party 2: %v", err)
	}
	if !bytes.Equal(pk, pk2) {
		t.Fatal("public keys should match across shares")
	}
}

func TestIdentifierEncoding(t *testing.T) {
	for _, id := range []uint16{1, 2, 3, 100, 255} {
		encoded, err := EncodeIdentifier(id)
		if err != nil {
			t.Fatalf("EncodeIdentifier(%d): %v", id, err)
		}
		decoded, err := DecodeIdentifier(encoded)
		if err != nil {
			t.Fatalf("DecodeIdentifier(%d): %v", id, err)
		}
		if decoded != id {
			t.Fatalf("roundtrip failed: %d → %x → %d", id, encoded, decoded)
		}
	}
}

func TestDeriveKeysFromSeed(t *testing.T) {
	seed := moneroSeed32(t)

	sk1, vk1, err := DeriveKeysFromSeed(seed)
	if err != nil {
		t.Fatalf("DeriveKeysFromSeed: %v", err)
	}

	sk2, vk2, err := DeriveKeysFromSeed(seed)
	if err != nil {
		t.Fatalf("DeriveKeysFromSeed (2nd): %v", err)
	}

	if !bytes.Equal(sk1, sk2) {
		t.Fatal("spend key should be deterministic")
	}
	if !bytes.Equal(vk1, vk2) {
		t.Fatal("view key should be deterministic")
	}

	if len(sk1) != 32 {
		t.Fatalf("expected 32-byte spend key, got %d", len(sk1))
	}
	if len(vk1) != 32 {
		t.Fatalf("expected 32-byte view key, got %d", len(vk1))
	}

	pk, err := SpendKeyToPublic(sk1)
	if err != nil {
		t.Fatalf("SpendKeyToPublic: %v", err)
	}
	if len(pk) != 32 {
		t.Fatalf("expected 32-byte public key, got %d", len(pk))
	}
	t.Logf("spend key: %x", sk1)
	t.Logf("view key:  %x", vk1)
	t.Logf("public key: %x", pk)
}

func TestSignatureVerification(t *testing.T) {
	n := uint16(3)
	threshold := uint16(2)

	keyShares, _ := runDKG(t, n, threshold)

	msg := []byte("verify me on monero mainnet")

	t.Log("=== Sign + Verify (parties 0,1) ===")
	sig01 := runSign(t, keyShares, []int{0, 1}, msg)
	err := VerifySignature(msg, sig01, keyShares[0])
	if err != nil {
		t.Fatalf("VerifySignature (0,1): %v", err)
	}

	t.Log("=== Sign + Verify (parties 1,2) ===")
	sig12 := runSign(t, keyShares, []int{1, 2}, msg)
	err = VerifySignature(msg, sig12, keyShares[1])
	if err != nil {
		t.Fatalf("VerifySignature (1,2): %v", err)
	}

	t.Log("=== Sign + Verify (parties 0,2) ===")
	sig02 := runSign(t, keyShares, []int{0, 2}, msg)
	err = VerifySignature(msg, sig02, keyShares[0])
	if err != nil {
		t.Fatalf("VerifySignature (0,2): %v", err)
	}

	t.Log("=== Verify wrong message fails ===")
	wrongMsg := []byte("wrong message")
	err = VerifySignature(wrongMsg, sig01, keyShares[0])
	if err == nil {
		t.Fatal("expected verification to fail with wrong message")
	}

	t.Log("=== Verify with any key share of same group ===")
	err = VerifySignature(msg, sig01, keyShares[2])
	if err != nil {
		t.Fatalf("VerifySignature with different key share of same group: %v", err)
	}

	t.Log("=== All signature verification tests passed ===")
}

func TestSighashDryRun(t *testing.T) {
	seed := moneroSeed32(t)
	sk, _, err := DeriveKeysFromSeed(seed)
	if err != nil {
		t.Fatalf("DeriveKeysFromSeed: %v", err)
	}

	result := runKeyImport(t, 3, 2, sk)

	t.Log("=== Sign synthetic sighash ===")
	sighash := make([]byte, 32)
	sighash[0] = 0xDE
	sighash[15] = 0xAD
	sighash[31] = 0xBE

	sig := runSign(t, result.keyShares, []int{0, 1}, sighash)
	err = VerifySignature(sighash, sig, result.keyShares[0])
	if err != nil {
		t.Fatalf("sighash signature verification failed: %v", err)
	}

	sig2 := runSign(t, result.keyShares, []int{1, 2}, sighash)
	err = VerifySignature(sighash, sig2, result.keyShares[1])
	if err != nil {
		t.Fatalf("sighash signature verification (1,2) failed: %v", err)
	}

	t.Log("=== Verify address derivation ===")
	addr, err := DeriveAddress(result.keyShares[0])
	if err != nil {
		t.Fatalf("DeriveAddress: %v", err)
	}
	t.Logf("monero address: %s", addr)
	if len(addr) < 90 {
		t.Fatalf("address too short: %s", addr)
	}

	t.Log("=== Sighash dry run passed ===")
}

func TestKeyImportSetupRoundtrip(t *testing.T) {
	seed := moneroSeed32(t)
	sk, _, err := DeriveKeysFromSeed(seed)
	if err != nil {
		t.Fatalf("DeriveKeysFromSeed: %v", err)
	}

	parties := []PartyInfo{
		{FrostID: 1, Name: []byte("alice")},
		{FrostID: 2, Name: []byte("bob")},
		{FrostID: 3, Name: []byte("charlie")},
	}

	setup, err := KeyImportSetupMsgNew(3, 2, parties, 0, 12345, 1, sk)
	if err != nil {
		t.Fatalf("KeyImportSetupMsgNew: %v", err)
	}
	t.Logf("setup message: %d bytes", len(setup))

	session, err := KeyImportSessionFromSetup(setup, []byte("bob"))
	if err != nil {
		t.Fatalf("KeyImportSessionFromSetup: %v", err)
	}
	defer session.Close()

	t.Log("roundtrip OK")
}

func TestHandleClose(t *testing.T) {
	secret, _, err := DkgPart1(1, 3, 2)
	if err != nil {
		t.Fatalf("DkgPart1: %v", err)
	}

	err = secret.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}

	err = secret.Close()
	if err == nil {
		t.Fatal("double Close should return error")
	}
}
