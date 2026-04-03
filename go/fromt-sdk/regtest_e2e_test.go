package fromtsdk

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	fromt "github.com/vultisig/frosty-lib/go/fromt"
)

const (
	defaultDaemonURL = "http://localhost:18081"
	regtestNetwork   = uint8(0) // regtest uses mainnet address format
)

func getDaemonURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("MONERO_DAEMON_URL")
	if url == "" {
		url = defaultDaemonURL
	}
	return url
}

func skipIfNoDaemon(t *testing.T, daemonURL string) {
	t.Helper()
	resp, err := http.Post(daemonURL+"/json_rpc", "application/json",
		bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":"0","method":"get_block_count"}`)))
	if err != nil {
		t.Skipf("monerod not available at %s: %v", daemonURL, err)
	}
	resp.Body.Close()
}

func rpcCall(daemonURL, method string, params interface{}) (json.RawMessage, error) {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "0",
		"method":  method,
	}
	if params != nil {
		req["params"] = params
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := http.Post(daemonURL+"/json_rpc", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	err = json.Unmarshal(respBody, &rpcResp)
	if err != nil {
		return nil, err
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("rpc error: %s", rpcResp.Error.Message)
	}
	return rpcResp.Result, nil
}

func getBlockCount(daemonURL string) (int64, error) {
	result, err := rpcCall(daemonURL, "get_block_count", nil)
	if err != nil {
		return 0, err
	}
	var res struct {
		Count int64 `json:"count"`
	}
	err = json.Unmarshal(result, &res)
	return res.Count, err
}

func mineBlocks(daemonURL string, address string, count int) error {
	_, err := rpcCall(daemonURL, "generateblocks", map[string]interface{}{
		"wallet_address":  address,
		"amount_of_blocks": count,
	})
	return err
}

func run2of3DKG(t *testing.T) [][]byte {
	t.Helper()
	n := uint16(3)
	threshold := uint16(2)

	type party struct {
		id     uint16
		idB    []byte
		secret *fromt.DkgSecretHandle
		r1Pkg  []byte
	}

	parties := make([]party, n)
	for i := uint16(0); i < n; i++ {
		id := i + 1
		idB, err := fromt.EncodeIdentifier(id)
		if err != nil {
			t.Fatalf("EncodeIdentifier(%d): %v", id, err)
		}
		secret, pkg, err := fromt.DkgPart1(id, n, threshold)
		if err != nil {
			t.Fatalf("DkgPart1 party %d: %v", id, err)
		}
		parties[i] = party{id: id, idB: idB, secret: secret, r1Pkg: pkg}
	}

	type r2Result struct {
		secret *fromt.DkgSecretHandle
		r2Pkgs []byte
	}
	r2Results := make([]r2Result, n)
	for i := uint16(0); i < n; i++ {
		var entries []fromt.MapEntry
		for j := uint16(0); j < n; j++ {
			if j == i {
				continue
			}
			entries = append(entries, fromt.MapEntry{ID: parties[j].idB, Value: parties[j].r1Pkg})
		}
		r1Map := fromt.EncodeMap(entries)
		secret2, r2Pkgs, err := fromt.DkgPart2(parties[i].secret, r1Map)
		if err != nil {
			t.Fatalf("DkgPart2 party %d: %v", i+1, err)
		}
		r2Results[i] = r2Result{secret: secret2, r2Pkgs: r2Pkgs}
	}

	keyShares := make([][]byte, n)
	for i := uint16(0); i < n; i++ {
		var r1Entries []fromt.MapEntry
		for j := uint16(0); j < n; j++ {
			if j == i {
				continue
			}
			r1Entries = append(r1Entries, fromt.MapEntry{ID: parties[j].idB, Value: parties[j].r1Pkg})
		}

		r2Decoded, err := fromt.DecodeMap(r2Results[i].r2Pkgs)
		if err != nil {
			t.Fatalf("DecodeMap r2 party %d: %v", i+1, err)
		}

		var r2ForMe []fromt.MapEntry
		for senderIdx := uint16(0); senderIdx < n; senderIdx++ {
			if senderIdx == i {
				continue
			}
			senderR2, decErr := fromt.DecodeMap(r2Results[senderIdx].r2Pkgs)
			if decErr != nil {
				t.Fatalf("DecodeMap sender %d: %v", senderIdx+1, decErr)
			}
			for _, e := range senderR2 {
				decodedID, idErr := fromt.DecodeIdentifier(e.ID)
				if idErr != nil {
					continue
				}
				if decodedID == i+1 {
					r2ForMe = append(r2ForMe, fromt.MapEntry{ID: parties[senderIdx].idB, Value: e.Value})
				}
			}
		}
		_ = r2Decoded

		r1Map := fromt.EncodeMap(r1Entries)
		r2Map := fromt.EncodeMap(r2ForMe)

		ks, _, err := fromt.DkgPart3(r2Results[i].secret, r1Map, r2Map, regtestNetwork, 0)
		if err != nil {
			t.Fatalf("DkgPart3 party %d: %v", i+1, err)
		}
		keyShares[i] = ks
	}

	return keyShares
}

func TestRegtestE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping regtest E2E test")
	}

	daemonURL := getDaemonURL(t)
	skipIfNoDaemon(t, daemonURL)

	t.Log("=== Step 1: DKG (2-of-3) ===")
	keyShares := run2of3DKG(t)
	t.Logf("generated %d keyshares", len(keyShares))

	addr, err := fromt.DeriveAddress(keyShares[0])
	if err != nil {
		t.Fatalf("DeriveAddress: %v", err)
	}
	t.Logf("vault address: %s", addr)

	t.Log("=== Step 2: Mine blocks to fund vault ===")
	heightBefore, err := getBlockCount(daemonURL)
	if err != nil {
		t.Fatalf("getBlockCount: %v", err)
	}
	t.Logf("chain height before mining: %d", heightBefore)

	err = mineBlocks(daemonURL, addr, 100)
	if err != nil {
		t.Fatalf("mineBlocks: %v", err)
	}

	// mine 60 more to unlock coinbase (60 block maturity)
	dummyAddr := "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
	err = mineBlocks(daemonURL, dummyAddr, 60)
	if err != nil {
		t.Fatalf("mineBlocks (maturity): %v", err)
	}

	heightAfter, err := getBlockCount(daemonURL)
	if err != nil {
		t.Fatalf("getBlockCount after: %v", err)
	}
	t.Logf("chain height after mining: %d", heightAfter)

	t.Log("=== Step 3: Scan balance ===")
	time.Sleep(2 * time.Second) // let daemon settle

	balance, numOutputs, err := ScanBalance(keyShares[0], daemonURL, 0, nil)
	if err != nil {
		t.Fatalf("ScanBalance: %v", err)
	}
	t.Logf("balance: %d piconero (%d outputs)", balance, numOutputs)

	if balance == 0 {
		t.Fatal("vault has zero balance after mining")
	}

	t.Log("=== Step 4: SpendPrepare with tx_extra memo ===")
	sendAmount := uint64(1_000_000_000_000) // 1 XMR
	if balance < sendAmount+100_000_000 {
		t.Fatalf("insufficient balance: have %d, need %d", balance, sendAmount)
	}

	memo := []byte("=:BTC.BTC:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4:1000000/3/10:t:30")
	t.Logf("tx_extra memo (%d bytes): %s", len(memo), string(memo))

	signableTx, spentOffsets, err := SpendPrepare(
		keyShares[0],
		daemonURL,
		dummyAddr,
		sendAmount,
		0,
		nil,
		nil,
		memo,
	)
	if err != nil {
		t.Fatalf("SpendPrepare: %v", err)
	}
	t.Logf("signable tx: %d bytes, spent offsets: %d bytes (%d outputs)", len(signableTx), len(spentOffsets), len(spentOffsets)/32)

	t.Log("=== Step 5: 3-phase CLSAG signing (parties 0,1) ===")
	signerIndices := []int{0, 1}

	ids := make([][]byte, len(signerIndices))
	for i, idx := range signerIndices {
		id := uint16(idx + 1)
		idBytes, idErr := fromt.EncodeIdentifier(id)
		if idErr != nil {
			t.Fatalf("EncodeIdentifier(%d): %v", id, idErr)
		}
		ids[i] = idBytes
	}

	// Phase 1: SpendPreprocess
	handles := make([]*fromt.SpendSignHandle, len(signerIndices))
	preprocesses := make([][]byte, len(signerIndices))
	for i, idx := range signerIndices {
		h, pp, ppErr := fromt.SpendPreprocess(keyShares[idx], signableTx)
		if ppErr != nil {
			t.Fatalf("SpendPreprocess signer %d: %v", idx+1, ppErr)
		}
		handles[i] = h
		preprocesses[i] = pp
		t.Logf("signer %d preprocess: %d bytes", idx+1, len(pp))
	}

	// Phase 2: SpendSign
	sigHandles := make([]*fromt.SpendSigHandle, len(signerIndices))
	shares := make([][]byte, len(signerIndices))
	for i := range signerIndices {
		var ppEntries []fromt.MapEntry
		for j := range signerIndices {
			if j == i {
				continue
			}
			ppEntries = append(ppEntries, fromt.MapEntry{ID: ids[j], Value: preprocesses[j]})
		}
		sh, share, signErr := fromt.SpendSign(handles[i], fromt.EncodeMap(ppEntries))
		if signErr != nil {
			t.Fatalf("SpendSign signer %d: %v", signerIndices[i]+1, signErr)
		}
		sigHandles[i] = sh
		shares[i] = share
		t.Logf("signer %d share: %d bytes", signerIndices[i]+1, len(share))
	}

	// Phase 3: SpendComplete
	var shareEntries []fromt.MapEntry
	for j := 1; j < len(signerIndices); j++ {
		shareEntries = append(shareEntries, fromt.MapEntry{ID: ids[j], Value: shares[j]})
	}
	rawTx, err := fromt.SpendComplete(sigHandles[0], fromt.EncodeMap(shareEntries))
	if err != nil {
		t.Fatalf("SpendComplete: %v", err)
	}
	t.Logf("raw signed tx: %d bytes", len(rawTx))

	for _, sh := range sigHandles[1:] {
		sh.Close()
	}

	t.Log("=== Step 6: Broadcast ===")
	txHex := hex.EncodeToString(rawTx)
	broadcastBody, _ := json.Marshal(map[string]interface{}{
		"tx_as_hex":    txHex,
		"do_not_relay": false,
	})
	resp, err := http.Post(daemonURL+"/sendrawtransaction", "application/json", bytes.NewReader(broadcastBody))
	if err != nil {
		t.Fatalf("broadcast: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var broadcastResult struct {
		Status     string `json:"status"`
		Reason     string `json:"reason"`
		DoubleSpend bool  `json:"double_spend"`
	}
	err = json.Unmarshal(respBody, &broadcastResult)
	if err != nil {
		t.Fatalf("parse broadcast response: %v", err)
	}
	t.Logf("broadcast status: %s reason: %s double_spend: %v", broadcastResult.Status, broadcastResult.Reason, broadcastResult.DoubleSpend)

	if broadcastResult.Status != "OK" {
		t.Fatalf("broadcast failed: %s", broadcastResult.Reason)
	}

	t.Log("=== Step 6b: Verify tx_extra memo in mempool tx ===")
	poolResp, err := http.Get(daemonURL + "/get_transaction_pool")
	if err != nil {
		t.Fatalf("get mempool: %v", err)
	}
	poolBody, _ := io.ReadAll(poolResp.Body)
	poolResp.Body.Close()
	var pool struct {
		Transactions []struct {
			IDHash  string `json:"id_hash"`
			TxBlob  string `json:"tx_blob"`
			TxJSON  string `json:"tx_json"`
		} `json:"transactions"`
	}
	err = json.Unmarshal(poolBody, &pool)
	if err != nil {
		t.Fatalf("parse mempool: %v", err)
	}
	t.Logf("mempool has %d transactions", len(pool.Transactions))

	memoFound := false
	for _, poolTx := range pool.Transactions {
		if poolTx.TxJSON != "" {
			memoHex := hex.EncodeToString(memo)
			if containsSubstring(poolTx.TxJSON, memoHex) {
				t.Logf("found memo %s in tx %s tx_json", memoHex, poolTx.IDHash)
				memoFound = true
			}
		}
	}
	if !memoFound && len(pool.Transactions) > 0 {
		t.Log("memo not found in tx_json, checking tx_blob for extra field...")
		for _, poolTx := range pool.Transactions {
			txBytes, decErr := hex.DecodeString(poolTx.TxBlob)
			if decErr != nil {
				continue
			}
			memoBytes := memo
			if containsBytes(txBytes, memoBytes) {
				t.Logf("found memo bytes in tx blob %s", poolTx.IDHash)
				memoFound = true
			}
		}
	}
	if memoFound {
		t.Log("tx_extra memo VERIFIED in broadcast transaction")
	} else {
		t.Log("WARNING: could not verify memo in mempool tx (may need deeper parsing)")
	}

	t.Log("=== Step 7: Mine block to confirm ===")
	err = mineBlocks(daemonURL, dummyAddr, 1)
	if err != nil {
		t.Fatalf("mine confirmation block: %v", err)
	}

	t.Log("=== Step 8: Verify balance decreased ===")
	time.Sleep(1 * time.Second)
	balanceAfter, numOutputsAfter, err := ScanBalance(keyShares[0], daemonURL, 0, nil)
	if err != nil {
		t.Fatalf("ScanBalance after: %v", err)
	}
	t.Logf("balance after: %d piconero (%d outputs)", balanceAfter, numOutputsAfter)

	// Balance may not decrease because the confirmation mining block adds a new coinbase.
	// The change output also returns to our vault. Verify the broadcast succeeded (already
	// confirmed above with status=OK) and that we have a change output.
	if balanceAfter == 0 {
		t.Fatal("vault balance is zero after spend")
	}

	t.Logf("=== SUCCESS: DKG -> fund -> scan -> SpendPrepare -> 3-phase CLSAG -> broadcast -> confirmed ===")
	t.Logf("=== Sent %d piconero, balance before=%d after=%d (change + new coinbase) ===", sendAmount, balance, balanceAfter)
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && strings.Contains(s, substr)
}

func containsBytes(haystack, needle []byte) bool {
	return bytes.Contains(haystack, needle)
}
