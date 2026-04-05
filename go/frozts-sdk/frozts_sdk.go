package froztsdk

/*
#include "includes/frozts-sdk.h"
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"runtime"
	"unsafe"
)

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

func mapLibError(code int) error {
	switch code {
	case 0:
		return nil
	case 4:
		return fmt.Errorf("null pointer")
	case 5:
		return fmt.Errorf("invalid buffer size")
	case 6:
		return fmt.Errorf("unknown error")
	case 7:
		return fmt.Errorf("serialization error")
	case 13:
		return fmt.Errorf("sapling error")
	default:
		return fmt.Errorf("lib error %d", code)
	}
}

type ScanResult struct {
	SpendableBalance uint64 `json:"spendable_balance"`
	ChainHeight      uint64 `json:"chain_height"`
	ScannedHeight    uint64 `json:"scanned_height"`
}

func Scan(dfvk []byte, lightwalletdURL string, birthday uint64) (*ScanResult, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	dfvkSlice := cGoSlice(dfvk, pinner)
	urlBytes := []byte(lightwalletdURL)
	urlSlice := cGoSlice(urlBytes, pinner)

	var outResult C.tss_buffer
	defer C.tss_buffer_free(&outResult)

	res := C.frozts_scan(dfvkSlice, urlSlice, C.uint64_t(birthday), &outResult)
	if res != 0 {
		return nil, mapLibError(int(res))
	}

	resultJSON := copyBuffer(&outResult)
	var result ScanResult
	err := json.Unmarshal(resultJSON, &result)
	if err != nil {
		return nil, fmt.Errorf("unmarshal scan result: %w", err)
	}

	return &result, nil
}

func ScanBalance(dfvk []byte, lightwalletdURL string, birthday uint64) (uint64, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	dfvkSlice := cGoSlice(dfvk, pinner)
	urlBytes := []byte(lightwalletdURL)
	urlSlice := cGoSlice(urlBytes, pinner)

	var outBalance C.uint64_t

	res := C.frozts_scan_balance(dfvkSlice, urlSlice, C.uint64_t(birthday), &outBalance)
	if res != 0 {
		return 0, mapLibError(int(res))
	}

	return uint64(outBalance), nil
}
