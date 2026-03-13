package fromtsdk

/*
#include "includes/fromt-sdk.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

func cGoSlice(data []byte, pinner *runtime.Pinner) *C.go_slice {
	if len(data) == 0 {
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
		return fmt.Errorf("ckd error")
	case 14:
		return fmt.Errorf("address error")
	default:
		return fmt.Errorf("lib error %d", code)
	}
}

func ScanBalance(keyShare []byte, daemonURL string, birthday uint64, spendKey []byte) (uint64, uint32, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	ksSlice := cGoSlice(keyShare, pinner)
	urlBytes := []byte(daemonURL)
	urlSlice := cGoSlice(urlBytes, pinner)

	var skSlice *C.go_slice
	if len(spendKey) > 0 {
		skSlice = cGoSlice(spendKey, pinner)
	}

	var outBalance C.uint64_t
	var outNumOutputs C.uint32_t

	res := C.fromt_scan_balance(ksSlice, urlSlice, C.uint64_t(birthday), skSlice, &outBalance, &outNumOutputs)
	if res != 0 {
		return 0, 0, mapLibError(int(res))
	}

	return uint64(outBalance), uint32(outNumOutputs), nil
}

func SpendPrepare(keyShare []byte, daemonURL, recipient string, amount, birthday uint64, excludedOffsets, spendKey []byte) (signableTx []byte, spentOffsets []byte, err error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	ksSlice := cGoSlice(keyShare, pinner)
	urlBytes := []byte(daemonURL)
	urlSlice := cGoSlice(urlBytes, pinner)
	rcptBytes := []byte(recipient)
	rcptSlice := cGoSlice(rcptBytes, pinner)

	var exclSlice *C.go_slice
	if len(excludedOffsets) > 0 {
		exclSlice = cGoSlice(excludedOffsets, pinner)
	}

	var skSlice *C.go_slice
	if len(spendKey) > 0 {
		skSlice = cGoSlice(spendKey, pinner)
	}

	var outTx C.tss_buffer
	defer C.tss_buffer_free(&outTx)
	var outOffsets C.tss_buffer
	defer C.tss_buffer_free(&outOffsets)

	res := C.fromt_spend_prepare(ksSlice, urlSlice, rcptSlice, C.uint64_t(amount), C.uint64_t(birthday), exclSlice, skSlice, &outTx, &outOffsets)
	if res != 0 {
		return nil, nil, mapLibError(int(res))
	}

	return copyBuffer(&outTx), copyBuffer(&outOffsets), nil
}
