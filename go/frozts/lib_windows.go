//go:build windows

package frozts

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/windows -lfroztslib -lws2_32 -luserenv -lbcrypt -lntdll
*/
import "C"
