//go:build windows

package frozto

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/windows -lfroztolib -lws2_32 -luserenv -lbcrypt -lntdll
*/
import "C"
