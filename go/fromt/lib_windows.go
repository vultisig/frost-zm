//go:build windows

package fromt

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/windows -lfromtlib -lws2_32 -luserenv -lbcrypt -lntdll
*/
import "C"
