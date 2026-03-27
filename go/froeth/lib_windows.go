//go:build windows

package froeth

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/windows -lfroethlib -lws2_32 -luserenv -lbcrypt -lntdll
*/
import "C"
