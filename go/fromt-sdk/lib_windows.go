//go:build windows

package fromtsdk

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/windows -lfromtsdk -lws2_32 -luserenv -lbcrypt -lntdll
*/
import "C"
