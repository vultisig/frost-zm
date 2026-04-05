//go:build darwin

package froztosdk

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/darwin -lfroztosdk -Wl,-rpath,${SRCDIR}/includes/darwin
*/
import "C"
