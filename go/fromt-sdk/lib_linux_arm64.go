//go:build linux && arm64

package fromtsdk

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/linux-arm64 -Wl,-rpath,${SRCDIR}/includes/linux-arm64 -lfromtsdk
*/
import "C"
