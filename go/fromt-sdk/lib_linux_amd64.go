//go:build linux && amd64

package fromtsdk

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/linux-amd64 -Wl,-rpath,${SRCDIR}/includes/linux-amd64 -lfromtsdk
*/
import "C"
