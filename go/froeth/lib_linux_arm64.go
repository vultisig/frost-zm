//go:build linux && arm64

package froeth

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/linux-arm64 -Wl,-rpath,${SRCDIR}/includes/linux-arm64 -lfroethlib
*/
import "C"
