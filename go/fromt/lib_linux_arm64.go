//go:build linux && arm64

package fromt

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/linux-arm64 -Wl,-rpath,${SRCDIR}/includes/linux-arm64 -lfromtlib
*/
import "C"
