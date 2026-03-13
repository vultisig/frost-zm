//go:build linux && amd64

package fromt

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/linux-amd64 -Wl,-rpath,${SRCDIR}/includes/linux-amd64 -lfromtlib
*/
import "C"
