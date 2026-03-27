//go:build linux && amd64

package froeth

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/linux-amd64 -Wl,-rpath,${SRCDIR}/includes/linux-amd64 -lfroethlib
*/
import "C"
