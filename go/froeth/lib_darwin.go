//go:build darwin

package froeth

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/darwin -lfroethlib -Wl,-rpath,${SRCDIR}/includes/darwin
*/
import "C"
