//go:build darwin

package fromt

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/darwin -lfromtlib -Wl,-rpath,${SRCDIR}/includes/darwin
*/
import "C"
