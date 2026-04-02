//go:build darwin

package frobt

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/darwin -lfrobtlib -Wl,-rpath,${SRCDIR}/includes/darwin
*/
import "C"
