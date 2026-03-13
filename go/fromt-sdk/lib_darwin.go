//go:build darwin

package fromtsdk

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/darwin -lfromtsdk -Wl,-rpath,${SRCDIR}/includes/darwin
*/
import "C"
