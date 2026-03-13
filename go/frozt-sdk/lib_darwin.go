//go:build darwin

package froztsdk

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/darwin -lfroztsdk -Wl,-rpath,${SRCDIR}/includes/darwin
*/
import "C"
