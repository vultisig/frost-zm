//go:build darwin

package frozts

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/darwin -lfroztslib -Wl,-rpath,${SRCDIR}/includes/darwin
*/
import "C"
