//go:build darwin

package frozto

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/darwin -lfroztolib -Wl,-rpath,${SRCDIR}/includes/darwin
*/
import "C"
