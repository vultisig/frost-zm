//go:build linux && amd64

package frozto

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/linux-amd64 -Wl,-rpath,${SRCDIR}/includes/linux-amd64 -lfroztolib
*/
import "C"
