//go:build linux && amd64

package frozts

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/linux-amd64 -Wl,-rpath,${SRCDIR}/includes/linux-amd64 -lfroztslib
*/
import "C"
