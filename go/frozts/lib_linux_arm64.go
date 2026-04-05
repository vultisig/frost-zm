//go:build linux && arm64

package frozts

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/linux-arm64 -Wl,-rpath,${SRCDIR}/includes/linux-arm64 -lfroztslib
*/
import "C"
