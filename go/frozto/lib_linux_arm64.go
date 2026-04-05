//go:build linux && arm64

package frozto

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/linux-arm64 -Wl,-rpath,${SRCDIR}/includes/linux-arm64 -lfroztolib
*/
import "C"
