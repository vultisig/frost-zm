//go:build linux && arm64

package frosst

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/linux-arm64 -lfrosstlib -Wl,-rpath,${SRCDIR}/includes/linux-arm64
*/
import "C"
