//go:build linux && amd64

package frosst

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/linux-amd64 -lfrosstlib -Wl,-rpath,${SRCDIR}/includes/linux-amd64
*/
import "C"
