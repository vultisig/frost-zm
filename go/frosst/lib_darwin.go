//go:build darwin

package frosst

/*
#cgo LDFLAGS: -L${SRCDIR}/includes/darwin -lfrosstlib -Wl,-rpath,${SRCDIR}/includes/darwin
*/
import "C"
