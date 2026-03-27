package frosst

import "github.com/vultisig/frost-zm/go/frostgo"

func toError(code int) error {
	return frostgo.ToError("frosst", code)
}
