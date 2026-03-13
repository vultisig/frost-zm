package fromt

import "github.com/vultisig/frost-zm/go/frostgo"

func toError(code int) error {
	return frostgo.ToError("fromt", code)
}
