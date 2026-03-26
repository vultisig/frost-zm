package froeth

import "github.com/vultisig/frost-zm/go/frostgo"

func mapLibError(code int) error {
	return frostgo.ToError("froeth", code)
}
