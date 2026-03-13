package frozt

import "github.com/vultisig/frost-zm/go/frostgo"

func mapLibError(code int) error {
	return frostgo.ToError("frozt", code)
}
