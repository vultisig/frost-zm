package fromt

/*
#include "includes/fromt-lib.h"
*/
import "C"

import "github.com/vultisig/frost-zm/go/frostgo"

func toError(code int) error {
	return frostgo.ToError("fromt", code)
}

func LastBlamedParty() uint16 {
	return uint16(C.frost_last_blamed_party())
}
