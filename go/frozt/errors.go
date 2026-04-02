package frozt

/*
#include "includes/frozt-lib.h"
*/
import "C"

import "github.com/vultisig/frosty-lib/go/frostgo"

func mapLibError(code int) error {
	return frostgo.ToError("frozt", code)
}

func LastBlamedParty() uint16 {
	return uint16(C.frost_last_blamed_party())
}
