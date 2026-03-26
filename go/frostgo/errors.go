package frostgo

import "fmt"

const (
	LibOK                = 0
	LibInvalidHandle     = 1
	LibHandleInUse       = 2
	LibInvalidHandleType = 3
	LibNullPtr           = 4
	LibInvalidBufferSize = 5
	LibUnknownError      = 6
	LibSerializationErr  = 7
	LibInvalidIdentifier = 8
	LibDkgError          = 9
	LibSigningError      = 10
	LibReshareError      = 11
	LibKeyImportError    = 12
	LibSaplingError      = 13
	LibCkdError          = 13
	LibAddressError      = 14
)

var sharedErrorMessages = map[int]string{
	LibInvalidHandle:     "invalid handle",
	LibHandleInUse:       "handle in use",
	LibInvalidHandleType: "invalid handle type",
	LibNullPtr:           "null pointer",
	LibInvalidBufferSize: "invalid buffer size",
	LibUnknownError:      "unknown error",
	LibSerializationErr:  "serialization error",
	LibInvalidIdentifier: "invalid identifier",
	LibDkgError:          "dkg error",
	LibSigningError:      "signing error",
	LibReshareError:      "reshare error",
	LibKeyImportError:    "key import error",
}

var froztMessages = map[int]string{
	13: "sapling error",
}

var fromtMessages = map[int]string{
	13: "ckd error",
	14: "address error",
}

var frobtMessages = map[int]string{
	13: "ckd error",
	14: "address error",
	15: "tx error",
}

func ToError(prefix string, code int) error {
	if code == LibOK {
		return nil
	}
	msg, found := sharedErrorMessages[code]
	if !found {
		switch prefix {
		case "frozt":
			msg, found = froztMessages[code]
		case "fromt":
			msg, found = fromtMessages[code]
		case "frobt":
			msg, found = frobtMessages[code]
		}
	}
	if found {
		return fmt.Errorf("%s: %s", prefix, msg)
	}
	return fmt.Errorf("%s: unknown error code %d", prefix, code)
}
