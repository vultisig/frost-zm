package frozt

import (
	"fmt"

	"github.com/vultisig/frosty-lib/go/frostgo"
)

type MapEntry struct {
	ID    uint16
	Value []byte
}

func EncodeMap(entries []MapEntry) []byte {
	generic := make([]frostgo.MapEntry, 0, len(entries))
	for _, e := range entries {
		idBytes, err := encodeIdentifier(e.ID)
		if err != nil {
			continue
		}
		generic = append(generic, frostgo.MapEntry{ID: idBytes, Value: e.Value})
	}
	return frostgo.EncodeMap(generic)
}

func DecodeMap(data []byte) ([]MapEntry, error) {
	generic, err := frostgo.DecodeMap(data)
	if err != nil {
		return nil, fmt.Errorf("frozt: %w", err)
	}
	entries := make([]MapEntry, 0, len(generic))
	for i, ge := range generic {
		id, decErr := decodeIdentifier(ge.ID)
		if decErr != nil {
			return nil, fmt.Errorf("frozt: codec: invalid identifier at entry %d: %w", i, decErr)
		}
		entries = append(entries, MapEntry{ID: id, Value: ge.Value})
	}
	return entries, nil
}
