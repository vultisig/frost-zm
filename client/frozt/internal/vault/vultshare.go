package vault

import (
	"encoding/json"
	"os"
)

type VultShare struct {
	Version  int    `json:"version"`
	Chain    string `json:"chain"`
	PartyID  int    `json:"party_id"`
	ZAddress string `json:"z_address"`
	Bundle   string `json:"bundle"`
}

func ExportVultShare(path string, share VultShare) error {
	data, err := json.MarshalIndent(share, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func ImportVultShare(path string) (VultShare, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return VultShare{}, err
	}
	var share VultShare
	err = json.Unmarshal(data, &share)
	return share, err
}
