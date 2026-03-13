module github.com/vultisig/frost-zm/client/vult

go 1.24.0

require (
	github.com/tyler-smith/go-bip32 v1.0.0
	github.com/tyler-smith/go-bip39 v1.1.0
	github.com/vultisig/commondata v0.0.0
	github.com/vultisig/frost-zm/client/shared v0.0.0
	github.com/vultisig/frost-zm/go v0.0.0
	golang.org/x/crypto v0.48.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/FactomProject/basen v0.0.0-20150613233007-fe3947df716e // indirect
	github.com/FactomProject/btcutilecc v0.0.0-20130527213604-d3a63a5752ec // indirect
)

replace github.com/vultisig/frost-zm/go => ../../go

replace github.com/vultisig/frost-zm/client/shared => ../shared

replace github.com/vultisig/commondata => ../../../commondata
