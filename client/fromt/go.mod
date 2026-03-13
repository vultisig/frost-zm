module github.com/vultisig/frost-zm/client/fromt

go 1.24.0

require (
	filippo.io/edwards25519 v1.2.0
	github.com/dimalinux/gopherphis v0.0.0-20231002075534-34c5cdaebac1
	github.com/tyler-smith/go-bip32 v1.0.0
	github.com/tyler-smith/go-bip39 v1.1.0
	github.com/vultisig/frost-zm/client/shared v0.0.0
	github.com/vultisig/frost-zm/go v0.0.0
	golang.org/x/crypto v0.48.0
)

require (
	ekyu.moe/cryptonight v0.3.0 // indirect
	github.com/FactomProject/basen v0.0.0-20150613233007-fe3947df716e // indirect
	github.com/FactomProject/btcutilecc v0.0.0-20130527213604-d3a63a5752ec // indirect
	github.com/aead/skein v0.0.0-20160722084837-9365ae6e95d2 // indirect
	github.com/dchest/blake256 v1.1.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
)

replace github.com/vultisig/frost-zm/go => ../../go

replace github.com/vultisig/frost-zm/client/shared => ../shared

replace github.com/vultisig/commondata => ../../../commondata
