module github.com/vultisig/frosty-lib/client/frozts

go 1.24.0

require github.com/vultisig/frosty-lib/go v0.0.0

require (
	github.com/tyler-smith/go-bip39 v1.1.0
	github.com/vultisig/commondata v0.0.0
	github.com/vultisig/frosty-lib/client/shared v0.0.0
	golang.org/x/crypto v0.48.0
	google.golang.org/grpc v1.79.1
	google.golang.org/protobuf v1.36.11
)

require (
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
)

replace github.com/vultisig/frosty-lib/go => ../../go

replace github.com/vultisig/frosty-lib/client/shared => ../shared

replace github.com/vultisig/commondata => ../../../commondata
