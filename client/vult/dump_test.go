package vult

import (
	"encoding/hex"
	"fmt"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"
	keygenV1 "github.com/vultisig/commondata/go/vultisig/keygen/v1"

	fromt "github.com/vultisig/frost-zm/go/fromt"
	frozt "github.com/vultisig/frost-zm/go/frozt"

	sharedvault "github.com/vultisig/frost-zm/client/shared/vault"
)

func TestDumpVultStructure(t *testing.T) {
	env := loadDotEnv(t)

	mnemonic := env["FROZT_MNEMONIC"]
	if mnemonic == "" {
		t.Fatal("FROZT_MNEMONIC not set in .env")
	}
	fromtMnemonic := env["FROMT_MNEMONIC"]
	if fromtMnemonic == "" {
		fromtMnemonic = mnemonic
	}

	zcashSeed := zcashSeedFromMnemonic(mnemonic)
	froztResult := runFroztKeyImport(t, 3, 2, zcashSeed, 0)

	froztVK, _ := frozt.PubKeyPackageVerifyingKey(froztResult.pubKeyPackage)
	froztVKHex := hex.EncodeToString(froztVK)
	froztKeys, _ := frozt.SaplingDeriveKeys(froztResult.pubKeyPackage, froztResult.extras)

	moneroSeed := moneroSeedFromMnemonic(t, fromtMnemonic)
	fromtResult := runFromtKeyImport(t, 3, 2, moneroSeed, 0, 0)

	fromtPK, _ := fromt.KeySharePublicKey(fromtResult.keyShares[0])
	fromtPKHex := hex.EncodeToString(fromtPK)
	fromtAddr, _ := fromt.DeriveAddress(fromtResult.keyShares[0])
	fromtViewKey, _ := fromt.KeyShareViewKey(fromtResult.keyShares[0])

	froztBundle, _ := frozt.KeyShareBundlePack(
		froztResult.keyPackages[0], froztResult.pubKeyPackage, froztResult.extras, 3256538,
	)

	vault := &v1.Vault{
		Name:         "my-vault",
		Signers:      []string{"party-1", "party-2", "party-3"},
		LocalPartyId: "party-1",
		LibType:      keygenV1.LibType_LIB_TYPE_KEYIMPORT,
	}

	froztEntry := sharedvault.FroztChainKeyEntry(froztBundle, froztVKHex)
	sharedvault.SetChainKeyEntry(vault, froztEntry)

	fromtEntry := sharedvault.FromtChainKeyEntry(fromtResult.keyShares[0], fromtPKHex)
	sharedvault.SetChainKeyEntry(vault, fromtEntry)

	opts := protojson.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}
	jsonBytes, err := opts.Marshal(vault)
	if err != nil {
		t.Fatalf("protojson marshal: %v", err)
	}

	vultData, err := sharedvault.BuildVultFile(vault)
	if err != nil {
		t.Fatalf("BuildVultFile: %v", err)
	}

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              .vult Vault — Protobuf Structure               ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println(string(jsonBytes))
	fmt.Println()

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                   Decoded Chain Details                      ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	fmt.Println("── ZcashSapling ──────────────────────────────────────────────")
	fmt.Printf("  verifying_key:  %s\n", froztVKHex)
	fmt.Printf("  z-address:      %s\n", froztKeys.Address)
	fmt.Printf("  bundle size:    %d bytes\n", len(froztBundle))

	froztKP, _ := frozt.KeyShareBundleKeyPackage(froztBundle)
	froztPKP, _ := frozt.KeyShareBundlePubKeyPackage(froztBundle)
	froztExtras, _ := frozt.KeyShareBundleSaplingExtras(froztBundle)
	froztBday, _ := frozt.KeyShareBundleBirthday(froztBundle)

	fmt.Printf("  birthday:       %d\n", froztBday)
	fmt.Printf("  key_package:    %d bytes\n", len(froztKP))
	fmt.Printf("  pub_key_pkg:    %d bytes\n", len(froztPKP))
	fmt.Printf("  sapling_extras: %d bytes (nsk[32] || ovk[32] || dk[32])\n", len(froztExtras))
	fmt.Printf("    nsk: %s\n", hex.EncodeToString(froztExtras[:32]))
	fmt.Printf("    ovk: %s\n", hex.EncodeToString(froztExtras[32:64]))
	fmt.Printf("    dk:  %s\n", hex.EncodeToString(froztExtras[64:96]))
	fmt.Println()

	fmt.Println("── Monero ────────────────────────────────────────────────────")
	fmt.Printf("  public_key:     %s\n", fromtPKHex)
	fmt.Printf("  address:        %s\n", fromtAddr)
	fmt.Printf("  view_key:       %s\n", hex.EncodeToString(fromtViewKey))
	fmt.Printf("  keyshare size:  %d bytes\n", len(fromtResult.keyShares[0]))

	fromtBday, _ := fromt.KeyShareBirthday(fromtResult.keyShares[0])
	fromtID, _ := fromt.KeyShareIdentifier(fromtResult.keyShares[0])

	fmt.Printf("  birthday:       %d\n", fromtBday)
	fmt.Printf("  identifier:     %d\n", fromtID)
	fmt.Println()

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                  Raw .vult file (base64)                     ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  size: %d bytes\n", len(vultData))
	fmt.Printf("  %s...%s\n", string(vultData[:80]), string(vultData[len(vultData)-40:]))
	fmt.Println()
}
