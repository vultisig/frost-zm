// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {SchnorrVerifier} from "../src/SchnorrVerifier.sol";
import {FrostAccount} from "../src/FrostAccount.sol";
import {FrostAccountFactory} from "../src/FrostAccountFactory.sol";

contract SchnorrVerifierHarness {
    function verify(
        bytes memory groupPubKey,
        bytes memory message,
        bytes memory signature
    ) external view returns (bool) {
        return SchnorrVerifier.verify(groupPubKey, message, signature);
    }
}

contract SchnorrVerifierTest is Test {
    SchnorrVerifierHarness verifier;

    function setUp() public {
        verifier = new SchnorrVerifierHarness();
    }

    function test_rejectsInvalidPubkeyLength() public {
        bytes memory badPubkey = hex"0102";
        bytes memory message = hex"deadbeef";
        bytes memory signature = new bytes(65);

        vm.expectRevert("invalid pubkey length");
        verifier.verify(badPubkey, message, signature);
    }

    function test_rejectsInvalidSignatureLength() public {
        bytes memory pubkey = new bytes(33);
        pubkey[0] = 0x02;
        bytes memory message = hex"deadbeef";
        bytes memory badSig = new bytes(32);

        vm.expectRevert("invalid signature length");
        verifier.verify(pubkey, message, badSig);
    }

    function test_rejectsZeroZ() public {
        bytes memory pubkey = new bytes(33);
        pubkey[0] = 0x02;
        for (uint i = 1; i < 33; i++) pubkey[i] = bytes1(uint8(i));

        bytes memory message = hex"deadbeef";
        // R (33 bytes) + z=0 (32 bytes)
        bytes memory sig = new bytes(65);
        sig[0] = 0x02;
        for (uint i = 1; i < 33; i++) sig[i] = bytes1(uint8(i + 10));
        // z remains all zeros → should reject

        vm.expectRevert("invalid z scalar");
        verifier.verify(pubkey, message, sig);
    }
}

contract FrostAccountTest is Test {
    FrostAccount account;
    FrostAccountFactory factory;
    address entryPoint;

    function setUp() public {
        entryPoint = address(0xBEEF);
        // Use a valid-looking compressed pubkey
        bytes memory pubkey = hex"02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
        account = new FrostAccount(entryPoint, pubkey);
        factory = new FrostAccountFactory();
    }

    function test_entryPoint() public view {
        assertEq(account.entryPoint(), entryPoint);
    }

    function test_groupPubKey() public view {
        bytes memory pk = account.groupPubKey();
        assertEq(pk.length, 33);
        assertEq(uint8(pk[0]), 0x02);
    }

    function test_receiveEth() public {
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(account).call{value: 0.5 ether}("");
        assertTrue(ok);
        assertEq(address(account).balance, 0.5 ether);
    }

    function test_executeRevertsForNonEntryPoint() public {
        vm.expectRevert(FrostAccount.InvalidEntryPoint.selector);
        account.execute(address(0x1), 0, "");
    }

    function test_executeFromEntryPoint() public {
        vm.deal(address(account), 1 ether);
        address target = address(0xCAFE);

        vm.prank(entryPoint);
        account.execute(target, 0.1 ether, "");

        assertEq(target.balance, 0.1 ether);
    }

    function test_factoryDeterministicAddress() public {
        bytes memory pubkey = hex"02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

        address predicted = factory.getAddress(entryPoint, pubkey, 0);
        FrostAccount deployed = factory.createAccount(entryPoint, pubkey, 0);

        assertEq(address(deployed), predicted);
    }

    function test_factoryDifferentSaltsDifferentAddresses() public {
        bytes memory pubkey = hex"02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

        address addr1 = factory.getAddress(entryPoint, pubkey, 0);
        address addr2 = factory.getAddress(entryPoint, pubkey, 1);

        assertTrue(addr1 != addr2);
    }
}
