// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./SchnorrVerifier.sol";

/// @title FrostAccount
/// @notice ERC-4337 compatible smart contract wallet controlled by a FROST threshold group.
/// @dev The FROST group verifying key is the account owner. Threshold signing happens off-chain;
///      this contract only verifies the aggregated Schnorr signature on-chain.
///
///      Signature format in UserOperation.signature:
///        R (33 bytes, compressed secp256k1 point) || z (32 bytes, scalar)
///
///      Compatible with ERC-4337 v0.7 (PackedUserOperation).
contract FrostAccount {
    /// The FROST group's compressed public key (33 bytes)
    bytes public groupPubKey;

    /// The ERC-4337 EntryPoint
    address public immutable entryPoint;

    /// Nonce for replay protection (for direct execute calls)
    uint256 public nonce;

    event Executed(address indexed target, uint256 value, bytes data);

    error InvalidEntryPoint();
    error InvalidSignature();
    error CallFailed();

    modifier onlyEntryPoint() {
        if (msg.sender != entryPoint) revert InvalidEntryPoint();
        _;
    }

    constructor(address entryPoint_, bytes memory groupPubKey_) {
        entryPoint = entryPoint_;
        groupPubKey = groupPubKey_;
    }

    /// @notice Validate a UserOperation signature (called by EntryPoint)
    /// @param userOpHash The hash of the UserOperation
    /// @param signature The FROST Schnorr signature (R || z, 65 bytes)
    /// @return validationData 0 for success, 1 for failure
    function validateSignature(
        bytes32 userOpHash,
        bytes memory signature
    ) external view returns (uint256 validationData) {
        bool valid = SchnorrVerifier.verify(
            groupPubKey,
            abi.encodePacked(userOpHash),
            signature
        );
        return valid ? 0 : 1;
    }

    /// @notice Execute a call (only via EntryPoint after signature validation)
    function execute(address dest, uint256 value, bytes calldata data) external onlyEntryPoint {
        (bool success,) = dest.call{value: value}(data);
        if (!success) revert CallFailed();
        emit Executed(dest, value, data);
    }

    /// @notice Execute a batch of calls
    function executeBatch(
        address[] calldata dests,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external onlyEntryPoint {
        require(dests.length == values.length && values.length == datas.length, "length mismatch");
        for (uint256 i = 0; i < dests.length; i++) {
            (bool success,) = dests[i].call{value: values[i]}(datas[i]);
            if (!success) revert CallFailed();
            emit Executed(dests[i], values[i], datas[i]);
        }
    }

    /// @notice Allow the account to receive ETH
    receive() external payable {}
}
