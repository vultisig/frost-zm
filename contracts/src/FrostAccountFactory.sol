// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./FrostAccount.sol";

/// @title FrostAccountFactory
/// @notice CREATE2 factory for deterministic deployment of FrostAccount instances.
/// @dev Users can precompute their account address before deployment using getAddress().
contract FrostAccountFactory {
    /// @notice Deploy a new FrostAccount
    /// @param entryPoint The ERC-4337 EntryPoint address
    /// @param groupPubKey The FROST group compressed public key (33 bytes)
    /// @param salt Deterministic deployment salt
    /// @return account The deployed FrostAccount
    function createAccount(
        address entryPoint,
        bytes memory groupPubKey,
        uint256 salt
    ) external returns (FrostAccount account) {
        bytes32 actualSalt = keccak256(abi.encodePacked(groupPubKey, salt));

        account = new FrostAccount{salt: actualSalt}(entryPoint, groupPubKey);
    }

    /// @notice Precompute the address of a FrostAccount before deployment
    /// @param entryPoint The ERC-4337 EntryPoint address
    /// @param groupPubKey The FROST group compressed public key (33 bytes)
    /// @param salt Deterministic deployment salt
    /// @return The counterfactual address
    function getAddress(
        address entryPoint,
        bytes memory groupPubKey,
        uint256 salt
    ) external view returns (address) {
        bytes32 actualSalt = keccak256(abi.encodePacked(groupPubKey, salt));

        bytes memory bytecode = abi.encodePacked(
            type(FrostAccount).creationCode,
            abi.encode(entryPoint, groupPubKey)
        );

        bytes32 hash = keccak256(
            abi.encodePacked(bytes1(0xff), address(this), actualSalt, keccak256(bytecode))
        );

        return address(uint160(uint256(hash)));
    }
}
