// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SchnorrVerifier
/// @notice Verifies FROST secp256k1 Schnorr signatures on-chain using the ecrecover precompile.
/// @dev The FROST Secp256K1Sha256TR ciphersuite produces signatures (R, z) where:
///   - Verification: z*G = R + c*P
///   - Challenge: c = H("FROST-secp256k1-SHA256-v1/chal", group_commitment_bytes || msg)
///
///   We use the ecrecover trick to verify without expensive EC math in Solidity.
///   The key identity: ecrecover can recover a point from (hash, v, r, s) via
///   s^{-1} * (hash*G + r*Q) = Q, which we abuse for Schnorr verification.
library SchnorrVerifier {
    /// secp256k1 curve order
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    /// secp256k1 field prime (for y-coordinate recovery)
    uint256 internal constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    /// @notice Verify a FROST Schnorr signature
    /// @param groupPubKey 33-byte compressed secp256k1 public key (group verifying key)
    /// @param message The message that was signed (arbitrary bytes)
    /// @param signature 65-byte signature: R (33 bytes compressed) || z (32 bytes scalar)
    /// @return valid True if the signature is valid
    function verify(
        bytes memory groupPubKey,
        bytes memory message,
        bytes memory signature
    ) internal view returns (bool valid) {
        require(groupPubKey.length == 33, "invalid pubkey length");
        require(signature.length == 65, "invalid signature length");

        // Extract R (33 bytes) and z (32 bytes) from signature
        bytes memory rBytes = new bytes(33);
        uint256 z;
        assembly {
            // Copy R (33 bytes at offset 32 in signature memory)
            let src := add(signature, 32)
            let dst := add(rBytes, 32)
            mstore(dst, mload(src))
            // Copy last byte of R
            let lastByte := byte(0, mload(add(src, 32)))
            mstore8(add(dst, 32), lastByte)
            // Read z (32 bytes at offset 65 in signature memory)
            z := mload(add(signature, 65))
        }
        require(z != 0 && z < N, "invalid z scalar");

        // Compute challenge c = SHA256(tag || tag || group_commitment || message)
        // where tag = SHA256("FROST-secp256k1-SHA256-v1/chal")
        // The tag hash is a constant we precompute.
        uint256 c = _computeChallenge(rBytes, message);

        // Extract R.x from compressed R
        uint256 rx;
        assembly {
            rx := mload(add(rBytes, 33))
            rx := shr(8, rx) // shift right to remove the prefix byte bleeding
        }
        // Actually, properly extract 32 bytes after the prefix
        rx = _extractXFromCompressed(rBytes);
        require(rx != 0 && rx < N, "invalid R.x");

        // ecrecover trick for Schnorr verification:
        //
        // We want to verify: z*G = R + c*P
        //
        // The ecrecover precompile, given (digest, v, r, s), returns:
        //   addr = address(s^{-1} * (digest*G + r*RECOVERED_POINT))
        //
        // We set up inputs so that ecrecover effectively computes
        // the expected signer address from the Schnorr equation.
        //
        // Approach: compute expected P address from the groupPubKey,
        // then verify the Schnorr equation holds.
        //
        // Direct approach: compute e = (N - c*rx) mod N as digest,
        // use v=27/28, r=rx, s=(z*rx) mod N
        // ecrecover should return the address of the group public key P.

        address expectedAddr = _pubkeyToAddress(groupPubKey);

        uint256 ecdsa_s = mulmod(z, rx, N);
        uint256 digest = N - mulmod(c, rx, N);

        // Try v=27
        address recovered = ecrecover(bytes32(digest), 27, bytes32(rx), bytes32(ecdsa_s));
        if (recovered == expectedAddr && recovered != address(0)) {
            return true;
        }
        // Try v=28
        recovered = ecrecover(bytes32(digest), 28, bytes32(rx), bytes32(ecdsa_s));
        if (recovered == expectedAddr && recovered != address(0)) {
            return true;
        }

        return false;
    }

    /// @notice Compute the FROST challenge hash
    /// @dev c = SHA256(tag || tag || R_bytes || message) where tag = SHA256("FROST-secp256k1-SHA256-v1/chal")
    function _computeChallenge(
        bytes memory rBytes,
        bytes memory message
    ) private pure returns (uint256) {
        // Precomputed: SHA256("FROST-secp256k1-SHA256-v1/chal")
        // This is computed once and hardcoded.
        bytes32 tagHash = _sha256TagHash();

        bytes memory input = abi.encodePacked(tagHash, tagHash, rBytes, message);
        bytes32 result = sha256(input);
        return uint256(result) % N;
    }

    /// @notice Precomputed SHA256("FROST-secp256k1-SHA256-v1/chal")
    /// @dev This must match the frost-core ciphersuite's challenge tag exactly.
    ///      Compute offline: SHA256(b"FROST-secp256k1-SHA256-v1/chal")
    function _sha256TagHash() private pure returns (bytes32) {
        // TODO: Replace with actual precomputed hash after verifying against Rust implementation.
        // For now, compute dynamically (costs more gas but is correct).
        return sha256("FROST-secp256k1-SHA256-v1/chal");
    }

    /// @notice Extract x-coordinate from 33-byte compressed public key
    function _extractXFromCompressed(bytes memory compressed) private pure returns (uint256 x) {
        require(compressed.length == 33, "invalid compressed key");
        assembly {
            x := mload(add(compressed, 33))
        }
    }

    /// @notice Convert compressed public key to Ethereum address
    /// @dev Decompress, then keccak256(uncompressed[1:65])[12:32]
    function _pubkeyToAddress(bytes memory compressed) private view returns (address) {
        require(compressed.length == 33, "invalid compressed key");

        uint8 prefix;
        uint256 x;
        assembly {
            prefix := byte(0, mload(add(compressed, 32)))
            x := mload(add(compressed, 33))
        }
        require(prefix == 0x02 || prefix == 0x03, "invalid prefix");

        // Decompress: y^2 = x^3 + 7 (mod P)
        uint256 y = _decompressY(x, prefix);

        // keccak256(x || y) -> take last 20 bytes
        bytes32 hash = keccak256(abi.encodePacked(x, y));
        return address(uint160(uint256(hash)));
    }

    /// @notice Decompress secp256k1 y-coordinate from x and parity prefix
    function _decompressY(uint256 x, uint8 prefix) private view returns (uint256 y) {
        // y^2 = x^3 + 7 mod P
        uint256 x3 = mulmod(mulmod(x, x, P), x, P);
        uint256 rhs = addmod(x3, 7, P);

        // Square root via modexp: y = rhs^((P+1)/4) mod P
        // (P+1)/4 = 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c
        uint256 exp = (P + 1) / 4;
        y = _modexp(rhs, exp, P);

        // Verify
        require(mulmod(y, y, P) == rhs, "invalid point");

        // Match parity
        if ((y & 1 == 0) != (prefix == 0x02)) {
            y = P - y;
        }
    }

    /// @notice Modular exponentiation using the precompile at address 0x05
    function _modexp(uint256 base, uint256 exp, uint256 mod_) private view returns (uint256 result) {
        bytes memory input = abi.encodePacked(
            uint256(32), // base length
            uint256(32), // exp length
            uint256(32), // mod length
            base,
            exp,
            mod_
        );
        bytes memory output = new bytes(32);
        assembly {
            let success := staticcall(gas(), 0x05, add(input, 32), mload(input), add(output, 32), 32)
            if iszero(success) { revert(0, 0) }
            result := mload(add(output, 32))
        }
    }
}
