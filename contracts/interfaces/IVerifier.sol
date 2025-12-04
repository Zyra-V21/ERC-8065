// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Verifier Interfaces for Ceaser 1.0 (Note System)
 * @notice Interfaces for ZK proof verifiers generated from circom circuits
 * @dev These verifiers use the standard note commitment scheme:
 *      - commitment = Poseidon(secret, nullifier, amount, assetId)
 *      - nullifierHash = Poseidon(nullifier, leafIndex)
 */

/**
 * @notice Shield verifier - proves knowledge of note data
 * @dev Public inputs: [amount, assetId, commitment]
 */
interface IShieldVerifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[3] calldata _pubSignals
    ) external view returns (bool);
}

/**
 * @notice Transfer verifier - proves ownership and creates new note
 * @dev Public inputs: [root, nullifierHash, newCommitment, assetId]
 */
interface ITransferVerifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[4] calldata _pubSignals
    ) external view returns (bool);
}

/**
 * @notice Unshield/Burn verifier - proves ownership for withdrawal
 * @dev Public inputs: [root, nullifierHash, amount, assetId, recipient]
 */
interface IUnshieldVerifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[5] calldata _pubSignals
    ) external view returns (bool);
}
