// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Verifier Interfaces for 0zk Circuits
 * @notice Interfaces for ZK proof verifiers generated from 0zk circom circuits
 * @dev These verifiers use the 0zk commitment scheme:
 *      - notePublicKey = Poseidon(receiverMasterPublicKey, random)
 *      - commitment = Poseidon(notePublicKey, tokenHash, amount, assetId)
 *      - nullifierHash = Poseidon(nullifyingKey, leafIndex)
 */

/**
 * @notice Shield verifier for 0zk addresses
 * @dev Public inputs: [amount, assetId, commitment]
 */
interface IShieldVerifier0zk {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[3] calldata _pubSignals
    ) external view returns (bool);
}

/**
 * @notice Transfer verifier for 0zk addresses
 * @dev Public inputs: [root, nullifierHash, newCommitment, assetId]
 */
interface ITransferVerifier0zk {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[4] calldata _pubSignals
    ) external view returns (bool);
}

/**
 * @notice Unshield/Burn verifier for 0zk addresses
 * @dev Public inputs: [root, nullifierHash, amount, assetId, recipient]
 */
interface IUnshieldVerifier0zk {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[5] calldata _pubSignals
    ) external view returns (bool);
}

