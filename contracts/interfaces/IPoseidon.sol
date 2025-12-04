// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IPoseidonT3
 * @notice Interface for Poseidon hash with 2 inputs (Merkle tree nodes)
 */
interface IPoseidonT3 {
    function poseidon(uint256[2] memory) external pure returns (uint256);
}

/**
 * @title IPoseidonT4
 * @notice Interface for Poseidon hash with 3 inputs (commitments - for debugging)
 */
interface IPoseidonT4 {
    function poseidon(uint256[3] memory) external pure returns (uint256);
}

