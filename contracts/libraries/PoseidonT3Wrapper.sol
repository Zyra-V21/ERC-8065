// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./PoseidonT3.sol";

/**
 * @title PoseidonT3Wrapper
 * @notice Wrapper contract that exposes PoseidonT3 library as a contract
 * @dev This is needed because the MerkleTreeComponent expects a contract address
 */
contract PoseidonT3Wrapper {
    /**
     * @notice Hash 2 inputs using Poseidon
     * @param inputs Array of 2 field elements
     * @return The Poseidon hash
     */
    function poseidon(uint256[2] memory inputs) external pure returns (uint256) {
        return PoseidonT3.hash(inputs);
    }
}

