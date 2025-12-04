// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./PoseidonT4.sol";
import "../interfaces/IPoseidon.sol";

/**
 * @title PoseidonT4Wrapper
 * @notice Wrapper contract to expose PoseidonT4 library as IPoseidonT4 interface
 * @dev Used for commitment calculation: Poseidon(secret, nullifier, amount, assetId)
 */
contract PoseidonT4Wrapper is IPoseidonT4 {
    function poseidon(uint256[3] memory inputs) external pure override returns (uint256) {
        return PoseidonT4.hash(inputs);
    }
}

