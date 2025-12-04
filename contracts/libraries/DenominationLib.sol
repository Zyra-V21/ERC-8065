// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title DenominationLib
 * @author Ceaser Protocol
 * @notice Library for validating fixed denominations for amount privacy
 */
library DenominationLib {
    uint256 internal constant DENOM_0_001 = 0.001 ether;
    uint256 internal constant DENOM_0_01 = 0.01 ether;
    uint256 internal constant DENOM_0_1 = 0.1 ether;
    uint256 internal constant DENOM_1 = 1 ether;
    uint256 internal constant DENOM_10 = 10 ether;
    uint256 internal constant DENOM_100 = 100 ether;

    /// @notice Check if amount is a valid denomination
    function isValid(uint256 amount) internal pure returns (bool) {
        return (
            amount == DENOM_0_001 ||
            amount == DENOM_0_01 ||
            amount == DENOM_0_1 ||
            amount == DENOM_1 ||
            amount == DENOM_10 ||
            amount == DENOM_100
        );
    }

    /// @notice Get denomination index (0-5)
    function getIndex(uint256 amount) internal pure returns (uint8 index) {
        if (amount == DENOM_0_001) return 0;
        if (amount == DENOM_0_01) return 1;
        if (amount == DENOM_0_1) return 2;
        if (amount == DENOM_1) return 3;
        if (amount == DENOM_10) return 4;
        if (amount == DENOM_100) return 5;
        revert();
    }
}

