// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title RateLimiterComponent
 * @author Ceaser Protocol
 * @notice Rate limiting per block to prevent rapid draining attacks
 */
abstract contract RateLimiterComponent {
    uint256 public constant MAX_SHIELD_PER_BLOCK = 1000 ether;
    uint256 public constant MAX_BURN_PER_BLOCK = 100 ether;

    mapping(uint256 => uint256) public blockShieldTotals;
    mapping(uint256 => uint256) public blockBurnTotals;

    error ShieldRateLimitExceeded(uint256 current, uint256 limit);
    error BurnRateLimitExceeded(uint256 current, uint256 limit);

    function _checkShieldLimit(uint256 amount) internal {
        uint256 blockTotal = blockShieldTotals[block.number] + amount;
        
        if (blockTotal > MAX_SHIELD_PER_BLOCK) {
            revert ShieldRateLimitExceeded(blockTotal, MAX_SHIELD_PER_BLOCK);
        }
        
        blockShieldTotals[block.number] = blockTotal;
    }

    function _checkBurnLimit(uint256 amount) internal {
        uint256 blockTotal = blockBurnTotals[block.number] + amount;
        
        if (blockTotal > MAX_BURN_PER_BLOCK) {
            revert BurnRateLimitExceeded(blockTotal, MAX_BURN_PER_BLOCK);
        }
        
        blockBurnTotals[block.number] = blockTotal;
    }
}

