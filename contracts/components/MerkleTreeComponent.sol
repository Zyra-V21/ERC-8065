// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IPoseidonT3} from "../interfaces/IPoseidon.sol";

/**
 * @title MerkleTreeComponent
 * @author Ceaser Protocol
 * @notice Incremental Merkle tree for storing note commitments
 * @dev Uses Poseidon hash. Tree depth: 20 (max 1M notes). Keeps 100 historical roots.
 */
abstract contract MerkleTreeComponent {
    uint32 public constant MERKLE_LEVELS = 20;
    uint256 public constant ROOT_HISTORY_SIZE = 100;
    uint256 internal constant SNARK_SCALAR_FIELD = 
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    IPoseidonT3 public immutable poseidon;
    mapping(uint256 => bytes32) public filledSubtrees;
    bytes32[100] public roots;
    uint32 public currentRootIndex;
    uint32 public nextLeafIndex;
    bytes32[20] public zeros;

    error ZeroPoseidonAddress();

    constructor(address _poseidon) {
        if (_poseidon == address(0)) revert ZeroPoseidonAddress();
        poseidon = IPoseidonT3(_poseidon);
        bytes32 currentZero = bytes32(uint256(keccak256("zkETH")) % SNARK_SCALAR_FIELD);
        
        for (uint32 i = 0; i < MERKLE_LEVELS; i++) {
            zeros[i] = currentZero;
            filledSubtrees[i] = currentZero;
            currentZero = _hashLeftRight(currentZero, currentZero);
        }
        roots[0] = currentZero;
    }

    error MerkleTreeFull();

    /// @notice Insert a leaf into the Merkle tree
    function _insert(bytes32 leaf) internal returns (uint32 index) {
        uint32 currentIndex = nextLeafIndex;
        if (currentIndex >= uint32(2)**MERKLE_LEVELS) revert MerkleTreeFull();
        
        bytes32 currentHash = leaf;
        
        for (uint32 i = 0; i < MERKLE_LEVELS; i++) {
            if (currentIndex % 2 == 0) {
                // Left child - store and hash with zero
                filledSubtrees[i] = currentHash;
                currentHash = _hashLeftRight(currentHash, zeros[i]);
            } else {
                // Right child - hash with stored left sibling
                currentHash = _hashLeftRight(filledSubtrees[i], currentHash);
            }
            currentIndex /= 2;
        }
        
        currentRootIndex = (currentRootIndex + 1) % uint32(ROOT_HISTORY_SIZE);
        roots[currentRootIndex] = currentHash;
        
        nextLeafIndex++;
        return nextLeafIndex - 1;
    }
    
    function _hashLeftRight(bytes32 left, bytes32 right) internal view returns (bytes32) {
        uint256[2] memory inputs;
        inputs[0] = uint256(left);
        inputs[1] = uint256(right);
        return bytes32(poseidon.poseidon(inputs));
    }

    /// @notice Check if a root is in the history
    function isKnownRoot(bytes32 root) public view virtual returns (bool) {
        if (root == bytes32(0)) return false;
        
        uint32 i = currentRootIndex;
        do {
            if (roots[i] == root) return true;
            if (i == 0) i = uint32(ROOT_HISTORY_SIZE);
            i--;
        } while (i != currentRootIndex);
        
        return false;
    }
    
    /// @notice Get the current (latest) root
    function getLastRoot() external view virtual returns (bytes32) {
        return roots[currentRootIndex];
    }
}

