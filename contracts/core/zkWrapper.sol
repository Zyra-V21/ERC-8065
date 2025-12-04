// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

import {IShieldVerifier, ITransferVerifier, IUnshieldVerifier} from "../interfaces/IVerifier.sol";
import "../interfaces/IzkWrapper.sol";
import "../components/MerkleTreeComponent.sol";
import "../components/RateLimiterComponent.sol";
import "../libraries/DenominationLib.sol";

/**
 * @title zkWrapper
 * @author Ceaser Protocol
 * @notice Multi-asset privacy wrapper for ETH and ERC20 tokens
 * @dev Direct shield/unshield model with no intermediate public balances.
 *      Uses fixed denominations for amount privacy and Poseidon-based commitments.
 *      Commitment scheme: Poseidon(secret, nullifier, amount, assetId)
 */
contract zkWrapper is 
    IzkWrapper,
    MerkleTreeComponent,
    RateLimiterComponent,
    ReentrancyGuard,
    Pausable,
    Ownable 
{
    using SafeERC20 for IERC20;
    using DenominationLib for uint256;

    /// @notice Asset ID for native ETH
    uint256 public constant ETH_ASSET_ID = 0;

    /// @notice Verifier contracts (generated from circom)
    IShieldVerifier public immutable shieldVerifier;
    ITransferVerifier public immutable transferVerifier;
    IUnshieldVerifier public immutable unshieldVerifier;
    
    /// @notice Nullifiers (spent notes) - prevents double-spending
    mapping(bytes32 => bool) public nullifiers;
    
    /// @notice Registered assets (assetId => token address, 0x0 for ETH)
    mapping(uint256 => address) public registeredAssets;
    
    /// @notice Total locked per asset (for accounting)
    mapping(uint256 => uint256) public totalLocked;
    
    /// @notice Total notes created
    uint64 public totalNotesCreated;
    
    error ZeroAddress();

    constructor(
        address _shieldVerifier,
        address _transferVerifier,
        address _unshieldVerifier,
        address _poseidon
    ) 
        MerkleTreeComponent(_poseidon)
        Ownable(msg.sender) 
    {
        if (_shieldVerifier == address(0)) revert ZeroAddress();
        if (_transferVerifier == address(0)) revert ZeroAddress();
        if (_unshieldVerifier == address(0)) revert ZeroAddress();
        
        shieldVerifier = IShieldVerifier(_shieldVerifier);
        transferVerifier = ITransferVerifier(_transferVerifier);
        unshieldVerifier = IUnshieldVerifier(_unshieldVerifier);
        
        registeredAssets[ETH_ASSET_ID] = address(0);
        emit AssetRegistered(ETH_ASSET_ID, address(0));
    }

    error InvalidTokenAddress();

    /**
     * @notice Register a new ERC20 token for privacy
     * @param token ERC20 token address
     * @return assetId The assigned asset ID
     */
    function registerAsset(address token) external onlyOwner returns (uint256 assetId) {
        if (token == address(0)) revert InvalidTokenAddress();
        
        assetId = uint256(uint160(token));
        
        if (registeredAssets[assetId] != address(0) && assetId != ETH_ASSET_ID) {
            revert AssetAlreadyRegistered(assetId);
        }
        
        registeredAssets[assetId] = token;
        emit AssetRegistered(assetId, token);
    }

    /**
     * @notice Shield native ETH directly into a private note
     * @param proof ZK proof of commitment knowledge
     * @param commitment Poseidon(secret, nullifier, amount, assetId)
     * @param amount Must be valid denomination (sent as msg.value)
     */
    function shieldETH(
        uint256[8] calldata proof,
        bytes32 commitment,
        uint256 amount
    ) external payable nonReentrant whenNotPaused {
        // Validate amount matches msg.value
        if (msg.value != amount) revert InsufficientETH();
        if (amount == 0) revert ZeroAmount();
        
        // Validate denomination for privacy
        if (!DenominationLib.isValid(amount)) {
            revert InvalidDenomination(amount);
        }
        
        // Rate limiting
        _checkShieldLimit(amount);
        
        // Verify ZK proof (3 public inputs: amount, assetId, commitment)
        bool valid = shieldVerifier.verifyProof(
            [proof[0], proof[1]],
            [[proof[2], proof[3]], [proof[4], proof[5]]],
            [proof[6], proof[7]],
            [amount, ETH_ASSET_ID, uint256(commitment)]
        );
        if (!valid) revert InvalidProof();
        
        // Insert commitment into Merkle tree
        uint32 leafIndex = _insert(commitment);
        
        totalLocked[ETH_ASSET_ID] += amount;
        totalNotesCreated++;
        
        emit Shield(commitment, leafIndex, ETH_ASSET_ID, block.timestamp);
    }
    
    /**
     * @notice Shield ERC20 tokens directly into a private note
     * @param proof ZK proof of commitment knowledge
     * @param commitment Poseidon(secret, nullifier, amount, assetId)
     * @param amount Must be valid denomination
     * @param assetId Asset ID (= uint256(token address))
     */
    function shieldERC20(
        uint256[8] calldata proof,
        bytes32 commitment,
        uint256 amount,
        uint256 assetId
    ) external nonReentrant whenNotPaused {
        if (amount == 0) revert ZeroAmount();
        if (assetId == ETH_ASSET_ID) revert AssetNotRegistered(assetId);
        
        address token = registeredAssets[assetId];
        if (token == address(0)) revert AssetNotRegistered(assetId);
        
        // Validate denomination for privacy
        if (!DenominationLib.isValid(amount)) {
            revert InvalidDenomination(amount);
        }
        
        // Rate limiting
        _checkShieldLimit(amount);
        
        // Verify ZK proof (3 public inputs: amount, assetId, commitment)
        bool valid = shieldVerifier.verifyProof(
            [proof[0], proof[1]],
            [[proof[2], proof[3]], [proof[4], proof[5]]],
            [proof[6], proof[7]],
            [amount, assetId, uint256(commitment)]
        );
        if (!valid) revert InvalidProof();
        
        // Transfer tokens to wrapper (lock them)
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        
        // Insert commitment into Merkle tree
        uint32 leafIndex = _insert(commitment);
        
        totalLocked[assetId] += amount;
        totalNotesCreated++;
        
        emit Shield(commitment, leafIndex, assetId, block.timestamp);
    }
    
    /**
     * @notice Transfer private note to new owner
     * @param proof ZK proof of ownership
     * @param nullifierHash Hash of nullifier
     * @param newCommitment New note commitment
     * @param root Merkle root to verify against
     * @param assetId Asset being transferred
     */
    function privateTransfer(
        uint256[8] calldata proof,
        bytes32 nullifierHash,
        bytes32 newCommitment,
        bytes32 root,
        uint256 assetId
    ) external nonReentrant whenNotPaused {
        // Validate root
        if (!isKnownRoot(root)) revert UnknownMerkleRoot(root);
        
        // Check nullifier not used
        if (nullifiers[nullifierHash]) revert NullifierAlreadyUsed(nullifierHash);
        
        // Verify ZK proof (4 public inputs: root, nullifierHash, newCommitment, assetId)
        bool valid = transferVerifier.verifyProof(
            [proof[0], proof[1]],
            [[proof[2], proof[3]], [proof[4], proof[5]]],
            [proof[6], proof[7]],
            [uint256(root), uint256(nullifierHash), uint256(newCommitment), assetId]
        );
        if (!valid) revert InvalidProof();
        
        // Mark nullifier as spent
        nullifiers[nullifierHash] = true;
        
        // Insert new commitment
        uint32 newLeafIndex = _insert(newCommitment);
        
        totalNotesCreated++;
        
        emit PrivateTransfer(nullifierHash, newCommitment, assetId, newLeafIndex);
    }
    
    /**
     * @notice Unshield private note directly to recipient
     * @param proof ZK proof of ownership
     * @param nullifierHash Hash of nullifier
     * @param amount Amount to unshield
     * @param assetId Asset being unshielded
     * @param recipient Address to receive tokens
     * @param root Merkle root to verify against
     */
    function unshield(
        uint256[8] calldata proof,
        bytes32 nullifierHash,
        uint256 amount,
        uint256 assetId,
        address recipient,
        bytes32 root
    ) external nonReentrant whenNotPaused {
        // Validate inputs
        if (!isKnownRoot(root)) revert UnknownMerkleRoot(root);
        if (nullifiers[nullifierHash]) revert NullifierAlreadyUsed(nullifierHash);
        if (!DenominationLib.isValid(amount)) revert InvalidDenomination(amount);
        if (recipient == address(0)) revert InvalidRecipient();
        
        // Rate limiting
        _checkBurnLimit(amount);
        
        // Verify ZK proof (5 public inputs: root, nullifierHash, amount, assetId, recipient)
        bool valid = unshieldVerifier.verifyProof(
            [proof[0], proof[1]],
            [[proof[2], proof[3]], [proof[4], proof[5]]],
            [proof[6], proof[7]],
            [uint256(root), uint256(nullifierHash), amount, assetId, uint256(uint160(recipient))]
        );
        if (!valid) revert InvalidProof();
        
        // Mark nullifier as spent
        nullifiers[nullifierHash] = true;
        
        // Update accounting
        totalLocked[assetId] -= amount;
        
        // Send tokens directly to recipient
        if (assetId == ETH_ASSET_ID) {
            // Native ETH
            (bool success, ) = recipient.call{value: amount}("");
            if (!success) revert TransferFailed();
        } else {
            // ERC20
            address token = registeredAssets[assetId];
            if (token == address(0)) revert AssetNotRegistered(assetId);
            IERC20(token).safeTransfer(recipient, amount);
        }
        
        emit Unshield(nullifierHash, recipient, assetId);
    }

    function isKnownRoot(bytes32 root) public view override(IzkWrapper, MerkleTreeComponent) returns (bool) {
        return MerkleTreeComponent.isKnownRoot(root);
    }
    
    function getLastRoot() external view override(IzkWrapper, MerkleTreeComponent) returns (bytes32) {
        return roots[currentRootIndex];
    }
    
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }
    
    function isAssetRegistered(uint256 assetId) external view returns (bool) {
        return assetId == ETH_ASSET_ID || registeredAssets[assetId] != address(0);
    }
    
    /// @notice Get total locked balance for an asset
    function getAssetBalance(uint256 assetId) external view returns (uint256) {
        return totalLocked[assetId];
    }

    function pause() external onlyOwner {
        _pause();
    }
    
    function unpause() external onlyOwner {
        _unpause();
    }

    error DirectETHNotAllowed();

    receive() external payable {
        revert DirectETHNotAllowed();
    }
}
