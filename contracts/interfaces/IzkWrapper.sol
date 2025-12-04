// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IzkWrapper
 * @notice Interface for zkWrapper - Multi-Asset Privacy Wrapper (Railgun-style)
 * @dev Direct shield/unshield model for maximum privacy (amount obfuscation)
 * 
 * Privacy Model:
 * - NO intermediate public balances
 * - shieldETH/shieldERC20: Lock tokens + create note in ONE tx
 * - unshield: Destroy note + send tokens in ONE tx
 * - Amount hidden via fixed denominations
 */
interface IzkWrapper {
    // ============ EVENTS ============
    
    event AssetRegistered(uint256 indexed assetId, address indexed token);
    
    /// @notice Emitted when tokens are shielded into a private note
    event Shield(
        bytes32 indexed commitment,
        uint32 leafIndex,
        uint256 indexed assetId,
        uint256 timestamp
        // NOTE: amount NOT included for privacy
    );
    
    /// @notice Emitted when a private transfer occurs
    event PrivateTransfer(
        bytes32 indexed nullifierHash,
        bytes32 indexed newCommitment,
        uint256 indexed assetId,
        uint32 newLeafIndex
    );
    
    /// @notice Emitted when a note is unshielded
    event Unshield(
        bytes32 indexed nullifierHash,
        address indexed recipient,
        uint256 indexed assetId
        // NOTE: amount NOT included for privacy
    );

    // ============ ERRORS ============
    
    error ZeroAmount();
    error InvalidDenomination(uint256 amount);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error UnknownMerkleRoot(bytes32 root);
    error InvalidProof();
    error InvalidRecipient();
    error AssetNotRegistered(uint256 assetId);
    error AssetAlreadyRegistered(uint256 assetId);
    error TransferFailed();
    error InsufficientETH();

    // ============ SHIELD FUNCTIONS (Direct Lock + Note) ============
    
    /**
     * @notice Shield native ETH directly into a private note
     * @dev Locks ETH and creates note in ONE transaction
     * @param proof ZK proof of commitment knowledge
     * @param commitment Poseidon(secret, nullifier, amount, assetId)
     * @param amount Must be valid denomination (sent as msg.value)
     */
    function shieldETH(
        uint256[8] calldata proof,
        bytes32 commitment,
        uint256 amount
    ) external payable;
    
    /**
     * @notice Shield ERC20 tokens directly into a private note
     * @dev Locks tokens and creates note in ONE transaction
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
    ) external;

    // ============ PRIVATE TRANSFER ============
    
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
    ) external;

    // ============ UNSHIELD (Direct Note Destroy + Withdraw) ============
    
    /**
     * @notice Unshield private note directly to recipient
     * @dev Destroys note and sends tokens in ONE transaction
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
    ) external;

    // ============ VIEW FUNCTIONS ============
    
    function isKnownRoot(bytes32 root) external view returns (bool);
    function getLastRoot() external view returns (bytes32);
    function isNullifierUsed(bytes32 nullifier) external view returns (bool);
    function isAssetRegistered(uint256 assetId) external view returns (bool);
    function totalNotesCreated() external view returns (uint64);
    function getAssetBalance(uint256 assetId) external view returns (uint256);
    
    // ============ CONSTANTS ============
    
    function ETH_ASSET_ID() external view returns (uint256);
}
