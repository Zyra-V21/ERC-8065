// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IzkWrapper0zk
 * @notice Interface for zkWrapper0zk - Privacy Wrapper with 0zk Addresses
 * @dev Uses Railgun-style 0zk addresses for receiving funds
 * 
 * Commitment Scheme:
 * - notePublicKey = Poseidon(receiverMasterPublicKey, random)
 * - commitment = Poseidon(notePublicKey, tokenHash, amount, assetId)
 * - nullifierHash = Poseidon(nullifyingKey, leafIndex)
 * 
 * Key Difference from zkWrapper:
 * - Shield TO a 0zk address (receiver's masterPublicKey in proof)
 * - Only owner of nullifyingKey can spend notes
 * - No need to share secrets - just share 0zk address
 */
interface IzkWrapper0zk {
    // ============ EVENTS ============
    
    event AssetRegistered(uint256 indexed assetId, address indexed token);
    
    /// @notice Emitted when tokens are shielded to a 0zk address
    /// @dev ciphertext contains encrypted note data for receiver to scan
    /// @dev ephemeralPubKey allows receiver to derive shared secret via ECDH
    event Shield0zk(
        bytes32 indexed commitment,
        uint32 leafIndex,
        uint256 indexed assetId,
        uint256 timestamp,
        bytes ciphertext,
        bytes32 ephemeralPubKey
    );
    
    /// @notice Emitted when a private transfer occurs
    event PrivateTransfer0zk(
        bytes32 indexed nullifierHash,
        bytes32 indexed newCommitment,
        uint256 indexed assetId,
        uint32 newLeafIndex
    );
    
    /// @notice Emitted when a note is unshielded
    event Unshield0zk(
        bytes32 indexed nullifierHash,
        address indexed recipient,
        uint256 indexed assetId
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

    // ============ SHIELD FUNCTIONS ============
    
    /**
     * @notice Shield native ETH to a 0zk address
     * @param proof ZK proof of commitment knowledge
     * @param commitment Poseidon(notePublicKey, tokenHash, amount, assetId)
     * @param amount Must be valid denomination (sent as msg.value)
     * @param ciphertext Encrypted note data for receiver to scan
     * @param ephemeralPubKey Sender's ephemeral public key for ECDH
     */
    function shieldETH(
        uint256[8] calldata proof,
        bytes32 commitment,
        uint256 amount,
        bytes calldata ciphertext,
        bytes32 ephemeralPubKey
    ) external payable;
    
    /**
     * @notice Shield ERC20 tokens to a 0zk address
     * @param proof ZK proof of commitment knowledge
     * @param commitment Poseidon(notePublicKey, tokenHash, amount, assetId)
     * @param amount Must be valid denomination
     * @param assetId Asset ID (= uint256(token address))
     * @param ciphertext Encrypted note data for receiver to scan
     * @param ephemeralPubKey Sender's ephemeral public key for ECDH
     */
    function shieldERC20(
        uint256[8] calldata proof,
        bytes32 commitment,
        uint256 amount,
        uint256 assetId,
        bytes calldata ciphertext,
        bytes32 ephemeralPubKey
    ) external;

    // ============ PRIVATE TRANSFER ============
    
    /**
     * @notice Transfer private note to another 0zk address
     * @param proof ZK proof of ownership (uses nullifyingKey)
     * @param nullifierHash Poseidon(nullifyingKey, leafIndex)
     * @param newCommitment New note commitment for receiver
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

    // ============ UNSHIELD ============
    
    /**
     * @notice Unshield private note directly to recipient
     * @param proof ZK proof of ownership (uses nullifyingKey)
     * @param nullifierHash Poseidon(nullifyingKey, leafIndex)
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
    function ETH_ASSET_ID() external view returns (uint256);
}

