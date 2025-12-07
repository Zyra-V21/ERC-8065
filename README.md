# ERC-8065: Zero Knowledge Wrapper

Reference implementation for ERC-8065, a standard interface for privacy-preserving token wrappers using ZK-SNARKs.

## Overview

ERC-8065 defines a standard interface for wrapping ETH and ERC20 tokens into private notes using zero-knowledge proofs. This enables:

- **Private balances**: Token amounts hidden using commitments
- **Private transfers**: Transfer ownership without revealing sender/receiver
- **Stealth addresses (0zk)**: Receive funds without sharing spending keys
- **Fixed denominations**: Enhanced anonymity sets

## Contracts

### Core

| Contract | Description |
|----------|-------------|
| `zkWrapper.sol` | Multi-asset privacy wrapper with simple note system |
| `zkWrapper0zk.sol` | Privacy wrapper with stealth address support (0zk addresses) |

### Components

| Contract | Description |
|----------|-------------|
| `MerkleTreeComponent.sol` | Incremental Merkle tree (depth 20, Poseidon hash) |
| `RateLimiterComponent.sol` | Per-block rate limiting for shield/unshield |

### Libraries

| Contract | Description |
|----------|-------------|
| `DenominationLib.sol` | Fixed denomination validation |

## Interface

```solidity
interface IzkWrapper {
    function shieldETH(uint256[8] calldata proof, bytes32 commitment, uint256 amount) external payable;
    function shieldERC20(uint256[8] calldata proof, bytes32 commitment, uint256 amount, uint256 assetId) external;
    function privateTransfer(uint256[8] calldata proof, bytes32 nullifierHash, bytes32 newCommitment, bytes32 root, uint256 assetId) external;
    function unshield(uint256[8] calldata proof, bytes32 nullifierHash, uint256 amount, uint256 assetId, address recipient, bytes32 root) external;
}
```

## Commitment Schemes

### Simple Notes (zkWrapper)
```
commitment = Poseidon(secret, nullifier, amount, assetId)
nullifierHash = Poseidon(nullifier)
```

### Stealth Addresses (zkWrapper0zk)
```
notePublicKey = Poseidon(receiverMasterPublicKey, random)
commitment = Poseidon(notePublicKey, tokenHash, amount, assetId)
nullifierHash = Poseidon(nullifyingKey, leafIndex)
```

## Fixed Denominations

For optimal privacy, only these amounts are allowed:
- 0.001 ETH
- 0.01 ETH
- 0.1 ETH
- 1 ETH
- 10 ETH
- 100 ETH

## Live Implementation

- **Demo**: https://zkwrapper.pages.dev
- **Network**: Base Sepolia
- **Contract**: `0xD9f3Dd735Ebc866dE5709159e5Dbd23a57ED4417`

## ERC Draft

- [ERC-8065 PR](https://github.com/ethereum/ERCs/pull/1322)
- [ERC-8065 Discussion (Ethereum Magicians)](https://ethereum-magicians.org/t/erc-8065-zero-knowledge-token-wrapper/26006)
 -[ERC-8065 proposal by @0xNullLabs](https://github.com/0xNullLabs/ERC-8065-Zero-Knowledge-Token-Wrapper/blob/erc-draft-zero-knowledge-token-wrapper/ERCS/erc-8065.md)

## License

MIT

## Author

@ZyraV21 (Twitter, Telegram)

DISCLAIMER: This contracts has NOT been audited for production. This contracts are being part of an investigation over TESTNET, author is not responsible
to any financial losts due to the use of this contracts on MAINNET/Production

