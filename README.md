# ZipherX Unified Boost File

A single, comprehensive blockchain data file for instant ZipherX wallet synchronization.

## Overview

| Property | Value |
|----------|-------|
| **Format** | ZBOOST01 (Unified Binary) |
| **Version** | 1 |
| **Chain Height** | 2,934,130 |
| **File Size** | ~496 MB (uncompressed) |
| **Created** | 2025-12-06 |

## What's Inside?

The unified boost file contains **all data** needed for fast wallet synchronization in a single download:

| Section | Count | Description |
|---------|-------|-------------|
| **Shielded Outputs** | 645,482 | Encrypted notes for trial decryption |
| **Shielded Spends** | 258,606 | Nullifiers for spent note detection |
| **Block Hashes** | 2,457,162 | For P2P header validation (Sapling onwards) |
| **Block Timestamps** | 2,934,131 | For transaction date display |
| **Serialized Tree** | 1 | Merkle commitment tree frontier |
| **Reliable Peers** | 1 | P2P bootstrap addresses |

## File Format Specification

### Header (128 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | Magic | `ZBOOST01` (ASCII) |
| 8 | 4 | Version | Format version (1) |
| 12 | 8 | Chain Height | End block height (uint64 LE) |
| 20 | 8 | Sapling Height | Sapling activation (476,969) |
| 28 | 32 | Tree Root | Commitment tree root hash |
| 60 | 32 | Block Hash | Hash at chain height |
| 92 | 4 | Section Count | Number of sections (6) |
| 96 | 8 | Created At | Unix timestamp |
| 104 | 24 | Reserved | Padding for future use |

### Section Table (56 bytes per section)

Immediately follows header. Each entry:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | Type | Section type ID |
| 4 | 8 | Offset | Byte offset in file |
| 12 | 8 | Size | Section data size in bytes |
| 20 | 8 | Count | Number of records |
| 28 | 8 | Start Height | First block height |
| 36 | 8 | End Height | Last block height |
| 44 | 12 | Reserved | Padding |

### Section Types

| ID | Name | Record Size | Description |
|----|------|-------------|-------------|
| 1 | Outputs | 652 bytes | height(4) + tx_idx(2) + out_idx(2) + cmu(32) + epk(32) + ciphertext(580) |
| 2 | Spends | 36 bytes | height(4) + nullifier(32) |
| 3 | Hashes | 32 bytes | Block hash in wire format (little-endian) |
| 4 | Timestamps | 4 bytes | Unix timestamp (uint32 LE) |
| 5 | Tree | Variable | Serialized commitment tree frontier |
| 6 | Peers | Variable | JSON array of peer addresses |

### Section Data Layout

```
[Header: 128 bytes]
[Section Table: 6 × 56 = 336 bytes]
[Outputs Data: 645,482 × 652 = ~401 MB]
[Spends Data: 258,606 × 36 = ~9 MB]
[Hashes Data: 2,457,162 × 32 = ~75 MB]
[Timestamps Data: 2,934,131 × 4 = ~11 MB]
[Tree Data: ~414 bytes]
[Peers Data: ~1 KB]
```

## Byte Order Convention

All multi-byte integers are **little-endian** (matching wire format):

- CMUs: Little-endian (wire format, NOT display format)
- EPKs: Little-endian (wire format)
- Nullifiers: Little-endian (wire format)
- Block hashes: Little-endian (wire format, reversed from RPC display)
- Integers: Little-endian (uint16, uint32, uint64)

**Important**: RPC/API responses display hashes in big-endian. The file stores them in wire format (bytes reversed).

## Height Ranges

| Section | Start Height | End Height | Notes |
|---------|--------------|------------|-------|
| Outputs | 476,969 | 2,934,130 | From Sapling activation |
| Spends | 476,969 | 2,934,130 | From Sapling activation |
| Hashes | 476,969 | 2,934,130 | From Sapling (no pre-Sapling hashes) |
| Timestamps | 0 | 2,934,130 | From genesis block |
| Tree | 2,934,130 | 2,934,130 | At chain tip |

## Verification

```bash
# Verify SHA256 checksum
shasum -a 256 -c SHA256SUMS.txt

# Or manually
shasum -a 256 zipherx_boost_v1.bin
```

## Usage

The ZipherX wallet automatically:

1. Checks for updates on GitHub releases
2. Downloads the unified file if newer version available
3. Parses sections on-demand during sync
4. Uses bundled data for instant wallet initialization

### For Imported Wallets

When importing a private key, the wallet:

1. Downloads the unified boost file (~496 MB)
2. Uses parallel note decryption (Rayon) for fast scanning
3. Computes nullifiers to detect spent notes
4. Builds witnesses for spendable notes

### For New Wallets

New wallets only need the serialized tree section (~414 bytes) since there are no historical notes to find.

## Technical Details

### Cryptographic Values

| Property | Value |
|----------|-------|
| Sapling Activation | 476,969 |
| Tree Root | `66698f156b865a7872853e5b2862bb78cc4c1fa2aa6aab99aa2b89cdb35e6e5e` |
| Block Hash | `0000034ce99a8a33945932adf0a04d70e5b5ecc6d9dc9ac3f95afeb9447f9e6e` |

### Shielded Output Record (652 bytes)

```
struct ShieldedOutput {
    height: u32,        // 4 bytes - Block height
    tx_index: u16,      // 2 bytes - Transaction index in block
    out_index: u16,     // 2 bytes - Output index in transaction
    cmu: [u8; 32],      // 32 bytes - Note commitment
    epk: [u8; 32],      // 32 bytes - Ephemeral public key
    ciphertext: [u8; 580], // 580 bytes - Encrypted note
}
```

### Shielded Spend Record (36 bytes)

```
struct ShieldedSpend {
    height: u32,        // 4 bytes - Block height
    nullifier: [u8; 32], // 32 bytes - Nullifier
}
```

## Migration from Legacy Files

This unified format replaces the following legacy files:

| Legacy File | Size | Now In |
|-------------|------|--------|
| shielded_outputs.bin | ~430 MB | Section 1 (Outputs) + Section 2 (Spends) |
| block_hashes.bin | ~75 MB | Section 3 (Hashes) |
| block_timestamps.bin | ~11 MB | Section 4 (Timestamps) |
| commitment_tree_serialized.bin | ~414 B | Section 5 (Tree) |
| reliable_peers.json | ~1 KB | Section 6 (Peers) |

**Benefits of unified format:**
- Single HTTP request instead of 5+
- Atomic updates (all-or-nothing)
- Consistent checksums
- Simpler caching logic
- Reduced GitHub API calls

## GitHub Release

The unified boost file is distributed via GitHub Releases:

- **Repository**: VictorLux/ZipherX_Boost
- **Release Tag**: v{height}-unified
- **Files**: zipherx_boost_v1.bin, zipherx_boost_manifest.json, SHA256SUMS.txt

---

*ZipherX - Privacy is a right, not a privilege.*
