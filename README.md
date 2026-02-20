# ZipherX Unified Boost File

A single, comprehensive blockchain data file for instant ZipherX wallet synchronization.

> **DISCLAIMER**: This software and data are provided **"AS IS"**, without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. **ZipherX is beta software under active development.** By downloading or using the boost file, you acknowledge and agree that:
>
> - **USE AT YOUR OWN RISK.** The authors and contributors are not liable for any loss of funds, data corruption, or damages arising from the use of this software or data.
> - **ALWAYS VERIFY CHECKSUMS** before using any downloaded file. Do not trust files that fail checksum verification.
> - **ALWAYS BACKUP YOUR WALLET** before applying any sync data. Loss of wallet data may result in permanent loss of funds.
> - **NO FINANCIAL ADVICE.** Nothing in this repository constitutes financial, investment, or legal advice. Cryptocurrency involves significant risk.
> - **BETA SOFTWARE.** This project is in active beta. Bugs, breaking changes, and data format changes may occur without notice.
> - **NOT AUDITED.** The cryptographic data in the boost file has not been independently audited. Use trusted sources only.
> - The boost file contains **publicly available blockchain data only** — no private keys, seeds, or sensitive information are included.

## Overview

| Property | Value |
|----------|-------|
| **Format** | ZBOOST01 (Unified Binary) |
| **Version** | 2 |
| **Chain Height** | 3,018,214 |
| **File Size** | 2058 MB (zstd, 2 parts), 2210 MB uncompressed (7% reduction) |
| **Created** | 2026-02-20 |

## What's Inside?

The unified boost file contains **all data** needed for fast wallet synchronization in a single download:

| Section | Count | Description |
|---------|-------|-------------|
| **Shielded Outputs** | 1,047,610 | Encrypted notes for trial decryption |
| **Shielded Spends** | 436,859 | Nullifiers for spent note detection |
| **Block Hashes** | 2,541,246 | For P2P header validation (Sapling onwards) |
| **Block Timestamps** | 2,541,246 | For transaction date display |
| **Serialized Tree** | 478 bytes | Commitment tree state for instant load |
| **Reliable Peers** | 4 | P2P bootstrap addresses |
| **Block Headers** | 2,541,056 | Full headers with Equihash solutions for PoW verification |

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
| 92 | 4 | Section Count | Number of sections |
| 96 | 8 | Created At | Unix timestamp |
| 104 | 24 | Reserved | Padding for future use |

### Section Types

| ID | Name | Record Size | Description |
|----|------|-------------|-------------|
| 1 | Outputs | 684 bytes | height(4) + index(4) + cmu(32) + epk(32) + ciphertext(580) + received_in_tx(32) |
| 2 | Spends | 68 bytes | height(4) + nullifier(32) + txid(32) |
| 3 | Hashes | 32 bytes | Block hash in wire format (little-endian) |
| 4 | Timestamps | 4 bytes | Unix timestamp (uint32 LE) |
| 5 | Tree | Variable | Serialized Sapling commitment tree |
| 6 | Peers | Variable | Peer addresses |
| 7 | Headers | 582 bytes | version(4) + prevHash(32) + merkleRoot(32) + saplingRoot(32) + time(4) + bits(4) + nonce(32) + equihashSolution(~400) + nSolution(42) |

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
| Outputs | 476,969 | 3,018,214 | From Sapling activation |
| Spends | 476,969 | 3,018,214 | From Sapling activation |
| Hashes | 476,969 | 3,018,214 | From Sapling (no pre-Sapling hashes) |
| Timestamps | 476,969 | 3,018,214 | From Sapling activation |
| Tree | 476,969 | 3,018,214 | Sapling commitment tree |

## Verification

```bash
# Verify SHA256 checksum
shasum -a 256 -c SHA256SUMS.txt

# Or manually (uncompressed)
shasum -a 256 zipherx_boost_v1.bin
# Expected: 7608ee32a08106253103e135418de9fc7a2cb5b887ebcc97f71d0ff1b2b68336

# Compressed file:
shasum -a 256 zipherx_boost_v1.bin.zst
# Expected: 7608ee32a08106253103e135418de9fc7a2cb5b887ebcc97f71d0ff1b2b68336
```

## Usage

The ZipherX wallet automatically:

1. Checks for updates on GitHub releases
2. Downloads the unified file if newer version available
3. Parses sections on-demand during sync
4. Uses bundled data for instant wallet initialization

### For Imported Wallets

When importing a private key, the wallet:

1. Downloads the unified boost file (~2058 MB compressed, 2 parts)
2. Uses parallel note decryption (Rayon) for fast scanning
3. Computes nullifiers to detect spent notes
4. Builds witnesses for spendable notes

### For New Wallets

New wallets skip historical note scanning since there are no notes to find - only recent blocks are synced.

## Technical Details

### Cryptographic Values

| Property | Value |
|----------|-------|
| Sapling Activation | 476,969 |
| Chain Height | 3,018,214 |
| Block Hash | `000005c5977278447e8e7cc2ecdf1b060510a020d9e84b6dd02fd1849011a45e` |
| Tree Root | `1fe242b0d37501f10cd7091f9f526846e824616fda165415dc8ed18f5a4c6ec0` |

### Shielded Output Record (684 bytes — PRODUCTION v2)

```
struct ShieldedOutput {
    height: u32,           // 4 bytes - Block height
    index: u32,            // 4 bytes - Output index
    cmu: [u8; 32],         // 32 bytes - Note commitment (wire format)
    epk: [u8; 32],         // 32 bytes - Ephemeral public key (wire format)
    ciphertext: [u8; 580], // 580 bytes - Encrypted note
    received_in_tx: [u8; 32], // 32 bytes - Transaction ID (wire format)
}
```

### Shielded Spend Record (68 bytes — PRODUCTION v2)

```
struct ShieldedSpend {
    height: u32,           // 4 bytes - Block height
    nullifier: [u8; 32],   // 32 bytes - Nullifier (wire format)
    txid: [u8; 32],        // 32 bytes - Transaction ID (wire format)
}
```

## GitHub Release

The unified boost file is distributed via GitHub Releases:

- **Repository**: ZipherPunk/ZipherX_Boost
- **Release Tag**: v3018024-unified
- **Files**: zipherx_boost_v1.bin.zst.part1, zipherx_boost_v1.bin.zst.part2, zipherx_boost_manifest.json, SHA256SUMS.txt

---

*ZipherX - Privacy is a right, not a privilege.*
