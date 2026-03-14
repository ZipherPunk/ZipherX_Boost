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
| **Chain Height** | 3,032,466 (shielded) / 3,042,526 (transparent) |
| **Shielded Size** | 2058 MB (zstd, 2 parts), 2210 MB uncompressed |
| **Transparent Size** | 25.6 MB (zstd), 95.5 MB uncompressed |
| **Created** | 2026-03-05 (shielded), 2026-03-14 (transparent) |

## What's Inside?

### Shielded Boost (`zipherx_boost_v1.bin`)

The unified boost file contains **all data** needed for fast shielded wallet synchronization in a single download:

| Section | Count | Description |
|---------|-------|-------------|
| **Shielded Outputs** | 1,048,550 | Encrypted notes for trial decryption |
| **Shielded Spends** | 437,797 | Nullifiers for spent note detection |
| **Block Hashes** | 2,555,498 | For P2P header validation (Sapling onwards) |
| **Block Timestamps** | 2,555,498 | For transaction date display |
| **Serialized Tree** | 478 bytes | Commitment tree state for instant load |
| **Reliable Peers** | 4 | P2P bootstrap addresses |
| **Block Headers** | 2,541,056 | Full headers with Equihash solutions for PoW verification |

### Transparent Boost (`zipherx_tboost_v1.bin`) — NEW

A separate, lightweight file containing all unspent transparent outputs (UTXOs) for instant transparent address balance detection:

| Property | Value |
|----------|-------|
| **Format** | ZTBOOST1 |
| **Version** | 1 |
| **Chain Height** | 3,042,526 |
| **Unspent UTXOs** | 1,352,859 |
| **P2PKH Outputs** | 1,352,160 |
| **P2SH Outputs** | 606 |
| **Other** | 93 |
| **Total Value** | 10,353,924.04 ZCL |

## Backward Compatibility

The transparent boost is fully backward compatible:

- **Old app versions** (without transparent support) download only the shielded boost parts and ignore the `"transparent"` section in the manifest. Nothing breaks.
- **New app versions** download the shielded boost as before, plus the lightweight transparent boost file (26 MB). Transparent addresses are instantly populated from the UTXO snapshot, then peer-based sync covers the remaining blocks.
- **Migration**: Existing users with the shielded boost already downloaded only need the small transparent boost file (~26 MB). The app downloads it automatically on next sync.

## Transparent Boost File Format

### Header (64 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | Magic | `ZTBOOST1` (ASCII) |
| 8 | 4 | Version | Format version (1) |
| 12 | 4 | Height | Chain height at generation (uint32 LE) |
| 16 | 4 | Count | Number of UTXO entries (uint32 LE) |
| 20 | 44 | Reserved | Padding for future use |

### UTXO Entry (74 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | Height | Block height (uint32 LE) |
| 4 | 32 | TxID | Transaction hash (wire format, LE) |
| 36 | 4 | Vout | Output index (uint32 LE) |
| 40 | 8 | Value | Amount in zatoshis (uint64 LE) |
| 48 | 1 | Script Len | scriptPubKey length (max 25) |
| 49 | 25 | Script | scriptPubKey (zero-padded) |

### Script Types

| Type | Script Pattern | Length |
|------|---------------|--------|
| P2PKH | `OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG` | 25 bytes |
| P2SH | `OP_HASH160 <20-byte hash> OP_EQUAL` | 23 bytes |

## Shielded Boost File Format

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
- TxIDs: Little-endian (wire format, reversed from RPC display)
- Integers: Little-endian (uint16, uint32, uint64)

**Important**: RPC/API responses display hashes in big-endian. The file stores them in wire format (bytes reversed).

## Verification

```bash
# Verify SHA256 checksums
shasum -a 256 -c SHA256SUMS.txt

# Or manually (shielded, uncompressed)
shasum -a 256 zipherx_boost_v1.bin
# Expected: 783c538fb4fc51bed1006d79746b71078e92ff69ede15ed051b0f2afde7e7d97

# Transparent boost (uncompressed)
shasum -a 256 zipherx_tboost_v1.bin
# Expected: 651e7dfa9da43796482b408375c980174b4c4750ec16b66ab868cc05e9c771cc
```

## Usage

The ZipherX wallet automatically:

1. Checks for updates on GitHub releases
2. Downloads the shielded boost file if newer version available
3. Downloads the transparent boost file if transparent addresses are enabled
4. Parses sections on-demand during sync
5. Uses bundled data for instant wallet initialization

### For Imported Wallets

When importing a private key, the wallet:

1. Downloads the shielded boost file (~2058 MB compressed, 2 parts)
2. Downloads the transparent boost file (~26 MB compressed)
3. Uses parallel note decryption (Rayon) for fast shielded scanning
4. Matches UTXO scriptPubKeys against derived transparent addresses
5. Computes nullifiers to detect spent notes
6. Builds witnesses for spendable notes

### For New Wallets

New wallets skip historical scanning since there are no notes/UTXOs to find — only recent blocks are synced.

## GitHub Release

The boost files are distributed via GitHub Releases:

- **Repository**: ZipherPunk/ZipherX_Boost
- **Release Tag**: v3032466-unified
- **Shielded**: zipherx_boost_v1.bin.zst.part1, zipherx_boost_v1.bin.zst.part2
- **Transparent**: zipherx_tboost_v1.bin.zst
- **Manifests**: zipherx_boost_manifest.json, zipherx_tboost_manifest.json
- **Checksums**: SHA256SUMS.txt

### Manifest Version

The main manifest (`zipherx_boost_manifest.json`) uses **version 3** which includes an optional `"transparent"` section. Apps that don't support transparent boost simply ignore this field.

## Technical Details

### Cryptographic Values

| Property | Value |
|----------|-------|
| Sapling Activation | 476,969 |
| Chain Height (Shielded) | 3,032,466 |
| Chain Height (Transparent) | 3,042,526 |
| Block Hash | `00000631dcd17928f58cb4350ba177c977fbde33e323fe56b2576ce20882e55f` |
| Tree Root | `6f254f02aa127bb59faf0310136e7a2fd182b71d91b1ebfc3fd7e04db5d573d8` |

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

### Transparent UTXO Record (74 bytes)

```
struct TransparentUtxo {
    height: u32,           // 4 bytes - Block height
    txid: [u8; 32],        // 32 bytes - Transaction hash (wire format)
    vout: u32,             // 4 bytes - Output index
    value: u64,            // 8 bytes - Amount in zatoshis
    script_len: u8,        // 1 byte - scriptPubKey length
    script: [u8; 25],      // 25 bytes - scriptPubKey (zero-padded)
}
```

---

*ZipherX — Privacy is a right, not a privilege.*
