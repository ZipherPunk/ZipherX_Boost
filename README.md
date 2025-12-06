# ZipherX Boost Files

Public repository containing pre-computed blockchain data for [ZipherX](https://github.com/VictorLux/ZipherX) - a privacy-focused Zclassic (ZCL) wallet.

> *"Privacy is necessary for an open society in the electronic age."* - A Cypherpunk's Manifesto

## Contents

This repository hosts pre-computed cryptographic data that allows ZipherX wallet to sync faster:

### Commitment Tree Files
| File | Description | Size | In Git | In Releases |
|------|-------------|------|--------|-------------|
| `commitment_tree.bin.zst` | Compressed CMU data for position lookup | ~33 MB | Yes | Yes |
| `commitment_tree_serialized.bin` | Serialized Sapling tree frontier (instant load) | ~500 bytes | Yes | Yes |
| `commitment_tree_manifest.json` | Metadata, height, CMU count, SHA256 checksums | ~1 KB | Yes | Yes |

### Block Data Files
| File | Description | Size | In Git | In Releases |
|------|-------------|------|--------|-------------|
| `block_hashes.bin` | Block hashes from Sapling activation | ~78 MB | Yes | Yes |
| `block_timestamps.bin` | Block timestamps from genesis | ~12 MB | Yes | Yes |
| `block_timestamps_manifest.json` | Timestamps metadata and checksum | ~200 bytes | Yes | Yes |

### Network Files
| File | Description | Size | In Git | In Releases |
|------|-------------|------|--------|-------------|
| `reliable_peers.json` | Reliable P2P peers for bootstrap | ~1 KB | Yes | Yes |
| `manifest.json` | Master manifest with all file metadata | ~500 bytes | Yes | Yes |

### Other Files
| File | Description | In Git |
|------|-------------|--------|
| `shielded_outputs_manifest.json` | Shielded outputs metadata (for future use) | Yes |

## What Does the App Download?

ZipherX downloads the **compressed** `.zst` file from GitHub Releases:

1. **New wallets**: Download `commitment_tree_serialized.bin` (~500 bytes) for instant startup
2. **Imported wallets**: Download `commitment_tree.bin.zst` (~33 MB), decompress locally, verify checksum
3. **Timestamps**: Download `block_timestamps.bin` for accurate transaction dates
4. **Block hashes**: Download `block_hashes.bin` for P2P block validation

The app verifies SHA256 checksums from the manifest before using any downloaded data.

## What is a Commitment Tree?

The Sapling commitment tree is a Merkle tree containing all shielded transaction output commitments (CMUs) on the Zclassic blockchain. It's required to:

- Verify ownership of shielded notes
- Generate spend proofs for transactions
- Calculate wallet balances

Building this tree from scratch requires scanning millions of blockchain blocks, which can take hours. These pre-computed files allow instant wallet startup.

## Security

### Verification

All files include SHA-256 checksums in manifests. ZipherX verifies these checksums before using any downloaded data.

### Trust Model

- These files contain **publicly derivable data** from the Zclassic blockchain
- They do **NOT** contain any private keys, seeds, or wallet-specific information
- The commitment tree root can be independently verified against any Zclassic full node's `finalsaplingroot`
- If tampered with, transactions would fail cryptographic verification

### How to Verify Independently

```bash
# Get the expected tree root from a Zclassic node at the checkpoint height
zclassic-cli getblockheader $(zclassic-cli getblockhash HEIGHT) | grep finalsaplingroot

# Compare with the tree_root in commitment_tree_manifest.json
```

## Updates

These files are updated automatically using `update_zipherx_boost.py` as the Zclassic blockchain grows. The app checks for updates on first launch and downloads newer versions if available.

### GitHub Releases

Each update creates tagged releases:
- `v{height}-tree` - Commitment tree files
- `v{height}-hashes` - Block hashes
- `v{height}-timestamps` - Block timestamps
- `v{height}-peers` - Reliable peers

## File Formats

### commitment_tree.bin
```
[cmu_count: UInt64 LE][cmu1: 32 bytes][cmu2: 32 bytes]...
```
CMUs are in wire format (little-endian).

### block_hashes.bin
```
[count: UInt64 LE][start_height: UInt64 LE][hash1: 32 bytes][hash2: 32 bytes]...
```
Hashes are in wire format (little-endian), starting from Sapling activation (height 476,969).

### block_timestamps.bin
```
[timestamp0: UInt32 LE][timestamp1: UInt32 LE]...
```
4 bytes per block, starting from genesis (height 0).

## License

MIT License - See [LICENSE](LICENSE)

## Disclaimer

THE SOFTWARE AND DATA ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This repository contains pre-computed blockchain data for convenience. Users are encouraged to verify the data independently using a Zclassic full node. The maintainers make no guarantees about the accuracy, completeness, or timeliness of the data.

---

*Part of the ZipherX project - Privacy is a right, not a privilege.*
