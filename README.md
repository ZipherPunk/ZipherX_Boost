# ZipherX Boost Files

Public repository containing bootstrap files for [ZipherX](https://github.com/VictorLux/ZipherX) - a privacy-focused Zclassic (ZCL) wallet.

## Contents

This repository hosts pre-computed cryptographic data that allows ZipherX wallet to sync faster:

| File | Description | Size |
|------|-------------|------|
| `commitment_tree_serialized.bin` | Serialized Sapling commitment tree state | ~500 bytes |
| `commitment_tree_manifest.json` | Metadata (height, checksums, timestamps) | ~1 KB |
| `commitment_tree.bin.zst` | Compressed full commitment tree (fallback) | ~33 MB |

## What is a Commitment Tree?

The Sapling commitment tree is a Merkle tree containing all shielded transaction output commitments (CMUs) on the Zclassic blockchain. It's required to:

- Verify ownership of shielded notes
- Generate spend proofs for transactions
- Calculate wallet balances

Building this tree from scratch requires scanning millions of blockchain blocks, which can take hours. These pre-computed files allow instant wallet startup.

## Security

### Verification

All files include SHA-256 checksums in the manifest. The ZipherX app verifies these checksums before using any downloaded data.

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

These files are updated periodically as the Zclassic blockchain grows. The app checks for updates on first launch and downloads newer versions if available.

## License

MIT License - See [LICENSE](LICENSE)

## Disclaimer

THE SOFTWARE AND DATA ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This repository contains pre-computed blockchain data for convenience. Users are encouraged to verify the data independently using a Zclassic full node. The maintainers make no guarantees about the accuracy, completeness, or timeliness of the data.

---

*Part of the [ZipherX](https://github.com/VictorLux/ZipherX) project*
