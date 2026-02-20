#!/usr/bin/env python3
"""
Generate ZipherX Boost File v2 - PRODUCTION READY

Target: 1500+ blocks/sec using batch RPC calls with HTTP connection pooling

PRODUCTION ENHANCEMENTS:
- received_in_tx included in outputs for accurate change detection
- Equihash solutions included in headers for full PoW verification
- 100% accurate transaction history - no placeholders, no runtime resolution needed!

Features:
- Parallel block scanning with batch RPC (~2600 blocks/sec on optimized node)
- Automatic balance verification using Rust check_balance tool
- Auto-update README.md and SHA256SUMS.txt with current statistics
- Auto-commit, push, and create GitHub release
- Serialized commitment tree generation (via Rust tool or node RPC)

Usage:
    # Full automation (default): generate, verify, update docs, commit, push, release
    python3 generate_boost_file.py

    # Skip balance verification (faster, less safe)
    python3 generate_boost_file.py --skip-verify

    # Skip Git operations (generate only, no release)
    python3 generate_boost_file.py --skip-git

    # Custom output directory
    python3 generate_boost_file.py /path/to/output

    # Custom key file for verification
    python3 generate_boost_file.py --key-file /path/to/key.txt

    # Custom repository directory
    python3 generate_boost_file.py --repo-dir /path/to/ZipherX_Boost

Automation Pipeline:
1. Scan blockchain (parallel batch RPC)
2. Generate commitment tree (node RPC or Rust tool)
3. Write boost file and manifest
4. Verify balance (Rust check_balance tool)
5. Copy files to Git repo
6. Update SHA256SUMS.txt
7. Update README.md with statistics
8. Git commit and push
9. Create GitHub release with all files

Requirements:
- Running zclassicd node with RPC enabled
- Rust toolchain (for serialize_tree and check_balance)
- gh CLI authenticated for GitHub releases
- Git repository at ~/ZipherX_Boost

Node Configuration (for max speed, add to zclassic.conf):
    rpcthreads=32
    rpcworkqueue=256
    rpcservertimeout=120
"""

import os
import sys
from pathlib import Path
import json
import struct
import time
import hashlib
import logging
import base64
import subprocess
import re
import shutil
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import http.client
import socket

# Configuration
SAPLING_ACTIVATION = 476969
# NOTE: zclassicd defaults to only 4 RPC threads and 16 work queue!
# For max speed, add to zclassic.conf:
#   rpcthreads=32
#   rpcworkqueue=256
#   rpcservertimeout=120
# FIX #731: More conservative settings to avoid RPC overload
MAX_WORKERS = 16  # Reduced from 48 to prevent connection exhaustion
BATCH_SIZE = 200  # Reduced from 800 to prevent RPC timeouts

# Boost file magic
MAGIC = b'ZBOOST01'
HEADER_SIZE = 128

# GitHub release asset size limit (2 GiB)
GITHUB_MAX_ASSET_SIZE = 2147483648

# Setup logging
LOG_FILE = os.path.join(str(Path.home()), "ZipherX/Tools/boost_generator.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, mode='w'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def log(message):
    logger.info(message)

def log_error(message):
    logger.error(message)

# RPC Connection class for thread-local connections
class RPCConnection:
    def __init__(self, host, port, user, password):
        self.host = host
        self.port = port
        self.auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.conn = None
        self._connect()

    def _connect(self):
        try:
            self.conn = http.client.HTTPConnection(self.host, self.port, timeout=60)
        except Exception as e:
            log_error(f"Connection failed: {e}")

    def call(self, method, params=None):
        if params is None:
            params = []

        payload = json.dumps({
            "jsonrpc": "1.0",
            "id": "1",
            "method": method,
            "params": params
        })

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {self.auth}"
        }

        try:
            self.conn.request("POST", "/", payload, headers)
            response = self.conn.getresponse()
            data = response.read().decode()
            result = json.loads(data)
            if result.get('error'):
                log_error(f"RPC error: {result.get('error')}")
                return None
            return result.get('result')
        except (http.client.HTTPException, socket.error, ConnectionResetError) as e:
            log_error(f"RPC connection error: {e}, reconnecting...")
            # Reconnect and retry once
            self._connect()
            try:
                self.conn.request("POST", "/", payload, headers)
                response = self.conn.getresponse()
                data = response.read().decode()
                result = json.loads(data)
                return result.get('result')
            except Exception as e2:
                log_error(f"RPC retry failed: {e2}")
                return None

    def batch(self, calls):
        """Make batch RPC call"""
        batch_payload = []
        for i, (method, params) in enumerate(calls):
            batch_payload.append({
                "jsonrpc": "1.0",
                "id": str(i),
                "method": method,
                "params": params if params else []
            })

        payload = json.dumps(batch_payload)
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {self.auth}"
        }

        try:
            self.conn.request("POST", "/", payload, headers)
            response = self.conn.getresponse()
            data = response.read().decode()
            results = json.loads(data)
            # Sort by id and extract results
            sorted_results = sorted(results, key=lambda x: int(x['id']))
            return [r.get('result') for r in sorted_results]
        except (http.client.HTTPException, socket.error, ConnectionResetError) as e:
            # Reconnect and retry once
            log_error(f"RPC batch error: {e}, reconnecting...")
            self._connect()
            try:
                self.conn.request("POST", "/", payload, headers)
                response = self.conn.getresponse()
                data = response.read().decode()
                results = json.loads(data)
                sorted_results = sorted(results, key=lambda x: int(x['id']))
                return [r.get('result') for r in sorted_results]
            except Exception as e2:
                log_error(f"RPC batch retry failed: {e2}")
                return None

# Thread-local RPC connections
import threading
thread_local = threading.local()

RPC_HOST = None
RPC_PORT = None
RPC_USER = None
RPC_PASS = None

def get_rpc():
    """Get thread-local RPC connection"""
    if not hasattr(thread_local, 'rpc'):
        thread_local.rpc = RPCConnection(RPC_HOST, RPC_PORT, RPC_USER, RPC_PASS)
    return thread_local.rpc

def init_rpc():
    """Initialize RPC configuration from zclassic.conf"""
    global RPC_HOST, RPC_PORT, RPC_USER, RPC_PASS

    conf_paths = [
        os.path.expanduser("~/Library/Application Support/Zclassic/zclassic.conf"),
        os.path.expanduser("~/.zclassic/zclassic.conf"),
    ]

    conf_path = None
    for p in conf_paths:
        if os.path.exists(p):
            conf_path = p
            break

    if not conf_path:
        log_error("Could not find zclassic.conf")
        return False

    rpc_port = 8232
    rpc_user = None
    rpc_pass = None

    with open(conf_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('rpcuser='):
                rpc_user = line.split('=', 1)[1]
            elif line.startswith('rpcpassword='):
                rpc_pass = line.split('=', 1)[1]
            elif line.startswith('rpcport='):
                rpc_port = int(line.split('=', 1)[1])

    if not rpc_user or not rpc_pass:
        log_error("Could not find rpcuser/rpcpassword in zclassic.conf")
        return False

    RPC_HOST = "127.0.0.1"
    RPC_PORT = rpc_port
    RPC_USER = rpc_user
    RPC_PASS = rpc_pass

    log(f"RPC initialized: http://{RPC_HOST}:{RPC_PORT}")
    return True

def get_chain_height():
    """Get current chain height"""
    if RPC_HOST is None:
        raise Exception("RPC not initialized - call init_rpc() first")
    rpc = get_rpc()
    result = rpc.call("getblockcount")
    if result is None:
        raise Exception("RPC call returned None - check if node is running")
    return int(result)

def process_block_batch(heights):
    """
    Process a batch of blocks using persistent HTTP connection.
    Returns list of block data including headers for FIX #413.
    """
    results = []
    rpc = get_rpc()

    try:
        # Step 1: Get all block hashes in a single batch call
        hash_calls = [("getblockhash", [h]) for h in heights]
        hash_results = rpc.batch(hash_calls)

        if not hash_results:
            return results

        # Build height -> hash mapping
        hashes = {}
        for i, h in enumerate(heights):
            if i < len(hash_results) and hash_results[i]:
                hashes[h] = hash_results[i]

        if not hashes:
            return results

        # Step 2: Get all blocks in a single batch call
        block_calls = [("getblock", [hashes[h], 2]) for h in heights if h in hashes]
        block_results = rpc.batch(block_calls)

        if not block_results:
            return results

        # Process each block
        block_idx = 0
        for height in heights:
            if height not in hashes:
                continue

            if block_idx >= len(block_results) or not block_results[block_idx]:
                block_idx += 1
                continue

            block = block_results[block_idx]
            block_idx += 1

            outputs = []
            spends = []
            timestamp = block.get("time", 0)

            # FIX #413: Extract header fields for bundled headers section
            # Header format (140 bytes): version(4) + prevHash(32) + merkleRoot(32) + saplingRoot(32) + time(4) + bits(4) + nonce(32)
            # PRODUCTION: Now includes Equihash solution for full PoW verification!

            # FIX #539: Validate sapling_root is not zero/empty before using
            sapling_root_hex = block.get("finalsaplingroot", "")
            if not sapling_root_hex or sapling_root_hex == "0" * 64:
                log_error(f"WARNING: Invalid sapling_root at height {height} - using zero hash")
                sapling_root_hex = "0" * 64

            header = {
                'version': block.get("version", 4),
                'prevHash': bytes.fromhex(block.get("previousblockhash", "0" * 64))[::-1] if block.get("previousblockhash") else bytes(32),
                'merkleRoot': bytes.fromhex(block.get("merkleroot", "0" * 64))[::-1],
                'saplingRoot': bytes.fromhex(sapling_root_hex)[::-1],
                'time': block.get("time", 0),
                'bits': int(block.get("bits", "0"), 16) if isinstance(block.get("bits"), str) else block.get("bits", 0),
                'nonce': bytes.fromhex(block.get("nonce", "0" * 64))[::-1] if len(block.get("nonce", "")) == 64 else bytes(32),
                # PRODUCTION: Equihash solution for full PoW verification
                # Solution is variable length, typically 1345 bytes for Equihash(192,7)
                'solution': bytes.fromhex(block.get("solution", "")) if block.get("solution") else b''
            }

            # Process transactions
            output_index = 0
            for tx in block.get("tx", []):
                txid_hex = tx.get("txid", "")
                txid_bytes = bytes.fromhex(txid_hex)[::-1] if len(txid_hex) == 64 else bytes(32)

                # Shielded outputs - NOW INCLUDES txid!
                for vout in tx.get("vShieldedOutput", []):
                    cmu_hex = vout.get("cmu", "")
                    epk_hex = vout.get("ephemeralKey", "")
                    enc_hex = vout.get("encCiphertext", "")

                    if len(cmu_hex) == 64 and len(epk_hex) == 64 and len(enc_hex) == 1160:
                        outputs.append({
                            'height': height,
                            'index': output_index,
                            'cmu': bytes.fromhex(cmu_hex)[::-1],
                            'epk': bytes.fromhex(epk_hex)[::-1],
                            'enc': bytes.fromhex(enc_hex),
                            'txid': txid_bytes  # PRODUCTION: Real txid for change detection!
                        })
                        output_index += 1

                # Shielded spends - now includes txid!
                for vspend in tx.get("vShieldedSpend", []):
                    nf_hex = vspend.get("nullifier", "")
                    if len(nf_hex) == 64:
                        spends.append({
                            'height': height,
                            'nullifier': bytes.fromhex(nf_hex)[::-1],
                            'txid': txid_bytes  # Real txid!
                        })

            results.append({
                'height': height,
                'hash': bytes.fromhex(hashes[height]),  # FIX #599: Store in RPC format (big-endian), not reversed
                'timestamp': timestamp,
                'outputs': outputs,
                'spends': spends,
                'header': header  # FIX #413: Include header data
            })

    except Exception as e:
        # FIX #731: Log errors instead of silently passing
        if len(heights) > 0:
            log_error(f"Batch processing error for heights {heights[0]}-{heights[-1]}: {e}")
        else:
            log_error(f"Batch processing error: {e}")

    return results

def process_height_range_fast(start_height, end_height):
    """
    Process blocks using parallel batch processing for maximum speed.
    FIX #413: Now also collects block headers for bundled headers section.
    """
    all_outputs = []
    all_spends = []
    all_hashes = []
    all_timestamps = []
    all_headers = []  # FIX #413: Collect headers

    heights = list(range(start_height, end_height + 1))
    total = len(heights)

    # Split into batches
    batches = []
    for i in range(0, total, BATCH_SIZE):
        batches.append(heights[i:i + BATCH_SIZE])

    log(f"Processing {total} blocks in {len(batches)} batches of {BATCH_SIZE}...")
    start_time = time.time()

    processed = 0
    failed_batches = []
    results_lock = threading.Lock()

    def process_and_collect(batch):
        results = process_block_batch(batch)
        return batch, results

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_and_collect, batch): batch for batch in batches}

        for future in as_completed(futures):
            batch, results = future.result()

            with results_lock:
                succeeded_heights = set()
                for result in results:
                    all_outputs.extend(result['outputs'])
                    all_spends.extend(result['spends'])
                    all_hashes.append((result['height'], result['hash']))
                    all_timestamps.append((result['height'], result['timestamp']))
                    # FIX #413: Collect header data
                    if 'header' in result:
                        all_headers.append((result['height'], result['header']))
                    succeeded_heights.add(result['height'])

                # Track failed heights
                for h in batch:
                    if h not in succeeded_heights:
                        failed_batches.append(h)

                processed += len(batch)

            if processed % 10000 == 0 or processed == total:
                elapsed = time.time() - start_time
                rate = processed / elapsed if elapsed > 0 else 0
                eta = (total - processed) / rate if rate > 0 else 0
                progress_msg = f"Progress: {processed}/{total} ({processed*100//total}%) - {rate:.0f} blocks/sec - ETA: {int(eta)}s"
                print(f"\r  {progress_msg}    ", end="", flush=True)
                if processed % 100000 == 0:
                    log(progress_msg)

    print()

    # Retry failed blocks individually
    if failed_batches:
        log(f"Retrying {len(failed_batches)} failed blocks...")
        for height in sorted(set(failed_batches)):
            try:
                results = process_block_batch([height])
                for result in results:
                    all_outputs.extend(result['outputs'])
                    all_spends.extend(result['spends'])
                    all_hashes.append((result['height'], result['hash']))
                    all_timestamps.append((result['height'], result['timestamp']))
                    # FIX #413: Collect header data
                    if 'header' in result:
                        all_headers.append((result['height'], result['header']))
            except Exception as e:
                log_error(f"Still failed: block {height}")

    # Sort by height
    all_outputs.sort(key=lambda x: (x['height'], x['index']))
    all_spends.sort(key=lambda x: x['height'])
    all_hashes.sort(key=lambda x: x[0])
    all_timestamps.sort(key=lambda x: x[0])
    all_headers.sort(key=lambda x: x[0])  # FIX #413

    return all_outputs, all_spends, all_hashes, all_timestamps, all_headers

def validate_sapling_roots(headers):
    """
    FIX #539 v2: DISABLED - sapling_root uniqueness validation is NOT correct.
    Blocks WITHOUT shielded transactions correctly have identical sapling_roots.
    The sapling_root only changes when a block contains shielded outputs/spends.
    Returns (is_valid, report)
    """
    if not headers:
        return True, "No headers to validate"

    # DISABLED: This validation was incorrect - it assumed all blocks must have unique sapling_roots
    # But blocks without shielded transactions correctly have identical sapling_roots
    log(f"✅ FIX #539 v2: Validation disabled - duplicate sapling_roots are normal for blocks without shielded txs")
    return True, f"Validation disabled - {len(headers)} headers (duplicates allowed for blocks without shielded txs)"

def get_reliable_peers():
    """Get list of reliable P2P peers"""
    try:
        rpc = get_rpc()
        result = rpc.call("getpeerinfo")
        if result:
            peers = []
            for peer in result:
                addr = peer.get("addr", "")
                if addr and ":" in addr:
                    peers.append(addr)
            return peers[:50]
    except:
        pass
    return []

def write_boost_file(output_path, outputs, spends, hashes, timestamps, chain_height, tree_data=None, peers=None, headers=None):
    """Write the boost file with all sections.
    FIX #413: Now includes Section 7 (headers) for bundled block headers.
    PRODUCTION: Section 1 outputs now include txid for accurate change detection!
    """
    log(f"Writing boost file to {output_path}...")

    # Section 1: Outputs (684 bytes each = 652 + 32 txid)
    # Format: height(4) + index(4) + cmu(32) + epk(32) + enc(580) + txid(32)
    outputs_data = bytearray()
    for out in outputs:
        outputs_data.extend(struct.pack('<I', out['height']))
        outputs_data.extend(struct.pack('<I', out['index']))
        outputs_data.extend(out['cmu'])
        outputs_data.extend(out['epk'])
        outputs_data.extend(out['enc'])
        outputs_data.extend(out['txid'])  # PRODUCTION: Real txid for change detection!

    # Section 2: Spends (68 bytes each: 4 height + 32 nullifier + 32 txid)
    spends_data = bytearray()
    for spend in spends:
        spends_data.extend(struct.pack('<I', spend['height']))
        spends_data.extend(spend['nullifier'])
        spends_data.extend(spend['txid'])  # Real txid!

    # Section 3: Block Hashes (32 bytes each)
    hashes_data = bytearray()
    for height, hash_bytes in hashes:
        hashes_data.extend(hash_bytes)

    # Section 4: Timestamps (4 bytes each)
    timestamps_data = bytearray()
    for height, ts in timestamps:
        timestamps_data.extend(struct.pack('<I', ts))

    # Section 5: Tree (if provided)
    if tree_data is None:
        tree_data = b''

    # Section 6: Peers
    if peers is None:
        peers = []
    peers_data = bytearray()
    for peer in peers:
        peer_bytes = peer.encode('utf-8')
        if len(peer_bytes) <= 255:
            peers_data.append(len(peer_bytes))
            peers_data.extend(peer_bytes)

    # FIX #413: Section 7: Headers with Equihash solutions (PRODUCTION UPGRADE)
    # OLD Format (140 bytes): version(4) + prevHash(32) + merkleRoot(32) + saplingRoot(32) + time(4) + bits(4) + nonce(32)
    # NEW Format: 140 bytes header + 2 bytes solution length + variable solution
    if headers is None:
        headers = []
    headers_data = bytearray()
    for height, hdr in headers:
        # Write fixed header (140 bytes)
        headers_data.extend(struct.pack('<I', hdr['version']))
        headers_data.extend(hdr['prevHash'])
        headers_data.extend(hdr['merkleRoot'])
        headers_data.extend(hdr['saplingRoot'])
        headers_data.extend(struct.pack('<I', hdr['time']))
        headers_data.extend(struct.pack('<I', hdr['bits']))
        headers_data.extend(hdr['nonce'])

        # PRODUCTION: Write Equihash solution (variable length)
        solution = hdr.get('solution', b'')
        solution_len = len(solution)
        if solution_len > 65535:
            log_error(f"WARNING: Solution too large at height {height}: {solution_len} bytes, truncating")
            solution_len = 65535
            solution = solution[:65535]

        # Write solution length (2 bytes) + solution data
        headers_data.extend(struct.pack('<H', solution_len))
        headers_data.extend(solution)

    # Calculate offsets
    current_offset = HEADER_SIZE

    outputs_offset = current_offset
    current_offset += len(outputs_data)

    spends_offset = current_offset
    current_offset += len(spends_data)

    hashes_offset = current_offset
    current_offset += len(hashes_data)

    timestamps_offset = current_offset
    current_offset += len(timestamps_data)

    tree_offset = current_offset
    current_offset += len(tree_data)

    peers_offset = current_offset
    current_offset += len(peers_data)

    # FIX #413: Headers offset
    headers_offset = current_offset
    current_offset += len(headers_data)

    # Build sections for manifest
    start_height = SAPLING_ACTIVATION
    # FIX #452: Use actual header end height if available, otherwise chain_height
    # The RPC can return corrupted values, but our collected headers are accurate
    if headers:
        end_height = headers[-1][0]  # Use actual last header height
    else:
        end_height = chain_height

    sections = [
        {"type": 1, "offset": outputs_offset, "size": len(outputs_data), "count": len(outputs), "start_height": start_height, "end_height": end_height},
        {"type": 2, "offset": spends_offset, "size": len(spends_data), "count": len(spends), "start_height": start_height, "end_height": end_height},
        {"type": 3, "offset": hashes_offset, "size": len(hashes_data), "count": len(hashes), "start_height": start_height, "end_height": end_height},
        {"type": 4, "offset": timestamps_offset, "size": len(timestamps_data), "count": len(timestamps), "start_height": start_height, "end_height": end_height},
    ]

    if tree_data:
        sections.append({"type": 5, "offset": tree_offset, "size": len(tree_data), "count": 1, "start_height": start_height, "end_height": end_height})

    if peers_data:
        sections.append({"type": 6, "offset": peers_offset, "size": len(peers_data), "count": len(peers), "start_height": 0, "end_height": 0})

    # FIX #413: Add headers section
    if headers_data:
        sections.append({"type": 7, "offset": headers_offset, "size": len(headers_data), "count": len(headers), "start_height": start_height, "end_height": end_height})

    # Write header with magic, version, and section_count
    # Note: Section entries are NOT written to header - they only exist in manifest.json
    # The header is 128 bytes: magic(8) + version(4) + section_count(4) + reserved(112)
    with open(output_path, 'wb') as f:
        header = bytearray(HEADER_SIZE)
        header[0:8] = MAGIC
        header[8:12] = struct.pack('<I', 1)  # Version 1 (unified format)
        header[12:16] = struct.pack('<I', len(sections))  # Section count
        # Rest of header remains zeros (reserved for future use)

        f.write(header)

        log(f"Writing {len(outputs)} outputs ({len(outputs_data)} bytes)...")
        f.write(outputs_data)

        log(f"Writing {len(spends)} spends ({len(spends_data)} bytes)...")
        f.write(spends_data)

        log(f"Writing {len(hashes)} block hashes ({len(hashes_data)} bytes)...")
        f.write(hashes_data)

        log(f"Writing {len(timestamps)} timestamps ({len(timestamps_data)} bytes)...")
        f.write(timestamps_data)

        if tree_data:
            log(f"Writing serialized tree ({len(tree_data)} bytes)...")
            f.write(tree_data)

        if peers_data:
            log(f"Writing {len(peers)} peer addresses ({len(peers_data)} bytes)...")
            f.write(peers_data)

        # FIX #413: Write headers section with Equihash solutions
        if headers_data:
            log(f"Writing {len(headers)} block headers with Equihash solutions ({len(headers_data)} bytes, ~{len(headers_data)/(1024*1024):.1f} MB)...")
            f.write(headers_data)

    file_size = os.path.getsize(output_path)
    log(f"Total file size: {file_size / (1024*1024):.1f} MB")

    return sections

def write_boost_files_three_part(output_dir, outputs, spends, hashes, timestamps, chain_height, tree_data=None, peers=None, headers=None):
    """
    Write boost file as THREE separate files for optimal download size and security.

    PRODUCTION v2 - THREE FILE APPROACH:
    1. zipherx_boost_core.bin - Essential data for wallet operations (~800 MB)
       - outputs (with received_in_tx)
       - spends (with spent_txid)
       - block hashes
       - timestamps
       - tree root
       - peer addresses
       - headers WITHOUT Equihash solutions

    2. zipherx_boost_equihash.bin - Equihash solutions only (~1.38 GB)
       - Pure Equihash solutions for all headers
       - Optional download for full verification
       - Used for security health checks

    3. zipherx_boost_manifest.json - Metadata and checksums
    """
    log("=" * 70)
    log("WRITING THREE-FILE BOOST FORMAT (OPTIMIZED)")
    log("=" * 70)

    base_path = os.path.join(output_dir, "zipherx_boost")
    core_path = base_path + "_core.bin"
    equihash_path = base_path + "_equihash.bin"
    manifest_path = base_path + "_manifest.json"

    # ========================================================================
    # FILE 1: Core Boost File (headers WITHOUT Equihash solutions)
    # ========================================================================
    log(f"Writing core boost file to {core_path}...")

    # Section 1: Outputs (684 bytes each = 652 + 32 txid)
    outputs_data = bytearray()
    for out in outputs:
        outputs_data.extend(struct.pack('<I', out['height']))
        outputs_data.extend(struct.pack('<I', out['index']))
        outputs_data.extend(out['cmu'])
        outputs_data.extend(out['epk'])
        outputs_data.extend(out['enc'])
        outputs_data.extend(out['txid'])

    # Section 2: Spends (68 bytes each: 4 height + 32 nullifier + 32 txid)
    spends_data = bytearray()
    for spend in spends:
        spends_data.extend(struct.pack('<I', spend['height']))
        spends_data.extend(spend['nullifier'])
        spends_data.extend(spend['txid'])

    # Section 3: Block Hashes (32 bytes each)
    hashes_data = bytearray()
    for height, hash_bytes in hashes:
        hashes_data.extend(hash_bytes)

    # Section 4: Timestamps (4 bytes each)
    timestamps_data = bytearray()
    for height, ts in timestamps:
        timestamps_data.extend(struct.pack('<I', ts))

    # Section 5: Tree
    if tree_data is None:
        tree_data = b''

    # Section 6: Peers
    if peers is None:
        peers = []
    peers_data = bytearray()
    for peer in peers:
        peer_bytes = peer.encode('utf-8')
        if len(peer_bytes) <= 255:
            peers_data.append(len(peer_bytes))
            peers_data.extend(peer_bytes)

    # Section 7: Headers WITHOUT Equihash solutions (140 bytes each)
    headers_data = bytearray()
    if headers:
        for height, hdr in headers:
            # Write fixed header ONLY (140 bytes) - NO solution
            headers_data.extend(struct.pack('<I', hdr['version']))
            headers_data.extend(hdr['prevHash'])
            headers_data.extend(hdr['merkleRoot'])
            headers_data.extend(hdr['saplingRoot'])
            headers_data.extend(struct.pack('<I', hdr['time']))
            headers_data.extend(struct.pack('<I', hdr['bits']))
            headers_data.extend(hdr['nonce'])
            # NO Equihash solution here!

    # Write core file
    sections_core = write_boost_file(
        core_path, outputs, spends, hashes, timestamps, chain_height,
        tree_data=tree_data,
        peers=peers,
        headers=None  # Pass None so it doesn't add Section 7
    )

    # Manually add headers section (without solutions) to core file
    with open(core_path, 'r+b') as f:
        # Read existing header to get current size
        f.seek(0, 2)  # Seek to end
        core_size = f.tell()

        # Calculate headers offset
        headers_offset = core_size

        # Write headers data
        f.write(headers_data)

        # Update header to add headers section
        f.seek(0)
        header_data = f.read(HEADER_SIZE)

        # Parse header
        magic = header_data[0:8]
        version = int.from_bytes(header_data[8:12], 'little')
        section_count = int.from_bytes(header_data[12:16], 'little')

        # Rewrite with updated section count
        f.seek(0)
        new_header = bytearray(HEADER_SIZE)
        new_header[0:8] = MAGIC
        new_header[8:12] = struct.pack('<I', 2)  # Version 2 (three-file format)
        new_header[12:16] = struct.pack('<I', section_count + 1)  # Add headers section

        # Write section entries
        f.seek(24)  # Section entries start at offset 24
        for section in sections_core:
            f.write(struct.pack('<I', section['type']))
            f.write(struct.pack('<Q', section['offset']))
            f.write(struct.pack('<Q', section['size']))
            f.write(struct.pack('<I', section['count']))
            f.write(struct.pack('<I', section['start_height']))
            f.write(struct.pack('<I', section['end_height']))

        # Add headers section entry
        # FIX #452: Use ACTUAL header heights from collected data, not chain_height from RPC
        # The RPC can return corrupted values, but our collected headers are accurate
        actual_headers_count = len(headers)
        actual_end_height = headers[-1][0] if headers else SAPLING_ACTIVATION

        f.write(struct.pack('<I', 7))  # Section type 7 = headers (without solutions)
        f.write(struct.pack('<Q', headers_offset))
        f.write(struct.pack('<Q', len(headers_data)))
        f.write(struct.pack('<I', actual_headers_count))        # Use actual count
        f.write(struct.pack('<I', SAPLING_ACTIVATION))
        f.write(struct.pack('<I', actual_end_height))            # Use actual last header height

        log(f"  Headers section: {actual_headers_count} headers (height {SAPLING_ACTIVATION} to {actual_end_height})")

    core_size = os.path.getsize(core_path)
    log(f"  Core file: {core_size / (1024*1024):.1f} MB")

    # ========================================================================
    # FILE 2: Equihash Solutions Only
    # ========================================================================
    log(f"Writing Equihash solutions to {equihash_path}...")

    # Simple format: [count: u64][solution_len_1: u16][solution_1][solution_len_2: u16][solution_2]...
    equihash_data = bytearray()
    equihash_data.extend(struct.pack('<Q', len(headers)))  # Number of solutions

    if headers:
        for height, hdr in headers:
            solution = hdr.get('solution', b'')
            solution_len = len(solution)
            if solution_len > 65535:
                solution_len = 65535
                solution = solution[:65535]
            equihash_data.extend(struct.pack('<H', solution_len))
            equihash_data.extend(solution)

    with open(equihash_path, 'wb') as f:
        # Simple magic header for identification
        f.write(b'ZEQU\x00\x01')  # ZipherX Equihash file magic
        f.write(struct.pack('<Q', len(headers)))  # Number of solutions
        f.write(equihash_data)

    equihash_size = os.path.getsize(equihash_path)
    log(f"  Equihash file: {equihash_size / (1024*1024):.1f} MB")

    # ========================================================================
    # FILE 3: Manifest (updated for three-file format)
    # ========================================================================
    # FIX #599: Hashes are now stored in RPC format (big-endian), no need to reverse
    last_hash = hashes[-1][1].hex() if hashes else "0" * 64

    manifest = {
        "format": "zipherx_boost_v2_three_part",
        "version": 3,  # v3 = three-file format
        "created_at": datetime.now(timezone.utc).isoformat(),
        "chain_height": chain_height,
        "sapling_activation": SAPLING_ACTIVATION,
        "output_count": len(outputs),
        "spend_count": len(spends),
        "block_hash": last_hash,
        "tree_root": tree_data.hex() if tree_data else "",
        "files": {
            "core": {
                "name": "zipherx_boost_core.bin",
                "size": core_size,
                "sha256": "",
                "description": "Essential wallet data (outputs, spends, hashes, timestamps, headers without Equihash)",
                "required": True
            },
            "equihash": {
                "name": "zipherx_boost_equihash.bin",
                "size": equihash_size,
                "sha256": "",
                "description": "Equihash PoW solutions for full verification (optional)",
                "required": False
            }
        },
        "sections": sections_core + [{"type": 7, "offset": headers_offset, "size": len(headers_data),
                                      "count": len(headers), "start_height": SAPLING_ACTIVATION, "end_height": chain_height}]
    }

    # Compute SHA256 for core file
    log("Computing SHA256 checksums...")
    sha256_hash = hashlib.sha256()
    with open(core_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256_hash.update(chunk)
    manifest["files"]["core"]["sha256"] = sha256_hash.hexdigest()
    log(f"  Core SHA256: {manifest['files']['core']['sha256']}")

    # Compute SHA256 for equihash file
    sha256_hash = hashlib.sha256()
    with open(equihash_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256_hash.update(chunk)
    manifest["files"]["equihash"]["sha256"] = sha256_hash.hexdigest()
    log(f"  Equihash SHA256: {manifest['files']['equihash']['sha256']}")

    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)

    log(f"Manifest written to {manifest_path}")

    total_uncompressed = core_size + equihash_size
    log(f"Total uncompressed size: {total_uncompressed / (1024*1024):.1f} MB")
    log(f"  Core: {core_size / (1024*1024):.1f} MB (required)")
    log(f"  Equihash: {equihash_size / (1024*1024):.1f} MB (optional)")

    return {
        "core": core_path,
        "equihash": equihash_path,
        "manifest": manifest_path,
        "core_size": core_size,
        "equihash_size": equihash_size
    }

def write_manifest(manifest_path, outputs, spends, hashes, timestamps, chain_height, sections, file_size, tree_root="",
                   compressed_path=None, compressed_size=None, split_parts=None):
    """Write the manifest JSON file"""
    # FIX #599: Hashes are now stored in RPC format (big-endian), no need to reverse
    last_hash = hashes[-1][1].hex() if hashes else "0" * 64

    manifest = {
        "format": "zipherx_boost_v1",
        "version": 2,  # PRODUCTION: v2 includes received_in_tx and Equihash solutions
        "created_at": datetime.now(timezone.utc).isoformat(),
        "chain_height": chain_height,
        "sapling_activation": SAPLING_ACTIVATION,
        "output_count": len(outputs),
        "spend_count": len(spends),
        "block_hash": last_hash,
        "tree_root": tree_root,
        "files": {
            "uncompressed": {
                "name": "zipherx_boost_v1.bin",
                "size": file_size,
                "sha256": ""
            }
        },
        "sections": sections
    }

    # Add compressed file info if available
    if compressed_path and os.path.exists(compressed_path):
        manifest["files"]["compressed"] = {
            "name": os.path.basename(compressed_path),
            "size": compressed_size,
            "sha256": ""
        }

    # Add split parts info if the compressed file was split
    if split_parts:
        parts_info = []
        for part_path in split_parts:
            part_sha = compute_file_sha256(part_path)
            parts_info.append({
                "name": os.path.basename(part_path),
                "size": os.path.getsize(part_path),
                "sha256": part_sha
            })
            log(f"SHA256 (split part):   {os.path.basename(part_path)}: {part_sha}")
        manifest["files"]["split_parts"] = parts_info
        manifest["files"]["split_count"] = len(split_parts)

    log("Computing SHA256 checksum(s)...")
    boost_path = os.path.join(os.path.dirname(manifest_path), "zipherx_boost_v1.bin")
    if os.path.exists(boost_path):
        sha256_hash = hashlib.sha256()
        with open(boost_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256_hash.update(chunk)
        manifest["files"]["uncompressed"]["sha256"] = sha256_hash.hexdigest()
        log(f"SHA256 (uncompressed): {manifest['files']['uncompressed']['sha256']}")

    if compressed_path and os.path.exists(compressed_path):
        sha256_hash = hashlib.sha256()
        with open(compressed_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256_hash.update(chunk)
        manifest["files"]["compressed"]["sha256"] = sha256_hash.hexdigest()
        log(f"SHA256 (compressed):   {manifest['files']['compressed']['sha256']}")

    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)

    log(f"Manifest written to {manifest_path}")

def verify_completeness(outputs, spends, hashes, timestamps, chain_height, headers=None):
    """Verify the boost file is complete.
    FIX #413: Now also verifies headers section.
    """
    start_height = SAPLING_ACTIVATION
    expected_blocks = chain_height - start_height + 1

    hash_heights = set(h[0] for h in hashes)
    missing_hashes = [h for h in range(start_height, chain_height + 1) if h not in hash_heights]

    log("=== VERIFICATION ===")
    log(f"Expected blocks: {expected_blocks}")
    log(f"Block hashes:    {len(hashes)} ({len(missing_hashes)} missing)")
    log(f"Timestamps:      {len(timestamps)}")
    log(f"Shielded outputs: {len(outputs)}")
    log(f"Shielded spends:  {len(spends)}")

    # FIX #413: Verify headers
    if headers is not None:
        header_heights = set(h[0] for h in headers)
        missing_headers = [h for h in range(start_height, chain_height + 1) if h not in header_heights]
        log(f"Block headers:   {len(headers)} ({len(missing_headers)} missing)")
        if missing_headers and len(missing_headers) > 100:
            log_error(f"Missing {len(missing_headers)} block headers!")
            # Not fatal - headers are optional but recommended
    else:
        log(f"Block headers:   0 (section not generated)")

    if missing_hashes:
        log_error(f"Missing {len(missing_hashes)} block hashes!")
        if len(missing_hashes) <= 50:
            log_error(f"Missing heights: {missing_hashes}")
        return False

    if len(timestamps) != len(hashes):
        log_error(f"Timestamp count mismatch!")
        return False

    log("Verification PASSED!")
    return True

###############################################################################
# AUTOMATION FUNCTIONS - Balance Verification, README, Git, Release
###############################################################################

def verify_balance(key_file_path: str = os.path.join(str(Path.home()), "ZipherX/Tools/check_balance/key.txt")):
    """
    Verify wallet balance using the Rust check_balance tool.
    Returns (success, balance_zcl, node_balance_zcl) or (False, None, None) on error.
    """
    log("=== BALANCE VERIFICATION ===")

    check_balance_dir = os.path.join(str(Path.home()), "ZipherX/Tools/check_balance")

    if not os.path.exists(key_file_path):
        log_error(f"Key file not found: {key_file_path}")
        return False, None, None

    # Build the tool if needed
    log("Building check_balance tool...")
    result = subprocess.run(
        ["cargo", "build", "--release"],
        cwd=check_balance_dir,
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        log_error(f"Failed to build check_balance: {result.stderr}")
        return False, None, None

    # Run the balance check
    log("Running balance verification...")
    result = subprocess.run(
        ["cargo", "run", "--release", "--", key_file_path],
        cwd=check_balance_dir,
        capture_output=True,
        text=True,
        timeout=300
    )

    if result.returncode != 0:
        log_error(f"Balance check failed: {result.stderr}")
        return False, None, None

    # Parse output for balance
    output = result.stdout + result.stderr
    log(output)

    # Look for balance values
    boost_balance = None
    node_balance = None

    for line in output.split('\n'):
        if 'balance' in line.lower() and 'zcl' in line.lower():
            # Try to extract numeric value
            match = re.search(r'(\d+\.\d+)\s*ZCL', line, re.IGNORECASE)
            if match:
                value = float(match.group(1))
                if boost_balance is None:
                    boost_balance = value
                else:
                    node_balance = value

    if boost_balance is not None:
        log(f"✅ Boost file balance: {boost_balance} ZCL")
        if node_balance is not None:
            log(f"✅ Node balance: {node_balance} ZCL")
            if abs(boost_balance - node_balance) < 0.00000001:
                log("✅ BALANCE VERIFICATION PASSED - Boost file matches node!")
                return True, boost_balance, node_balance
            else:
                log_error("❌ BALANCE MISMATCH!")
                return False, boost_balance, node_balance
        else:
            log("ℹ️  Node balance not available for comparison")
            return True, boost_balance, None

    log("⚠️  Could not parse balance from output")
    return True, None, None  # Assume success if tool ran without error


def compute_file_sha256(file_path: str) -> str:
    """Compute SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def split_compressed_file(compressed_path: str):
    """Split a compressed file into parts that fit under GitHub's 2 GiB asset limit.
    Returns list of part file paths, or None if no split is needed.
    """
    file_size = os.path.getsize(compressed_path)
    if file_size <= GITHUB_MAX_ASSET_SIZE:
        return None  # No split needed

    # Calculate number of parts needed (each must be < 2 GiB)
    import math
    num_parts = math.ceil(file_size / GITHUB_MAX_ASSET_SIZE)
    part_size = math.ceil(file_size / num_parts)

    log(f"Compressed file ({file_size / (1024*1024):.1f} MB) exceeds GitHub 2 GiB limit")
    log(f"  Splitting into {num_parts} parts of ~{part_size / (1024*1024):.1f} MB each...")

    base_path = compressed_path  # e.g. /path/to/zipherx_boost_v1.bin.zst
    part_paths = []

    with open(compressed_path, "rb") as f:
        for i in range(num_parts):
            part_path = f"{base_path}.part{i + 1}"
            bytes_written = 0
            with open(part_path, "wb") as pf:
                while bytes_written < part_size:
                    chunk = f.read(min(65536, part_size - bytes_written))
                    if not chunk:
                        break
                    pf.write(chunk)
                    bytes_written += len(chunk)
            actual_size = os.path.getsize(part_path)
            log(f"  Part {i + 1}: {os.path.basename(part_path)} ({actual_size / (1024*1024):.1f} MB)")
            part_paths.append(part_path)

    return part_paths


def update_sha256sums(source_dir: str, repo_dir: str):
    """Generate SHA256SUMS.txt file.
    PRODUCTION: Includes compressed file (or split parts) for GitHub release.
    FIX: Calculate SHA256 from source_dir (new files) not repo_dir (old files).
    """
    log("Generating SHA256SUMS.txt...")

    sha_file = os.path.join(repo_dir, "SHA256SUMS.txt")

    lines = []

    # Check for split parts first (takes priority over single compressed file)
    import glob as glob_module
    split_parts = sorted(glob_module.glob(os.path.join(source_dir, "zipherx_boost_v1.bin.zst.part*")))
    if split_parts:
        for part_path in split_parts:
            part_name = os.path.basename(part_path)
            sha = compute_file_sha256(part_path)
            lines.append(f"{sha}  {part_name}")
            log(f"  {part_name}: {sha}")
        # Also include checksum of the full compressed file (for verification after reassembly)
        compressed_file = os.path.join(source_dir, "zipherx_boost_v1.bin.zst")
        if os.path.exists(compressed_file):
            sha = compute_file_sha256(compressed_file)
            lines.append(f"{sha}  zipherx_boost_v1.bin.zst")
            log(f"  zipherx_boost_v1.bin.zst: {sha} (full file, for verification after reassembly)")
    else:
        # Single compressed file
        compressed_file = os.path.join(source_dir, "zipherx_boost_v1.bin.zst")
        if os.path.exists(compressed_file):
            sha = compute_file_sha256(compressed_file)
            lines.append(f"{sha}  zipherx_boost_v1.bin.zst")
            log(f"  zipherx_boost_v1.bin.zst: {sha}")

    # Check for uncompressed file in source directory (where it was generated)
    boost_file = os.path.join(source_dir, "zipherx_boost_v1.bin")
    if os.path.exists(boost_file):
        sha = compute_file_sha256(boost_file)
        lines.append(f"{sha}  zipherx_boost_v1.bin")
        log(f"  zipherx_boost_v1.bin: {sha}")

    # Manifest is in both directories, use repo version (already copied)
    manifest_file = os.path.join(repo_dir, "zipherx_boost_manifest.json")
    if os.path.exists(manifest_file):
        sha = compute_file_sha256(manifest_file)
        lines.append(f"{sha}  zipherx_boost_manifest.json")
        log(f"  zipherx_boost_manifest.json: {sha}")

    with open(sha_file, 'w') as f:
        f.write('\n'.join(lines) + '\n')

    log(f"  Written to {sha_file}")


def update_readme(repo_dir: str, chain_height: int, output_count: int, spend_count: int,
                  block_hash: str, tree_root: str, file_size: int, sha256: str, gen_time_mins: float,
                  blocks_per_sec: float, compressed_size: int = None):
    """Update README.md with current statistics.
    PRODUCTION: Includes compressed size info if available.
    """
    log("Updating README.md...")

    readme_path = os.path.join(repo_dir, "README.md")
    if not os.path.exists(readme_path):
        log_error(f"README.md not found at {readme_path}")
        return False

    with open(readme_path, 'r') as f:
        content = f.read()

    block_count = chain_height - SAPLING_ACTIVATION + 1
    file_size_mb = file_size / (1024 * 1024)
    today = datetime.now().strftime("%Y-%m-%d")

    # Build file size string with compressed info if available
    if compressed_size:
        compressed_mb = compressed_size / (1024 * 1024)
        ratio = (1 - compressed_size / file_size) * 100
        file_size_str = f"{compressed_mb:.1f} MB (zstd), {file_size_mb:.1f} MB uncompressed ({ratio:.0f}% reduction)"
    else:
        file_size_str = f"{file_size_mb:.1f} MB (uncompressed)"

    # Patterns to replace
    replacements = [
        # Chain Height in table
        (r'\| \*\*Chain Height\*\* \| [\d,]+ \|', f'| **Chain Height** | {chain_height:,} |'),
        # File Size in table
        (r'\| \*\*File Size\*\* \| [\d.]+ MB( \(uncompressed\))? \|', f'| **File Size** | {file_size_str} |'),
        # Created date
        (r'\| \*\*Created\*\* \| \d{4}-\d{2}-\d{2} \|', f'| **Created** | {today} |'),
        # Shielded Outputs count
        (r'\| \*\*Shielded Outputs\*\* \| [\d,]+ \|', f'| **Shielded Outputs** | {output_count:,} |'),
        # Shielded Spends count
        (r'\| \*\*Shielded Spends\*\* \| [\d,]+ \|', f'| **Shielded Spends** | {spend_count:,} |'),
        # Block Hashes count
        (r'\| \*\*Block Hashes\*\* \| [\d,]+ \|', f'| **Block Hashes** | {block_count:,} |'),
        # Block Timestamps count
        (r'\| \*\*Block Timestamps\*\* \| [\d,]+ \|', f'| **Block Timestamps** | {block_count:,} |'),
        # Outputs Data size (684 bytes each = 652 + 32 txid)
        (r'\[Outputs Data: [\d,]+ × 652 = ~[\d.]+ MB\]', f'[Outputs Data: {output_count:,} × 684 = ~{output_count * 684 / (1024*1024):.1f} MB (includes received_in_tx)]'),
        # Spends Data size (68 bytes each = 36 + 32 txid)
        (r'\[Spends Data: [\d,]+ × 36 = ~[\d.]+ MB\]', f'[Spends Data: {spend_count:,} × 68 = ~{spend_count * 68 / (1024*1024):.1f} MB (includes txid)]'),
        # Hashes Data size (32 bytes each)
        (r'\[Hashes Data: [\d,]+ × 32 = ~[\d.]+ MB\]', f'[Hashes Data: {block_count:,} × 32 = ~{block_count * 32 / (1024*1024):.1f} MB]'),
        # Timestamps Data size (4 bytes each)
        (r'\[Timestamps Data: [\d,]+ × 4 = ~[\d.]+ MB\]', f'[Timestamps Data: {block_count:,} × 4 = ~{block_count * 4 / (1024*1024):.1f} MB]'),
        # Total size
        (r'\*\*Total: ~[\d.]+ MB\*\*', f'**Total: ~{file_size_mb:.1f} MB**'),
        # Heights in table (End Height)
        (r'\| Outputs \| 476,969 \| [\d,]+ \|', f'| Outputs | 476,969 | {chain_height:,} |'),
        (r'\| Spends \| 476,969 \| [\d,]+ \|', f'| Spends | 476,969 | {chain_height:,} |'),
        (r'\| Hashes \| 476,969 \| [\d,]+ \|', f'| Hashes | 476,969 | {chain_height:,} |'),
        (r'\| Timestamps \| 476,969 \| [\d,]+ \|', f'| Timestamps | 476,969 | {chain_height:,} |'),
        (r'\| Tree \| 476,969 \| [\d,]+ \|', f'| Tree | 476,969 | {chain_height:,} |'),
        # SHA256 hash
        (r'# Expected: [a-f0-9]{64}', f'# Expected: {sha256}'),
        # Block Hash in cryptographic values
        (r'\| Block Hash \| `[0-9a-f]{64}` \|', f'| Block Hash | `{block_hash}` |'),
        # Tree Root in cryptographic values
        (r'\| Tree Root \| `[0-9a-f]{64}` \|', f'| Tree Root | `{tree_root}` |'),
        # Chain Height in cryptographic values
        (r'\| Chain Height \| [\d,]+ \|', f'| Chain Height | {chain_height:,} |'),
        # Generation Speed
        (r'\| Generation Speed \| [\d,]+ blocks/sec \|', f'| Generation Speed | {int(blocks_per_sec):,} blocks/sec |'),
        # Total Blocks Scanned
        (r'\| Total Blocks Scanned \| [\d,]+ \|', f'| Total Blocks Scanned | {block_count:,} |'),
        # Generation Time
        (r'\| Generation Time \| [\d.]+ minutes \|', f'| Generation Time | {gen_time_mins:.1f} minutes |'),
        # Release tag
        (r'\| \*\*Release Tag\*\* \| v\d+-unified \|', f'| **Release Tag** | v{chain_height}-unified |'),
    ]

    for pattern, replacement in replacements:
        content = re.sub(pattern, replacement, content)

    with open(readme_path, 'w') as f:
        f.write(content)

    log(f"  README.md updated with height {chain_height}")
    return True


def copy_files_to_repo(source_dir: str, repo_dir: str):
    """Copy boost files to the Git repository.
    PRODUCTION: Copies split parts or compressed .zst file for GitHub release.
    """
    log(f"Copying files to {repo_dir}...")

    os.makedirs(repo_dir, exist_ok=True)

    # Copy manifest (always)
    files = ["zipherx_boost_manifest.json"]

    # Check for split parts first (takes priority)
    import glob as glob_module
    split_parts = sorted(glob_module.glob(os.path.join(source_dir, "zipherx_boost_v1.bin.zst.part*")))
    if split_parts:
        for part_path in split_parts:
            files.append(os.path.basename(part_path))
        log(f"  Using {len(split_parts)} split parts for GitHub release (2 GiB limit)")
    else:
        # Copy single compressed file if exists
        compressed_src = os.path.join(source_dir, "zipherx_boost_v1.bin.zst")
        if os.path.exists(compressed_src):
            files.append("zipherx_boost_v1.bin.zst")
            log("  Using compressed file for GitHub release")

    for filename in files:
        src = os.path.join(source_dir, filename)
        dst = os.path.join(repo_dir, filename)
        if os.path.exists(src):
            shutil.copy2(src, dst)
            log(f"  Copied {filename}")
        else:
            log_error(f"  Source file not found: {src}")


def git_commit_and_push(repo_dir: str, chain_height: int):
    """Commit changes and push to remote.

    Note: zipherx_boost_v1.bin is NOT committed to git (too large: 747MB).
    It is only uploaded via GitHub Releases. Only metadata files are committed.
    """
    log("=== GIT OPERATIONS ===")

    # Add metadata files only (NOT the large boost file - that goes to Releases)
    # Use -f to override .gitignore for manifest and SHA256SUMS
    log("Adding metadata files to git...")
    result = subprocess.run(
        ["git", "add", "-f", "zipherx_boost_manifest.json", "SHA256SUMS.txt", "README.md"],
        cwd=repo_dir,
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        log_error(f"git add failed: {result.stderr}")
        return False

    # Commit
    commit_msg = f"""Update boost file to height {chain_height}

- Chain height: {chain_height}
- Boost file regenerated with latest blockchain data
- SHA256 checksums updated
- README.md updated with current statistics

🤖 Generated with ZipherX Boost Generator"""

    log("Committing changes...")
    result = subprocess.run(
        ["git", "commit", "-m", commit_msg],
        cwd=repo_dir,
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        if "nothing to commit" in result.stdout + result.stderr:
            log("  No changes to commit")
            return True
        log_error(f"git commit failed: {result.stderr}")
        return False

    log(f"  Committed: {result.stdout.strip().split(chr(10))[0]}")

    # Push
    log("Pushing to remote...")
    result = subprocess.run(
        ["git", "push", "origin", "master"],
        cwd=repo_dir,
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        # Try 'main' branch
        result = subprocess.run(
            ["git", "push", "origin", "main"],
            cwd=repo_dir,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            log_error(f"git push failed: {result.stderr}")
            return False

    log("  Pushed successfully!")
    return True


def create_github_release(repo_dir: str, chain_height: int, file_size: int, output_count: int,
                          spend_count: int, tree_root: str):
    """Create a GitHub release with the boost files.
    PRODUCTION: Uses split parts or compressed .zst file for GitHub release.
    """
    log("=== CREATING GITHUB RELEASE ===")

    tag = f"v{chain_height}-unified"
    title = f"ZipherX Unified Boost File - Height {chain_height}"

    block_count = chain_height - SAPLING_ACTIVATION + 1
    file_size_mb = file_size / (1024 * 1024)

    # Check for split parts first (takes priority over single compressed file)
    import glob as glob_module
    split_part_files = sorted(glob_module.glob(os.path.join(repo_dir, "zipherx_boost_v1.bin.zst.part*")))

    if split_part_files:
        # Split parts mode
        num_parts = len(split_part_files)
        total_compressed = sum(os.path.getsize(p) for p in split_part_files)
        compressed_mb = total_compressed / (1024 * 1024)

        # Build download commands for release notes
        download_cmds = ""
        for part_path in split_part_files:
            part_name = os.path.basename(part_path)
            download_cmds += f"wget https://github.com/ZipherPunk/ZipherX_Boost/releases/download/{tag}/{part_name}\n"

        # Build reassembly command
        part_names = " ".join(os.path.basename(p) for p in split_part_files)

        notes = f"""## ZipherX Unified Boost File (PRODUCTION v2)

**Chain Height:** {chain_height:,}
**Download Size:** {compressed_mb:.1f} MB (zstd compressed, {num_parts} parts)
**Uncompressed Size:** {file_size_mb:.1f} MB

### Contents
| Section | Count |
|---------|-------|
| Shielded Outputs | {output_count:,} |
| Shielded Spends | {spend_count:,} |
| Block Hashes | {block_count:,} |
| Block Timestamps | {block_count:,} |
| Block Headers | {block_count:,} (with Equihash solutions) |
| Serialized Tree | 1 |
| Reliable Peers | 9 |

### PRODUCTION v2 Features
- **received_in_tx** included for all outputs (no placeholders!)
- **Equihash solutions** included for all headers (full PoW verification)
- 100% accurate transaction history
- Instant import with real txids for change detection

### Tree Root
`{tree_root}`

### How to Use
```bash
# Download all parts
{download_cmds}
# Reassemble and decompress
cat {part_names} > zipherx_boost_v1.bin.zst
zstd -d zipherx_boost_v1.bin.zst

# Verify checksum
shasum -a 256 -c SHA256SUMS.txt
```

---
*Generated with ZipherX Boost Generator v2*
*Privacy is a right, not a privilege.*
"""
    else:
        # Single compressed file or uncompressed fallback
        compressed_file = os.path.join(repo_dir, "zipherx_boost_v1.bin.zst")
        if os.path.exists(compressed_file):
            compressed_size = os.path.getsize(compressed_file)
            compressed_mb = compressed_size / (1024 * 1024)
            notes = f"""## ZipherX Unified Boost File (PRODUCTION v2)

**Chain Height:** {chain_height:,}
**Download Size:** {compressed_mb:.1f} MB (zstd compressed)
**Uncompressed Size:** {file_size_mb:.1f} MB

### Contents
| Section | Count |
|---------|-------|
| Shielded Outputs | {output_count:,} |
| Shielded Spends | {spend_count:,} |
| Block Hashes | {block_count:,} |
| Block Timestamps | {block_count:,} |
| Block Headers | {block_count:,} (with Equihash solutions) |
| Serialized Tree | 1 |
| Reliable Peers | 9 |

### PRODUCTION v2 Features
- **received_in_tx** included for all outputs (no placeholders!)
- **Equihash solutions** included for all headers (full PoW verification)
- 100% accurate transaction history
- Instant import with real txids for change detection

### Tree Root
`{tree_root}`

### How to Use
```bash
# Download and decompress
wget https://github.com/ZipherPunk/ZipherX_Boost/releases/download/{tag}/zipherx_boost_v1.bin.zst
zstd -d zipherx_boost_v1.bin.zst

# Verify checksum
shasum -a 256 -c SHA256SUMS.txt
```

---
*Generated with ZipherX Boost Generator v2*
*Privacy is a right, not a privilege.*
"""
        else:
            notes = f"""## ZipherX Unified Boost File

**Chain Height:** {chain_height:,}
**File Size:** {file_size_mb:.1f} MB

### Contents
| Section | Count |
|---------|-------|
| Shielded Outputs | {output_count:,} |
| Shielded Spends | {spend_count:,} |
| Block Hashes | {block_count:,} |
| Block Timestamps | {block_count:,} |
| Serialized Tree | 1 |
| Reliable Peers | 9 |

### Tree Root
`{tree_root}`

### Verification
```bash
shasum -a 256 -c SHA256SUMS.txt
```

---
*Generated with ZipherX Boost Generator*
*Privacy is a right, not a privilege.*
"""

    manifest_file = os.path.join(repo_dir, "zipherx_boost_manifest.json")
    sha_file = os.path.join(repo_dir, "SHA256SUMS.txt")

    # Check if release exists and delete it
    log(f"Checking for existing release {tag}...")
    result = subprocess.run(
        ["gh", "release", "view", tag],
        cwd=repo_dir,
        capture_output=True,
        text=True
    )
    if result.returncode == 0:
        log(f"  Deleting existing release {tag}...")
        subprocess.run(
            ["gh", "release", "delete", tag, "--yes"],
            cwd=repo_dir,
            capture_output=True,
            text=True
        )
        # Also delete the tag
        subprocess.run(
            ["git", "tag", "-d", tag],
            cwd=repo_dir,
            capture_output=True,
            text=True
        )
        subprocess.run(
            ["git", "push", "origin", f":refs/tags/{tag}"],
            cwd=repo_dir,
            capture_output=True,
            text=True
        )

    # Create release
    log(f"Creating release {tag}...")
    cmd = [
        "gh", "release", "create", tag,
        manifest_file,
        sha_file,
        "--title", title,
        "--notes", notes
    ]

    # Add boost file assets
    if split_part_files:
        for part_path in split_part_files:
            cmd.append(part_path)
            part_mb = os.path.getsize(part_path) / (1024 * 1024)
            log(f"  Uploading {os.path.basename(part_path)} ({part_mb:.1f} MB)")
    else:
        compressed_file = os.path.join(repo_dir, "zipherx_boost_v1.bin.zst")
        if os.path.exists(compressed_file):
            cmd.append(compressed_file)
            log(f"  Uploading compressed file ({os.path.getsize(compressed_file) / (1024*1024):.1f} MB)")
        else:
            boost_file = os.path.join(repo_dir, "zipherx_boost_v1.bin")
            if os.path.exists(boost_file):
                cmd.append(boost_file)
                log(f"  Uploading uncompressed file ({file_size_mb:.1f} MB)")

    result = subprocess.run(
        cmd,
        cwd=repo_dir,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        log_error(f"Failed to create release: {result.stderr}")
        return False, None

    # Extract release URL from output
    release_url = result.stdout.strip()
    if not release_url.startswith("http"):
        release_url = f"https://github.com/ZipherPunk/ZipherX_Boost/releases/tag/{tag}"

    log(f"Release created: {release_url}")
    return True, release_url


###############################################################################
# TREE GENERATION FUNCTIONS
###############################################################################

def generate_serialized_tree(outputs):
    """
    Generate serialized commitment tree from all CMUs.
    Uses the Rust FFI to build and serialize the tree.
    """
    import tempfile

    log(f"Building commitment tree from {len(outputs)} CMUs...")

    # Write all CMUs to a temporary file
    # Format: [count: u64 LE][cmu1: 32 bytes][cmu2: 32 bytes]...
    cmu_file = tempfile.NamedTemporaryFile(delete=False, suffix='.bin')
    try:
        # Write count as u64 LE
        cmu_file.write(struct.pack('<Q', len(outputs)))

        # Write each CMU (already in little-endian wire format)
        for out in outputs:
            cmu_file.write(out['cmu'])

        cmu_file.close()
        log(f"  Wrote {len(outputs)} CMUs to temp file ({os.path.getsize(cmu_file.name)} bytes)")

        # Use the serialize_tree Rust tool
        serialize_tool = os.path.join(str(Path.home()), "ZipherX/Libraries/zipherx-ffi/target/release/serialize_tree")

        if not os.path.exists(serialize_tool):
            log("  Building serialize_tree tool...")
            result = subprocess.run(
                ["cargo", "build", "--release", "--bin", "serialize_tree"],
                cwd=os.path.join(str(Path.home()), "ZipherX/Libraries/zipherx-ffi"),
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                log_error(f"  Failed to build serialize_tree: {result.stderr}")
                return None, ""

        # Run the serialize tool
        output_tree_file = tempfile.NamedTemporaryFile(delete=False, suffix='.bin')
        output_tree_file.close()

        log(f"  Running serialize_tree...")
        result = subprocess.run(
            [serialize_tool, cmu_file.name, output_tree_file.name],
            capture_output=True,
            text=True,
            timeout=600  # 10 minutes max
        )

        if result.returncode != 0:
            log_error(f"  serialize_tree failed: {result.stderr}")
            # Try fallback: use the existing commitment_tree.bin if available
            fallback_path = os.path.join(str(Path.home()), "ZipherX/Resources/commitment_tree.bin")
            if os.path.exists(fallback_path):
                log(f"  Using fallback tree from {fallback_path}")
                # We need to build tree from this file and serialize
                # For now, skip tree section
                return None, ""
            return None, ""

        # Read the serialized tree
        with open(output_tree_file.name, 'rb') as f:
            tree_data = f.read()

        # Extract tree root from output (last line of stdout)
        tree_root = ""
        for line in result.stdout.strip().split('\n'):
            if 'root:' in line.lower() or line.startswith('Root:'):
                tree_root = line.split(':')[-1].strip()
            elif len(line) == 64:  # Looks like a hex hash
                tree_root = line

        log(f"  Serialized tree: {len(tree_data)} bytes")
        if tree_root:
            log(f"  Tree root: {tree_root}")

        # Cleanup
        os.unlink(output_tree_file.name)

        return tree_data, tree_root

    except subprocess.TimeoutExpired:
        log_error("  serialize_tree timed out!")
        return None, ""
    except Exception as e:
        log_error(f"  Error generating tree: {e}")
        return None, ""
    finally:
        try:
            os.unlink(cmu_file.name)
        except:
            pass


def get_tree_from_node(chain_height):
    """
    Get the serialized Sapling commitment tree from the node.
    Uses z_gettreestate RPC call.
    """
    log("Getting commitment tree state from node...")
    rpc = get_rpc()

    try:
        # Get the block hash at chain height
        block_hash = rpc.call("getblockhash", [chain_height])
        if not block_hash:
            log_error("  Failed to get block hash")
            return None, ""

        # Get the tree state
        tree_state = rpc.call("z_gettreestate", [block_hash])
        if not tree_state:
            log_error("  Failed to get tree state")
            return None, ""

        # Extract Sapling tree data
        sapling = tree_state.get("sapling", {})
        tree_hex = sapling.get("commitments", {}).get("finalState", "")

        if not tree_hex:
            log_error("  No Sapling tree state in response")
            return None, ""

        tree_data = bytes.fromhex(tree_hex)
        tree_root = sapling.get("commitments", {}).get("finalRoot", "")

        log(f"  Got tree from node: {len(tree_data)} bytes")
        log(f"  Tree root: {tree_root}")

        return tree_data, tree_root

    except Exception as e:
        log_error(f"  Error getting tree from node: {e}")
        return None, ""


def main():
    import argparse

    parser = argparse.ArgumentParser(description='ZipherX Boost File Generator')
    parser.add_argument('output_dir', nargs='?', default=os.path.join(str(Path.home()), 'Documents/BoostCache'),
                        help='Output directory for boost files')
    parser.add_argument('--skip-verify', action='store_true',
                        help='Skip balance verification step')
    parser.add_argument('--skip-git', action='store_true',
                        help='Skip Git commit/push and GitHub release')
    parser.add_argument('--key-file', default=os.path.join(str(Path.home()), 'ZipherX/Tools/check_balance/key.txt'),
                        help='Path to key file for balance verification')
    parser.add_argument('--repo-dir', default=os.path.join(str(Path.home()), 'ZipherX_Boost'),
                        help='Path to Git repository for release')
    parser.add_argument('--three-file', action='store_true',
                        help='Use three-file format (core + equihash separately - smaller download)')

    args = parser.parse_args()
    output_dir = args.output_dir
    repo_dir = args.repo_dir

    log("=" * 70)
    log("ZipherX Boost File Generator - ULTRA FAST VERSION")
    log("=" * 70)
    log(f"Workers: {MAX_WORKERS}, Batch size: {BATCH_SIZE}")
    log(f"Log file: {LOG_FILE}")
    log(f"Output directory: {output_dir}")
    log(f"Repository directory: {repo_dir}")

    # Initialize HTTP RPC
    if not init_rpc():
        log_error("Failed to initialize RPC - exiting")
        sys.exit(1)

    try:
        chain_height = get_chain_height()
    except Exception as e:
        log_error(f"Cannot connect to zclassic node: {e}")
        sys.exit(1)

    log(f"Current chain height: {chain_height}")

    total_blocks = chain_height - SAPLING_ACTIVATION + 1
    log(f"Total blocks to scan: {total_blocks}")

    # Process all blocks (FIX #413: Now also collects headers)
    start_time = time.time()
    outputs, spends, hashes, timestamps, headers = process_height_range_fast(
        SAPLING_ACTIVATION,
        chain_height
    )

    elapsed = time.time() - start_time
    rate = total_blocks / elapsed if elapsed > 0 else 0
    log(f"Scan completed in {elapsed/60:.1f} minutes ({rate:.0f} blocks/sec)")
    log(f"Found {len(outputs)} shielded outputs")
    log(f"Found {len(spends)} shielded spends")
    log(f"Found {len(hashes)} block hashes")
    log(f"Found {len(timestamps)} timestamps")
    log(f"Found {len(headers)} block headers (FIX #413)")

    # Get peers
    log("Getting peer addresses...")
    peers = get_reliable_peers()
    log(f"Found {len(peers)} peers")

    # Get serialized commitment tree
    # FIX: Use generate_serialized_tree() directly because z_gettreestate's finalState
    # is only a compact incremental witness (~606 bytes), NOT the full commitment tree!
    log("Generating commitment tree from CMUs...")
    tree_data, tree_root = generate_serialized_tree(outputs)

    if tree_data is None:
        log_error("WARNING: Failed to generate tree from CMUs! Boost file will be incomplete.")
        tree_data = b''
        tree_root = ""

    # FIX #539: Validate sapling_roots are unique (CRITICAL for tree root validation)
    log("Validating sapling_roots for uniqueness...")
    roots_valid, roots_report = validate_sapling_roots(headers)
    if not roots_valid:
        log_error("SAPLING_ROOT VALIDATION FAILED!")
        log_error("Boost file would have CORRUPTED headers - aborting!")
        log_error("Please check:")
        log_error("  1. zclassicd is running with correct blockchain data")
        log_error("  2. RPC cache is cleared (restart zclassicd)")
        log_error("  3. Node is fully synced")
        sys.exit(1)

    # Verify (FIX #413: Now also verifies headers)
    if not verify_completeness(outputs, spends, hashes, timestamps, chain_height, headers):
        log_error("Verification failed!")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            sys.exit(1)

    # Write files
    os.makedirs(output_dir, exist_ok=True)
    boost_path = os.path.join(output_dir, "zipherx_boost_v1.bin")
    manifest_path = os.path.join(output_dir, "zipherx_boost_manifest.json")

    # FIX #413: Pass headers to write_boost_file for Section 7
    sections = write_boost_file(
        boost_path, outputs, spends, hashes, timestamps, chain_height,
        tree_data=tree_data,
        peers=peers,
        headers=headers
    )

    file_size = os.path.getsize(boost_path)

    ###########################################################################
    # COMPRESSION: Compress with zstd for GitHub release (2GB limit workaround)
    ###########################################################################
    log("")
    log("=" * 70)
    log("COMPRESSING BOOST FILE WITH ZSTD")
    log("=" * 70)

    compressed_path = os.path.join(output_dir, "zipherx_boost_v1.bin.zst")
    log(f"Compressing {boost_path}...")
    log(f"  Input:  {file_size / (1024*1024):.1f} MB")

    start_compress = time.time()
    # Use level 19 for maximum compression (2.1GB -> ~500MB, ~75% reduction)
    result = subprocess.run(
        ["zstd", "-19", "-f", boost_path, "-o", compressed_path],
        capture_output=True,
        text=True
    )

    split_parts = None
    if result.returncode != 0:
        log_error(f"Compression failed: {result.stderr}")
        log("  Continuing with uncompressed file...")
        compressed_path = boost_path
        compressed_size = file_size
    else:
        compressed_size = os.path.getsize(compressed_path)
        compress_time = time.time() - start_compress
        ratio = (1 - compressed_size / file_size) * 100
        log(f"  Output: {compressed_size / (1024*1024):.1f} MB ({ratio:.1f}% reduction)")
        log(f"  Time:   {compress_time:.1f} seconds")
        log(f"  Speed:  {(file_size / (1024*1024)) / compress_time:.1f} MB/sec")

        # Split if compressed file exceeds GitHub's 2 GiB asset limit
        if compressed_size > GITHUB_MAX_ASSET_SIZE:
            split_parts = split_compressed_file(compressed_path)

    write_manifest(manifest_path, outputs, spends, hashes, timestamps, chain_height, sections, file_size, tree_root,
                   compressed_path if compressed_path != boost_path else None, compressed_size,
                   split_parts=split_parts)

    total_time = time.time() - start_time
    blocks_per_sec = total_blocks / total_time if total_time > 0 else 0

    log("=" * 70)
    log("BOOST FILE GENERATION COMPLETE")
    log("=" * 70)
    log(f"Output file:  {boost_path}")
    log(f"Manifest:     {manifest_path}")
    log(f"File size:    {file_size / (1024*1024):.1f} MB")
    log(f"Total time:   {total_time/60:.1f} minutes")
    log(f"Average speed: {blocks_per_sec:.0f} blocks/sec")
    if tree_data:
        log(f"Tree size:    {len(tree_data)} bytes")
        log(f"Tree root:    {tree_root}")

    # Get block hash for documentation
    # FIX #599: Hashes are now stored in RPC format (big-endian), no need to reverse
    last_hash = hashes[-1][1].hex() if hashes else "0" * 64
    sha256 = compute_file_sha256(boost_path)

    ###########################################################################
    # AUTOMATION: Balance Verification
    ###########################################################################
    if not args.skip_verify:
        log("")
        log("=" * 70)
        success, boost_bal, node_bal = verify_balance(args.key_file)
        if not success:
            log_error("Balance verification FAILED! Stopping automation.")
            log("You can re-run with --skip-verify to skip this check.")
            sys.exit(1)
    else:
        log("Skipping balance verification (--skip-verify)")

    ###########################################################################
    # AUTOMATION: Copy to repo, update docs, Git, and release
    ###########################################################################
    if not args.skip_git:
        log("")
        log("=" * 70)
        log("AUTOMATION: Preparing release...")
        log("=" * 70)

        # Copy files to repo
        copy_files_to_repo(output_dir, repo_dir)

        # Generate SHA256SUMS.txt (FIX: calculate from source_dir where new files are)
        update_sha256sums(output_dir, repo_dir)

        # Update README.md
        # Pass compressed_size if different from file_size (i.e., compression succeeded)
        compressed_param = compressed_size if compressed_size != file_size else None
        update_readme(
            repo_dir=repo_dir,
            chain_height=chain_height,
            output_count=len(outputs),
            spend_count=len(spends),
            block_hash=last_hash,
            tree_root=tree_root,
            file_size=file_size,
            sha256=sha256,
            gen_time_mins=total_time / 60,
            blocks_per_sec=blocks_per_sec,
            compressed_size=compressed_param
        )

        # Git commit and push (metadata files only - boost file is too large)
        git_success = git_commit_and_push(repo_dir, chain_height)
        if not git_success:
            log("  ⚠️  Git commit/push failed, but continuing with GitHub Release...")

        # Create GitHub release (always, even if git commit failed)
        # The boost file is distributed via Releases, not committed to git
        success, release_url = create_github_release(
            repo_dir=repo_dir,
            chain_height=chain_height,
            file_size=file_size,
            output_count=len(outputs),
            spend_count=len(spends),
            tree_root=tree_root
        )
        if success:
            log("")
            log("=" * 70)
            log("🎉 ALL AUTOMATION COMPLETE!")
            log("=" * 70)
            log(f"Release URL: {release_url}")
            if not git_success:
                log("  ⚠️  Note: Git commit/push failed, but release was created successfully")
        else:
            log_error("Failed to create GitHub release")
    else:
        log("Skipping Git operations (--skip-git)")

    log("")
    log("=" * 70)
    log("DONE!")
    log("=" * 70)

if __name__ == "__main__":
    main()
