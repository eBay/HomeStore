#!/usr/bin/env python3
"""
Script to reconstruct and compare metablk chains from two different scanning methods.
- First file: "chunk" entries from chunk traversal (may have orphaned blocks due to deletion)
- Second file: "chain" entries from chain traversal (complete chain)
Both chains start from SSB (Super Block)
"""

import re
import sys
from collections import defaultdict

class MetaBlk:
    """Represents a meta block entry."""

    def __init__(self, self_bid, next_bid, prev_bid, type_name, line, pg_shard_id=None):
        self.self_bid = self_bid
        self.next_bid = next_bid
        self.prev_bid = prev_bid
        self.type_name = type_name
        self.line = line
        self.pg_shard_id = pg_shard_id  # Store PG ID or Shard ID

    def __repr__(self):
        return f"MetaBlk({self.self_bid}, type={self.type_name})"

def parse_bid(line, field_name):
    """Extract bid field (self_bid, next_bid, prev_bid) from a log line."""
    pattern = rf'{field_name}:\s*(\[?blk#=\d+\s+count=\d+\s+chunk=\d+\]?|Invalid_Blkid)'
    match = re.search(pattern, line)
    if match:
        bid_str = match.group(1).strip('[]')
        return bid_str if bid_str != 'Invalid_Blkid' else None
    return None

def parse_type(line):
    """Extract type from a log line."""
    match = re.search(r'type:\s*(\w+)', line)
    return match.group(1) if match else 'unknown'


def parse_pg_shard_id(line):
    """Extract PG ID or Shard ID from log line."""
    # For PGManager: [PGManager] chunk=X blk=Y pg_info: id=Z
    if '[PGManager]' in line:
        match = re.search(r'pg_info:\s*id=(\d+)', line)
        if match:
            return f"PG:{match.group(1)}"

    # For ShardManager: [ShardManager] chunk=X blk=Y shard_info: ... [ShardInfo: id=Z
    if '[ShardManager]' in line:
        match = re.search(r'\[ShardInfo:\s*id=(\d+)', line)
        if match:
            return f"Shard:{match.group(1)}"

    return None

def parse_chunk_entries(log_file, target_ssb_bid):
    """Parse chunk traversal entries and find SSB matching the target."""
    blocks = {}
    ssb_bid = None

    with open(log_file, 'r') as f:
        for line in f:
            # Find SSB - look for "[SSB] found at blkid=" matching target
            if '[SSB] found at blkid=' in line:
                # SSB info is all in one line
                self_bid = parse_bid(line, 'self_bid')
                if self_bid and self_bid == target_ssb_bid:
                    ssb_bid = self_bid
                    next_bid = parse_bid(line, 'next_bid')
                    prev_bid = parse_bid(line, 'prev_bid')
                    blocks[self_bid] = MetaBlk(self_bid, next_bid, prev_bid, 'SSB', line.strip())
                continue

            # Parse MetaBlk entries
            if '[MetaBlk] found' in line:
                self_bid = parse_bid(line, 'self_bid')
                if self_bid:
                    next_bid = parse_bid(line, 'next_bid')
                    prev_bid = parse_bid(line, 'prev_bid')
                    type_name = parse_type(line)
                    blocks[self_bid] = MetaBlk(self_bid, next_bid, prev_bid, type_name, line.strip())

            # Parse PGManager and ShardManager entries
            if '[PGManager]' in line or '[ShardManager]' in line:
                # Extract chunk and blk from log
                chunk_match = re.search(r'chunk=(\d+)', line)
                blk_match = re.search(r'blk=(\d+)', line)
                if chunk_match and blk_match:
                    # Construct bid in the format used by the script
                    chunk = chunk_match.group(1)
                    blk = blk_match.group(1)
                    # The bid format is "blk#=X count=1 chunk=Y"
                    self_bid = f"blk#={blk} count=1 chunk={chunk}"

                    # Check if this block already exists
                    if self_bid in blocks:
                        # Update with PG/Shard ID
                        pg_shard_id = parse_pg_shard_id(line)
                        blocks[self_bid].pg_shard_id = pg_shard_id

    return blocks, ssb_bid


def parse_chain_entries(log_file):
    """Parse chain traversal entries and find SSB start."""
    blocks = {}
    ssb_bid = None

    with open(log_file, 'r') as f:
        for line in f:
            # Find SSB - "Successfully loaded meta ssb from disk:"
            if 'Successfully loaded meta ssb from disk:' in line:
                self_bid = parse_bid(line, 'self_bid')
                if self_bid:
                    ssb_bid = self_bid
                    next_bid = parse_bid(line, 'next_bid')
                    prev_bid = parse_bid(line, 'prev_bid')
                    blocks[self_bid] = MetaBlk(self_bid, next_bid, prev_bid, 'SSB', line.strip())
                    continue

            # Parse Scanned meta blk entries
            if 'Scanned meta blk:' in line:
                self_bid = parse_bid(line, 'self_bid')
                if self_bid:
                    next_bid = parse_bid(line, 'next_bid')
                    prev_bid = parse_bid(line, 'prev_bid')
                    type_name = parse_type(line)
                    blocks[self_bid] = MetaBlk(self_bid, next_bid, prev_bid, type_name, line.strip())

            # Parse PGManager and ShardManager entries
            if '[PGManager]' in line or '[ShardManager]' in line:
                # Extract chunk and blk from log
                chunk_match = re.search(r'chunk=(\d+)', line)
                blk_match = re.search(r'blk=(\d+)', line)
                if chunk_match and blk_match:
                    # Construct bid in the format used by the script
                    chunk = chunk_match.group(1)
                    blk = blk_match.group(1)
                    # The bid format is "blk#=X count=1 chunk=Y"
                    self_bid = f"blk#={blk} count=1 chunk={chunk}"

                    # Check if this block already exists
                    if self_bid in blocks:
                        # Update with PG/Shard ID
                        pg_shard_id = parse_pg_shard_id(line)
                        blocks[self_bid].pg_shard_id = pg_shard_id

    return blocks, ssb_bid

def build_chain(blocks, start_bid):
    """Build chain from start_bid following next pointers, validating prev pointers."""
    chain = []
    visited = set()
    current_bid = start_bid
    prev_bid_expected = None

    while current_bid and current_bid not in visited:
        if current_bid in blocks:
            block = blocks[current_bid]

            # Validate prev pointer consistency
            if prev_bid_expected is not None:
                if block.prev_bid != prev_bid_expected:
                    # Note the inconsistency but continue
                    chain.append(f"WARNING: prev_bid mismatch at {current_bid}: expected={prev_bid_expected}, actual={block.prev_bid}")

            chain.append(block)
            visited.add(current_bid)
            prev_bid_expected = current_bid
            current_bid = block.next_bid
        else:
            # Broken chain - next_bid points to non-existent block
            chain.append(f"BROKEN_LINK -> {current_bid}")
            break

    return chain, visited

def find_orphaned_blocks(blocks, visited):
    """Find blocks that are not part of the main chain."""
    all_bids = set(blocks.keys())
    orphaned = all_bids - visited
    return orphaned

def format_bid(bid):
    """Format bid for compact display."""
    if not bid:
        return "NULL"
    # Extract blk#, chunk info for compact display
    match = re.match(r'blk#=(\d+)\s+count=(\d+)\s+chunk=(\d+)', bid)
    if match:
        blk_num, count, chunk = match.groups()
        if count == "1":
            return f"blk#{blk_num}@c{chunk}"
        else:
            return f"blk#{blk_num}({count})@c{chunk}"
    return bid

def print_chain(chain, title):
    """Print a chain with compact, table-like formatting."""
    print("\n" + "=" * 120)
    print(title)
    print("=" * 120)
    print(f"{'Idx':<5} {'Self BID':<20} {'Type':<25} {'Prev BID':<20} {'Next BID':<20} {'PGID/SHARDID':<15}")
    print("-" * 120)

    for i, item in enumerate(chain):
        if isinstance(item, MetaBlk):
            self_short = format_bid(item.self_bid)
            prev_short = format_bid(item.prev_bid)
            next_short = format_bid(item.next_bid)
            pg_shard_display = item.pg_shard_id if item.pg_shard_id else "-"

            print(
                f"{i:<5} {self_short:<20} {item.type_name:<25} {prev_short:<20} {next_short:<20} {pg_shard_display:<15}")
        else:
            print(f"{i:<5} {str(item)}")
    print("=" * 120 + "\n")

def check_bidirectional(block, blocks):
    """Check if prev and next pointers are bidirectional."""
    prev_bidir = False
    next_bidir = False

    # Check prev pointer
    if block.prev_bid and block.prev_bid in blocks:
        prev_block = blocks[block.prev_bid]
        if prev_block.next_bid == block.self_bid:
            prev_bidir = True

    # Check next pointer
    if block.next_bid and block.next_bid in blocks:
        next_block = blocks[block.next_bid]
        if next_block.prev_bid == block.self_bid:
            next_bidir = True

    return prev_bidir, next_bidir

def print_orphaned(blocks, orphaned_bids, title):
    """Print orphaned blocks (blocks not in the main chain) with bidirectional indicators."""
    if not orphaned_bids:
        return

    print("\n" + "=" * 140)
    print(title)
    print("=" * 140)
    print(f"{'ID':<5} {'Self BID':<20} {'Type':<25} {'Prev BID':<27} {'Next BID':<27} {'PGID/SHARDID':<15}")
    print("-" * 140)

    for idx, bid in enumerate(sorted(orphaned_bids)):
        block = blocks[bid]
        self_short = format_bid(block.self_bid)
        prev_short = format_bid(block.prev_bid)
        next_short = format_bid(block.next_bid)
        pg_shard_display = block.pg_shard_id if block.pg_shard_id else "-"

        # Check bidirectional links
        prev_bidir, next_bidir = check_bidirectional(block, blocks)

        # Add symbols: ✓ for bidirectional, ✗ for broken/not found
        if block.prev_bid:
            prev_symbol = "✓" if prev_bidir else "✗"
            prev_display = f"{prev_symbol} {prev_short}"
        else:
            prev_display = "  NULL"

        if block.next_bid:
            next_symbol = "✓" if next_bidir else "✗"
            next_display = f"{next_symbol} {next_short}"
        else:
            next_display = "  NULL"

        print(
            f"{idx:<5} {self_short:<20} {block.type_name:<25} {prev_display:<27} {next_display:<27} {pg_shard_display:<15}")

    print("\n" + "=" * 140 + "\n")

def compare_chains(chain1, chain2):
    """Compare two chains and report differences."""
    print("\n" + "=" * 100)
    print("CHAIN COMPARISON")
    print("=" * 100)

    # Extract self_bids from chains
    chain1_bids = [b.self_bid for b in chain1 if isinstance(b, MetaBlk)]
    chain2_bids = [b.self_bid for b in chain2 if isinstance(b, MetaBlk)]

    # Find common prefix
    common_length = 0
    for i in range(min(len(chain1_bids), len(chain2_bids))):
        if chain1_bids[i] == chain2_bids[i]:
            common_length += 1
        else:
            break

    # Show differences
    if chain1_bids == chain2_bids:
        print("\n  ✓ Chains are IDENTICAL!\n")
        print(f"    Chain length: {len(chain1_bids)}")
    else:
        print("\n  ✗ Chains are DIFFERENT\n")
        print(f"    Chain 1 length: {len(chain1_bids)}")
        print(f"    Chain 2 length: {len(chain2_bids)}")
        print(f"    Common prefix:  {common_length} blocks")

        # Show where they diverge
        if common_length < min(len(chain1_bids), len(chain2_bids)):
            print(f"\n  Chains diverge at position {common_length}:")
            if common_length < len(chain1):
                blk1 = chain1[common_length]
                if isinstance(blk1, MetaBlk):
                    print(f"    Chain 1: {format_bid(blk1.self_bid):<20} type={blk1.type_name}")
            if common_length < len(chain2):
                blk2 = chain2[common_length]
                if isinstance(blk2, MetaBlk):
                    print(f"    Chain 2: {format_bid(blk2.self_bid):<20} type={blk2.type_name}")

        # Show blocks only in each chain
        set1 = set(chain1_bids)
        set2 = set(chain2_bids)
        only_in_1 = set1 - set2
        only_in_2 = set2 - set1

        if only_in_1:
            print(f"\n  Blocks only in Chain 1 ({len(only_in_1)}):")
            for bid in only_in_1:
                idx = chain1_bids.index(bid)
                blk = chain1[idx]
                print(f"    Position {idx}: {format_bid(blk.self_bid):<20} type={blk.type_name}")

        if only_in_2:
            print(f"\n  Blocks only in Chain 2 ({len(only_in_2)}):")
            for bid in only_in_2:
                idx = chain2_bids.index(bid)
                blk = chain2[idx]
                print(f"    Position {idx}: {format_bid(blk.self_bid):<20} type={blk.type_name}")

    print("\n" + "=" * 100 + "\n")

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 compare_metablk_chains.py <chunk_log_file> <chain_log_file>")
        print()
        print("  chunk_log_file: Log file from chunk traversal (may have orphaned blocks)")
        print("  chain_log_file: Log file from chain traversal (complete chain)")
        sys.exit(1)

    chunk_log_file = sys.argv[1]
    chain_log_file = sys.argv[2]

    print()
    print("=" * 100)
    print("MetaBlk Chain Reconstruction and Comparison")
    print("=" * 100)
    print(f"Chunk traversal source: {chunk_log_file}")
    print(f"Chain traversal source: {chain_log_file}")
    print("=" * 100)
    print()

    # Parse chain entries first to get the SSB
    print("Parsing chain traversal entries...")
    chain_blocks, chain_ssb = parse_chain_entries(chain_log_file)
    print(f"  Found {len(chain_blocks)} blocks")
    print(f"  SSB start: {chain_ssb}")
    print()

    if not chain_ssb:
        print("ERROR: Could not find SSB in chain traversal entries")
        sys.exit(1)

    # Parse chunk entries using the SSB from chain
    print(f"Parsing chunk traversal entries using SSB from chain: {chain_ssb}...")
    chunk_blocks, chunk_ssb = parse_chunk_entries(chunk_log_file, chain_ssb)
    print(f"  Found {len(chunk_blocks)} blocks")
    print(f"  SSB start: {chunk_ssb}")
    print()

    if not chunk_ssb:
        print("ERROR: Could not find matching SSB in chunk traversal entries")
        sys.exit(1)

    # Build chains
    print("Building chain from chunk traversal...")
    chain1, visited1 = build_chain(chunk_blocks, chunk_ssb)
    print(f"  Chain length: {len([b for b in chain1 if isinstance(b, MetaBlk)])}")
    print()

    print("Building chain from chain traversal...")
    chain2, visited2 = build_chain(chain_blocks, chain_ssb)
    print(f"  Chain length: {len([b for b in chain2 if isinstance(b, MetaBlk)])}")
    print()

    # Find orphaned blocks in chunk traversal
    orphaned1 = find_orphaned_blocks(chunk_blocks, visited1)
    if orphaned1:
        print(f"Found {len(orphaned1)} orphaned blocks in chunk traversal (due to deletion)")
    print()

    # Print chains
    print_chain(chain1, "CHAIN FROM CHUNK TRAVERSAL")
    print_chain(chain2, "CHAIN FROM CHAIN TRAVERSAL")

    # Print orphaned blocks
    if orphaned1:
        print_orphaned(chunk_blocks, orphaned1, f"ORPHANED BLOCKS IN CHUNK TRAVERSAL ({len(orphaned1)} blocks)")

    # Compare chains
    compare_chains(chain1, chain2)

    # Summary
    print("\n" + "=" * 100)
    print("SUMMARY")
    print("=" * 100)
    chain1_count = len([b for b in chain1 if isinstance(b, MetaBlk)])
    chain2_count = len([b for b in chain2 if isinstance(b, MetaBlk)])

    print(f"\nChunk traversal:")
    print(f"  Blocks in chain: {chain1_count}")
    print(f"  Orphaned blocks: {len(orphaned1)}")
    print(f"  Total blocks:    {chain1_count + len(orphaned1)}")

    print(f"\nChain traversal:")
    print(f"  Blocks in chain: {chain2_count}")

    print(f"\nComparison:")
    print(f"  SSB match:        {'✓ YES' if chunk_ssb == chain_ssb else '✗ NO'}")
    chain1_bids = [b.self_bid for b in chain1 if isinstance(b, MetaBlk)]
    chain2_bids = [b.self_bid for b in chain2 if isinstance(b, MetaBlk)]
    print(f"  Chains identical: {'✓ YES' if chain1_bids == chain2_bids else '✗ NO'}")
    print("\n" + "=" * 100 + "\n")

if __name__ == "__main__":
    main()
