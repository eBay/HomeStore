#!/usr/bin/env python3
"""
Decode HomeStore superblock structures from disk dump.

Usage:
    python3 decode_superblock.py <disk_dump_file> [--verbose]
    python3 decode_superblock.py <disk_dump_file> chunk <slot_number>
    python3 decode_superblock.py <disk_dump_file> vdev <id_or_name>
    python3 decode_superblock.py <disk_dump_file> list-chunks --vdev=<id>
"""

from __future__ import annotations

import argparse
import struct
import sys
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import BinaryIO, Optional, Set, Dict, List, Tuple


# ============================================================================
# Constants
# ============================================================================

class VDevType(IntEnum):
    """Virtual device types."""
    DATA = 1
    INDEX = 2
    META = 3
    LOGDEV = 4

    @property
    def name_str(self) -> str:
        """Get human-readable name."""
        names = {
            VDevType.DATA: "DATA_VDEV",
            VDevType.INDEX: "INDEX_VDEV",
            VDevType.META: "META_VDEV",
            VDevType.LOGDEV: "LOGDEV_VDEV",
        }
        return names.get(self, f"UNKNOWN({self.value})")


# Layout constants
FIRST_BLOCK_OFFSET = 0
FIRST_BLOCK_SIZE = 4096
MAX_VDEVS_IN_SYSTEM = 1024
VDEV_INFO_SIZE = 512
CHUNK_INFO_SIZE = 512
CHUNK_INFO_SIZEOF = 248  # Actual C++ struct size
HS_INIT_CRC_16 = 0x8005

# Struct format strings
FIRST_BLOCK_HEADER_FMT = '<Q I 64s I I I I 16s'
PDEV_INFO_HEADER_FMT = '<Q Q I I I I I I B 16s'
VDEV_INFO_FMT = '<Q I I I I I I I H'
CHUNK_INFO_FMT = '<Q Q I I I B H'

# Magic values
FIRST_BLOCK_MAGIC = 0xabbecdcd


# ============================================================================
# CRC Calculation
# ============================================================================

def crc16_t10dif(data: bytes, init_crc: int = 0) -> int:
    """
    Calculate CRC16 T10 DIF checksum.

    Args:
        data: Bytes to checksum
        init_crc: Initial CRC value

    Returns:
        16-bit CRC value
    """
    crc = init_crc
    poly = 0x8bb7

    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = (crc << 1) ^ poly if (crc & 0x8000) else (crc << 1)
            crc &= 0xFFFF

    return crc


# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class FirstBlockHeader:
    """First block header metadata."""
    gen_number: int
    version: int
    product_name: str
    num_pdevs: int
    max_vdevs: int
    max_system_chunks: int
    cur_pdev_id: int
    system_uuid: uuid.UUID

    @classmethod
    def from_bytes(cls, data: bytes) -> FirstBlockHeader:
        """Parse from binary data."""
        fields = struct.unpack_from(FIRST_BLOCK_HEADER_FMT, data, 0)
        return cls(
            gen_number=fields[0],
            version=fields[1],
            product_name=fields[2].split(b'\x00')[0].decode('utf-8', errors='ignore'),
            num_pdevs=fields[3],
            max_vdevs=fields[4],
            max_system_chunks=fields[5],
            cur_pdev_id=fields[6],
            system_uuid=uuid.UUID(bytes=fields[7])
        )


@dataclass
class PDevInfoHeader:
    """Physical device info header."""
    data_offset: int
    size: int
    pdev_id: int
    max_pdev_chunks: int
    phys_page_size: int
    align_size: int
    atomic_phys_page_size: int
    num_streams: int
    mirror_super_block: int
    system_uuid: uuid.UUID

    @classmethod
    def from_bytes(cls, data: bytes) -> PDevInfoHeader:
        """Parse from binary data."""
        fields = struct.unpack_from(PDEV_INFO_HEADER_FMT, data, 0)
        return cls(
            data_offset=fields[0],
            size=fields[1],
            pdev_id=fields[2],
            max_pdev_chunks=fields[3],
            phys_page_size=fields[4],
            align_size=fields[5],
            atomic_phys_page_size=fields[6],
            num_streams=fields[7],
            mirror_super_block=fields[8],
            system_uuid=uuid.UUID(bytes=fields[9])
        )

    @property
    def size_gb(self) -> float:
        """Size in gigabytes."""
        return self.size / (1024 ** 3)

    @property
    def size_tb(self) -> float:
        """Size in terabytes."""
        return self.size / (1024 ** 4)


@dataclass
class FirstBlock:
    """First block structure (4096 bytes)."""
    magic: int
    checksum: int
    formatting_done: int
    header: FirstBlockHeader
    pdev_info: PDevInfoHeader

    @classmethod
    def from_bytes(cls, data: bytes) -> FirstBlock:
        """Parse from binary data."""
        if len(data) < FIRST_BLOCK_SIZE:
            raise ValueError(f"Data too small: {len(data)} < {FIRST_BLOCK_SIZE}")

        magic, checksum, formatting_done = struct.unpack_from('<Q I I', data, 0)
        header = FirstBlockHeader.from_bytes(data[16:])
        pdev_info = PDevInfoHeader.from_bytes(data[16 + 108:])

        return cls(magic, checksum, formatting_done, header, pdev_info)

    @property
    def is_valid(self) -> bool:
        """Check if magic number is valid."""
        return self.magic == FIRST_BLOCK_MAGIC


@dataclass
class VDevInfo:
    """Virtual device information."""
    vdev_size: int
    vdev_id: int
    num_mirrors: int
    blk_size: int
    chunk_size: int
    num_primary_chunks: int
    num_mirror_chunks: int
    creator_id: int
    checksum: int
    name: str
    vdev_type: VDevType

    @classmethod
    def from_bytes(cls, data: bytes) -> VDevInfo:
        """Parse from binary data."""
        if len(data) < VDEV_INFO_SIZE:
            raise ValueError(f"Data too small: {len(data)} < {VDEV_INFO_SIZE}")

        fields = struct.unpack_from(VDEV_INFO_FMT, data, 0)
        name = data[33:33+64].split(b'\x00')[0].decode('utf-8', errors='ignore')

        # Read vdev type from user_private
        vdev_type_val = struct.unpack_from('<I', data, 256)[0] if len(data) >= 260 else 0
        try:
            vdev_type = VDevType(vdev_type_val)
        except ValueError:
            vdev_type = VDevType.DATA  # Default fallback

        return cls(
            vdev_size=fields[0],
            vdev_id=fields[1],
            num_mirrors=fields[2],
            blk_size=fields[3],
            chunk_size=fields[4],
            num_primary_chunks=fields[5],
            num_mirror_chunks=fields[6],
            creator_id=fields[7],
            checksum=fields[8],
            name=name,
            vdev_type=vdev_type
        )

    @property
    def is_allocated(self) -> bool:
        """Check if vdev is allocated."""
        return self.checksum != 0

    @property
    def size_gb(self) -> float:
        """Size in gigabytes."""
        return self.vdev_size / (1024 ** 3)


@dataclass
class ChunkInfo:
    """Chunk information."""
    slot: int
    chunk_start_offset: int
    chunk_size: int
    vdev_id: int
    chunk_id: int
    chunk_ordinal: int
    chunk_allocated: int
    checksum: int
    raw_data: bytes = field(repr=False)

    @classmethod
    def from_bytes(cls, data: bytes, slot: int) -> ChunkInfo:
        """Parse from binary data."""
        if len(data) < CHUNK_INFO_SIZE:
            raise ValueError(f"Data too small: {len(data)} < {CHUNK_INFO_SIZE}")

        fields = struct.unpack_from(CHUNK_INFO_FMT, data, 0)
        return cls(
            slot=slot,
            chunk_start_offset=fields[0],
            chunk_size=fields[1],
            vdev_id=fields[2],
            chunk_id=fields[3],
            chunk_ordinal=fields[4],
            chunk_allocated=fields[5],
            checksum=fields[6],
            raw_data=data[:CHUNK_INFO_SIZEOF]
        )

    @property
    def is_allocated(self) -> bool:
        """Check if chunk is allocated."""
        return self.chunk_allocated != 0

    def verify_checksum(self) -> bool:
        """Verify CRC checksum."""
        test_data = bytearray(self.raw_data)
        struct.pack_into('<H', test_data, 29, 0)  # Zero out checksum field
        calculated = crc16_t10dif(bytes(test_data), HS_INIT_CRC_16)
        return calculated == self.checksum

    def calculate_checksum(self) -> int:
        """Calculate what the checksum should be."""
        test_data = bytearray(self.raw_data)
        struct.pack_into('<H', test_data, 29, 0)
        return crc16_t10dif(bytes(test_data), HS_INIT_CRC_16)

    @property
    def size_mb(self) -> float:
        """Size in megabytes."""
        return self.chunk_size / (1024 ** 2)


@dataclass
class SuperblockOffsets:
    """Calculated superblock offsets."""
    vdev_sb_offset: int
    chunk_sb_offset: int
    chunk_info_bitmap_size: int
    chunk_info_array_offset: int

    def chunk_offset(self, slot: int) -> int:
        """Calculate offset for chunk at given slot."""
        return self.chunk_info_array_offset + (slot * CHUNK_INFO_SIZE)


@dataclass
class ValidationIssue:
    """Represents a validation issue."""
    slot: int
    chunk_id: int
    vdev_id: int
    severity: str  # 'error', 'warning'
    message: str


@dataclass
class VDevValidation:
    """VDev validation results."""
    vdev_id: int
    vdev_size: int
    chunk_count: int
    valid_count: int
    invalid_count: int
    total_chunk_size: int
    issues: List[ValidationIssue] = field(default_factory=list)

    @property
    def utilization_pct(self) -> float:
        """Calculate utilization percentage."""
        return (self.total_chunk_size / self.vdev_size * 100) if self.vdev_size > 0 else 0

    @property
    def has_issues(self) -> bool:
        """Check if there are any issues."""
        return self.invalid_count > 0 or len(self.issues) > 0


@dataclass
class ScanSummary:
    """Summary of chunk scanning."""
    total_scanned: int
    allocated_count: int
    valid_count: int
    invalid_count: int
    max_slots_in_config: int
    max_slots_in_file: int

    @property
    def file_truncated(self) -> bool:
        """Check if file appears truncated."""
        return self.max_slots_in_file < self.max_slots_in_config


# ============================================================================
# Superblock Reader
# ============================================================================

class SuperblockReader:
    """Reads and parses HomeStore superblock."""

    def __init__(self, file_path: Path):
        """Initialize reader with file path."""
        self.file_path = file_path
        self.first_block: Optional[FirstBlock] = None
        self.offsets: Optional[SuperblockOffsets] = None

    def read_first_block(self, f: BinaryIO) -> FirstBlock:
        """Read and parse first block."""
        f.seek(FIRST_BLOCK_OFFSET)
        data = f.read(FIRST_BLOCK_SIZE)
        self.first_block = FirstBlock.from_bytes(data)
        return self.first_block

    def calculate_offsets(self, max_pdev_chunks: int) -> SuperblockOffsets:
        """Calculate superblock offsets."""
        vdev_sb_offset = FIRST_BLOCK_OFFSET + FIRST_BLOCK_SIZE
        vdev_super_block_size = MAX_VDEVS_IN_SYSTEM * VDEV_INFO_SIZE
        chunk_sb_offset = vdev_sb_offset + vdev_super_block_size

        # Calculate bitmap size
        bitmap_bits = ((max_pdev_chunks + 7) // 8) * 8
        bitmap_bytes = bitmap_bits // 8 + 4096
        chunk_info_bitmap_size = ((bitmap_bytes + 4095) // 4096) * 4096

        chunk_info_array_offset = chunk_sb_offset + chunk_info_bitmap_size

        self.offsets = SuperblockOffsets(
            vdev_sb_offset=vdev_sb_offset,
            chunk_sb_offset=chunk_sb_offset,
            chunk_info_bitmap_size=chunk_info_bitmap_size,
            chunk_info_array_offset=chunk_info_array_offset
        )
        return self.offsets

    def read_vdevs(self, f: BinaryIO) -> List[VDevInfo]:
        """Read all VDev info structures."""
        if not self.offsets:
            raise RuntimeError("Must calculate offsets first")

        f.seek(self.offsets.vdev_sb_offset)
        vdevs = []
        for _ in range(MAX_VDEVS_IN_SYSTEM):
            data = f.read(VDEV_INFO_SIZE)
            vdev = VDevInfo.from_bytes(data)
            vdevs.append(vdev)
        return vdevs

    def read_chunk_bitmap(self, f: BinaryIO, max_chunks: int) -> Set[int]:
        """Read and parse chunk allocation bitmap."""
        if not self.offsets:
            raise RuntimeError("Must calculate offsets first")

        f.seek(self.offsets.chunk_sb_offset)
        data = f.read(self.offsets.chunk_info_bitmap_size)
        return self._parse_bitmap(data, max_chunks)

    @staticmethod
    def _parse_bitmap(data: bytes, max_chunks: int) -> Set[int]:
        """Parse sisl::Bitset serialized bitmap."""
        # Parse header
        HEADER_SIZE = 40
        m_id, m_nbits, m_skip_bits, m_alignment_size, m_words_cap, m_word_bits = \
            struct.unpack_from('<QQQIQI', data, 0)

        bitmap_data = data[HEADER_SIZE:]
        allocated_slots = set()

        for slot in range(min(max_chunks, m_nbits)):
            byte_idx = slot // 8
            bit_idx = slot % 8

            if byte_idx >= len(bitmap_data):
                break

            if bitmap_data[byte_idx] & (1 << bit_idx):
                allocated_slots.add(slot)

        return allocated_slots

    def read_chunk(self, f: BinaryIO, slot: int) -> ChunkInfo:
        """Read chunk at specific slot."""
        if not self.offsets:
            raise RuntimeError("Must calculate offsets first")

        offset = self.offsets.chunk_offset(slot)
        f.seek(offset)
        data = f.read(CHUNK_INFO_SIZE)

        if len(data) < CHUNK_INFO_SIZE:
            raise ValueError(f"Cannot read chunk at slot {slot}")

        return ChunkInfo.from_bytes(data, slot)


# ============================================================================
# Chunk Scanner
# ============================================================================

@dataclass
class ChunkScanResult:
    """Result of scanning a single chunk."""
    chunk: ChunkInfo
    is_valid: bool
    calculated_crc: int


class ChunkScanner:
    """Scans and validates chunks."""

    def __init__(self, reader: SuperblockReader, bitmap_slots: Set[int]):
        """Initialize scanner."""
        self.reader = reader
        self.bitmap_slots = bitmap_slots

    def scan_all_chunks(
        self,
        f: BinaryIO,
        max_slots: int,
        verbose: bool = False
    ) -> Tuple[Dict[int, ChunkScanResult], ScanSummary]:
        """
        Scan all chunk slots and validate.

        Returns:
            Tuple of (chunks_data, scan_summary)
        """
        chunks_data: Dict[int, ChunkScanResult] = {}
        total_scanned = 0
        allocated_count = 0
        valid_count = 0
        invalid_count = 0

        # Get file size
        f.seek(0, 2)
        file_size = f.tell()

        max_readable_slot = (file_size - self.reader.offsets.chunk_info_array_offset) // CHUNK_INFO_SIZE
        actual_max_slots = min(max_slots, max_readable_slot)

        if verbose:
            print(f"  File size: {file_size:,} bytes ({file_size / (1024**2):.2f} MB)")
            print(f"  Scanning {actual_max_slots:,} chunk slots...")

        for slot in range(actual_max_slots):
            if verbose and slot > 0 and slot % 10000 == 0:
                pct = 100 * slot // actual_max_slots
                print(f"  Progress: {slot:,}/{actual_max_slots:,} slots ({pct}%)")

            try:
                chunk = self.reader.read_chunk(f, slot)
            except ValueError:
                break

            total_scanned += 1
            calculated_crc = chunk.calculate_checksum()

            # Skip truly empty slots
            if not chunk.is_allocated and chunk.checksum == 0:
                # Check if bitmap thinks it should be allocated
                if slot in self.bitmap_slots:
                    # Bitmap says allocated but chunk shows free
                    if calculated_crc == 0:
                        # Data is all zeros - skip
                        continue
                    # else: corrupted data - fall through
                else:
                    # Not in bitmap, appears free - skip
                    continue

            # Count as allocated
            allocated_count += 1
            is_valid = chunk.verify_checksum()

            if is_valid:
                valid_count += 1
            else:
                invalid_count += 1

            chunks_data[slot] = ChunkScanResult(chunk, is_valid, calculated_crc)

        if verbose:
            print(f"  Scan complete: {allocated_count:,} chunks found")

        summary = ScanSummary(
            total_scanned=total_scanned,
            allocated_count=allocated_count,
            valid_count=valid_count,
            invalid_count=invalid_count,
            max_slots_in_config=max_slots,
            max_slots_in_file=max_readable_slot
        )

        return chunks_data, summary


# ============================================================================
# Validator
# ============================================================================

class SuperblockValidator:
    """Validates superblock consistency."""

    def __init__(
        self,
        vdevs: List[VDevInfo],
        chunks_data: Dict[int, ChunkScanResult],
        bitmap_slots: Set[int]
    ):
        """Initialize validator."""
        self.vdevs = vdevs
        self.chunks_data = chunks_data
        self.bitmap_slots = bitmap_slots

    def validate_vdevs(self) -> Tuple[Dict[int, VDevValidation], List[ChunkScanResult]]:
        """
        Validate chunks from VDev perspective.

        Returns:
            Tuple of (validation_report, orphan_chunks)
        """
        # Build vdev->chunks mapping
        vdev_to_chunks: Dict[int, List[Tuple[int, ChunkScanResult]]] = {}
        for slot, scan_result in self.chunks_data.items():
            vdev_id = scan_result.chunk.vdev_id
            if vdev_id not in vdev_to_chunks:
                vdev_to_chunks[vdev_id] = []
            vdev_to_chunks[vdev_id].append((slot, scan_result))

        # Valid vdev IDs
        valid_vdev_ids = {v.vdev_id for v in self.vdevs if v.is_allocated}

        # Find orphan chunks
        orphan_chunks = []
        for vdev_id, chunks_list in vdev_to_chunks.items():
            if vdev_id not in valid_vdev_ids:
                orphan_chunks.extend([scan_result for _, scan_result in chunks_list])

        # Validate each vdev
        report: Dict[int, VDevValidation] = {}
        for vdev in self.vdevs:
            if not vdev.is_allocated:
                continue

            chunks_list = vdev_to_chunks.get(vdev.vdev_id, [])
            chunk_count = len(chunks_list)
            valid_count = sum(1 for _, sr in chunks_list if sr.is_valid)
            invalid_count = chunk_count - valid_count
            total_chunk_size = sum(sr.chunk.chunk_size for _, sr in chunks_list)

            issues = []
            for slot, scan_result in chunks_list:
                if not scan_result.is_valid:
                    msg = f"CRC mismatch: stored=0x{scan_result.chunk.checksum:04x} calc=0x{scan_result.calculated_crc:04x}"
                    issues.append(ValidationIssue(
                        slot=slot,
                        chunk_id=scan_result.chunk.chunk_id,
                        vdev_id=vdev.vdev_id,
                        severity='error',
                        message=msg
                    ))

            report[vdev.vdev_id] = VDevValidation(
                vdev_id=vdev.vdev_id,
                vdev_size=vdev.vdev_size,
                chunk_count=chunk_count,
                valid_count=valid_count,
                invalid_count=invalid_count,
                total_chunk_size=total_chunk_size,
                issues=issues
            )

        return report, orphan_chunks

    def compare_bitmap_vs_chunks(self) -> Dict[str, any]:
        """Compare bitmap vs actual chunk allocation."""
        chunk_slots = set(self.chunks_data.keys())
        in_bitmap_only = self.bitmap_slots - chunk_slots
        in_chunks_only = chunk_slots - self.bitmap_slots
        consistent = self.bitmap_slots & chunk_slots

        # Find CRC errors in bitmap-marked chunks
        bitmap_crc_errors = []
        for slot in self.bitmap_slots:
            if slot in self.chunks_data:
                scan_result = self.chunks_data[slot]
                if not scan_result.is_valid:
                    bitmap_crc_errors.append((
                        slot,
                        scan_result.chunk.checksum,
                        scan_result.calculated_crc
                    ))

        return {
            'in_bitmap_only': sorted(in_bitmap_only),
            'in_chunks_only': sorted(in_chunks_only),
            'consistent': len(consistent),
            'bitmap_with_crc_errors': bitmap_crc_errors,
            'has_inconsistency': len(in_bitmap_only) > 0 or len(in_chunks_only) > 0
        }


# ============================================================================
# Output Formatters
# ============================================================================

class OutputFormatter:
    """Formats validation output."""

    @staticmethod
    def format_size(bytes_val: int) -> str:
        """Format bytes as human-readable size."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"

    @staticmethod
    def print_compact_summary(
        first_block: FirstBlock,
        vdevs: List[VDevInfo],
        scan_summary: ScanSummary,
        comparison: Dict,
        validation_report: Dict[int, VDevValidation],
        orphan_chunks: List[ChunkScanResult]
    ):
        """Print compact validation summary."""
        print("\nHomeStore Superblock Summary")
        print("=" * 80)
        print(f"Product: {first_block.header.product_name} v{first_block.header.version}")
        print(f"System UUID: {first_block.header.system_uuid}")
        print(f"Formatting: {'Complete' if first_block.formatting_done else 'Incomplete'}")
        print(f"Device: pdev_id={first_block.pdev_info.pdev_id}, "
              f"size={first_block.pdev_info.size_tb:.2f} TB, "
              f"data_offset={first_block.pdev_info.data_offset / (1024**3):.2f} GB")

        # VDevs
        vdev_map = {v.vdev_id: v for v in vdevs if v.is_allocated}
        print(f"\nVDevs ({len(vdev_map)} total):")

        for vdev_id in sorted(validation_report.keys()):
            val = validation_report[vdev_id]
            vdev = vdev_map.get(vdev_id)

            if vdev:
                type_name = vdev.vdev_type.name_str
                name = vdev.name or "unnamed"
            else:
                type_name = "UNKNOWN"
                name = "unknown"

            status = "✓" if not val.has_issues else "✗"
            print(f"  [{vdev_id}] {type_name:12s} '{name:8s}' {val.vdev_size / (1024**3):9.2f} GB  "
                  f"{val.chunk_count:5,} chunks  {val.utilization_pct:5.0f}% util  {status}")

        # Chunks summary
        print(f"\nChunks:")
        alloc_pct = 100 * scan_summary.allocated_count / scan_summary.max_slots_in_config
        valid_pct = 100 * scan_summary.valid_count / scan_summary.allocated_count if scan_summary.allocated_count > 0 else 0
        print(f"  Total allocated: {scan_summary.allocated_count:,} / {scan_summary.max_slots_in_config:,} ({alloc_pct:.1f}%)")
        print(f"  Valid checksums: {scan_summary.valid_count:,} ({valid_pct:.1f}%)")
        print(f"  Invalid:         {scan_summary.invalid_count:,}")

        # Issues
        has_issues = (comparison['has_inconsistency'] or
                     scan_summary.invalid_count > 0 or
                     len(orphan_chunks) > 0)

        if has_issues:
            print(f"\nIssues:")

            # CRC errors
            if scan_summary.invalid_count > 0:
                invalid_chunks = []
                for vdev_id in sorted(validation_report.keys()):
                    for issue in validation_report[vdev_id].issues:
                        vdev = vdev_map.get(vdev_id)
                        vdev_name = vdev.name if vdev else f"vdev_{vdev_id}"
                        invalid_chunks.append((issue.slot, issue.chunk_id, vdev_id, vdev_name, issue.message))

                print(f"  ✗ {scan_summary.invalid_count} chunks with CRC errors:")
                for slot, chunk_id, vdev_id, vdev_name, msg in invalid_chunks[:10]:
                    print(f"    Slot {slot} (chunk_id={chunk_id}, vdev={vdev_id} '{vdev_name}'): {msg}")
                if len(invalid_chunks) > 10:
                    print(f"    ... and {len(invalid_chunks) - 10} more")

            # Bitmap inconsistencies
            if comparison['has_inconsistency']:
                if comparison['in_chunks_only']:
                    slots_str = ', '.join(str(s) for s in comparison['in_chunks_only'][:5])
                    if len(comparison['in_chunks_only']) > 5:
                        slots_str += f", ... (+{len(comparison['in_chunks_only']) - 5} more)"
                    print(f"  ⚠ Bitmap inconsistency: {len(comparison['in_chunks_only'])} chunks not in bitmap")
                    print(f"    Slots: {slots_str}")
                if comparison['in_bitmap_only']:
                    print(f"  ⚠ Bitmap inconsistency: {len(comparison['in_bitmap_only'])} bitmap slots empty")

            # Orphans
            if orphan_chunks:
                print(f"  ✗ {len(orphan_chunks)} orphan chunks (corrupted vdev_id):")
                for scan_result in orphan_chunks[:5]:
                    crc_info = "CRC OK" if scan_result.is_valid else \
                        f"CRC error: stored=0x{scan_result.chunk.checksum:04x} calc=0x{scan_result.calculated_crc:04x}"
                    print(f"    Slot {scan_result.chunk.slot} "
                          f"(vdev_id={scan_result.chunk.vdev_id} INVALID): {crc_info}")
                if len(orphan_chunks) > 5:
                    print(f"    ... and {len(orphan_chunks) - 5} more")

            print(f"\nStatus: ⚠ ISSUES DETECTED")
        else:
            print(f"\nStatus: ✓ OK")

    @staticmethod
    def print_verbose_validation(
        first_block: FirstBlock,
        vdevs: List[VDevInfo],
        scan_summary: ScanSummary,
        comparison: Dict,
        validation_report: Dict[int, VDevValidation],
        orphan_chunks: List[ChunkScanResult],
        bitmap_count: int
    ):
        """Print detailed verbose validation output."""
        # Bitmap comparison
        print("\n" + "=" * 80)
        print("BITMAP vs CHUNK ARRAY CONSISTENCY CHECK")
        print("=" * 80)
        print(f"\nBitmap indicates:          {bitmap_count:,} allocated slots")
        print(f"Chunk array contains:      {scan_summary.allocated_count:,} allocated chunks")
        print(f"Consistent (both agree):   {comparison['consistent']:,} chunks")

        # CRC errors
        if comparison['bitmap_with_crc_errors']:
            print(f"\n⚠️  CRC ERRORS in bitmap-marked chunks:")
            print(f"  {len(comparison['bitmap_with_crc_errors'])} chunks with CRC mismatches:\n")
            for slot, stored, calc in comparison['bitmap_with_crc_errors'][:10]:
                print(f"    - Slot {slot}: stored=0x{stored:04x}, calculated=0x{calc:04x}")
            if len(comparison['bitmap_with_crc_errors']) > 10:
                print(f"    ... and {len(comparison['bitmap_with_crc_errors']) - 10} more")

        # Bitmap sync
        if comparison['has_inconsistency']:
            print("\n⚠️  BITMAP/CHUNK SYNC INCONSISTENCIES:")
            if comparison['in_bitmap_only']:
                print(f"\n  {len(comparison['in_bitmap_only'])} bitmap slots with missing chunks:")
                for slot in comparison['in_bitmap_only'][:10]:
                    print(f"    - Slot {slot}")
            if comparison['in_chunks_only']:
                print(f"\n  {len(comparison['in_chunks_only'])} chunks not in bitmap:")
                for slot in comparison['in_chunks_only'][:10]:
                    print(f"    - Slot {slot}")
        else:
            status = "✓ CONSISTENT"
            if comparison['bitmap_with_crc_errors']:
                status += " (but some chunks have CRC errors)"
            print(f"\n{status}")

        # VDev validation
        print("\n" + "=" * 80)
        print("VDEV VALIDATION REPORT")
        print("=" * 80)
        print("\nNOTE: Chunk counts are derived by scanning and grouping by vdev_id")

        vdev_map = {v.vdev_id: v for v in vdevs if v.is_allocated}

        for vdev_id in sorted(validation_report.keys()):
            val = validation_report[vdev_id]
            vdev = vdev_map.get(vdev_id)

            type_name = vdev.vdev_type.name_str if vdev else "UNKNOWN"
            name = vdev.name if vdev else "unknown"
            status = "✓ OK" if not val.has_issues else "✗ ISSUES"

            print(f"\nVDev {vdev_id} ({type_name} - '{name}'): {status}")
            print(f"  Capacity:      {val.vdev_size:15,} bytes ({val.vdev_size / (1024**3):8.2f} GB)")
            print(f"  Chunks:        {val.chunk_count:15,}")
            print(f"  Valid:         {val.valid_count:15,}")
            print(f"  Invalid:       {val.invalid_count:15,}")
            print(f"  Allocated:     {val.total_chunk_size:15,} bytes ({val.total_chunk_size / (1024**3):8.2f} GB)")
            print(f"  Utilization:   {val.utilization_pct:14.2f} %")

            if val.issues:
                print(f"\n  Issues:")
                for issue in val.issues[:5]:
                    print(f"    - Slot {issue.slot}, chunk_id={issue.chunk_id}: {issue.message}")
                if len(val.issues) > 5:
                    print(f"    ... and {len(val.issues) - 5} more")


# ============================================================================
# CLI Commands
# ============================================================================

def cmd_validate(args: argparse.Namespace):
    """Run validation command."""
    file_path = Path(args.filename)
    reader = SuperblockReader(file_path)

    with open(file_path, 'rb') as f:
        # Read structures
        first_block = reader.read_first_block(f)
        if not first_block.is_valid:
            print(f"✗ Invalid magic number: 0x{first_block.magic:x}")
            sys.exit(1)

        offsets = reader.calculate_offsets(first_block.pdev_info.max_pdev_chunks)
        vdevs = reader.read_vdevs(f)
        bitmap_slots = reader.read_chunk_bitmap(f, first_block.pdev_info.max_pdev_chunks)

        # Scan chunks
        max_scan = first_block.header.max_system_chunks
        scanner = ChunkScanner(reader, bitmap_slots)
        chunks_data, scan_summary = scanner.scan_all_chunks(f, max_scan, args.verbose)

        # Validate
        validator = SuperblockValidator(vdevs, chunks_data, bitmap_slots)
        validation_report, orphan_chunks = validator.validate_vdevs()
        comparison = validator.compare_bitmap_vs_chunks()

        # Output
        formatter = OutputFormatter()
        if args.verbose:
            formatter.print_verbose_validation(
                first_block, vdevs, scan_summary, comparison,
                validation_report, orphan_chunks, len(bitmap_slots)
            )
        else:
            formatter.print_compact_summary(
                first_block, vdevs, scan_summary, comparison,
                validation_report, orphan_chunks
            )

        # Exit code
        has_issues = (comparison['has_inconsistency'] or
                     scan_summary.invalid_count > 0 or
                     len(orphan_chunks) > 0)
        sys.exit(1 if has_issues else 0)


def cmd_lookup_chunk(args: argparse.Namespace):
    """Look up specific chunk."""
    file_path = Path(args.filename)
    reader = SuperblockReader(file_path)

    with open(file_path, 'rb') as f:
        first_block = reader.read_first_block(f)
        reader.calculate_offsets(first_block.pdev_info.max_pdev_chunks)

        chunk = reader.read_chunk(f, args.slot)
        is_valid = chunk.verify_checksum()
        calc_crc = chunk.calculate_checksum()

        print(f"ChunkInfo[slot={chunk.slot}] ({'ALLOCATED' if chunk.is_allocated else 'FREE'}):")
        print(f"  offset:    0x{chunk.chunk_start_offset:x}")
        print(f"  size:      {chunk.size_mb:.2f} MB")
        print(f"  vdev_id:   {chunk.vdev_id}")
        print(f"  chunk_id:  {chunk.chunk_id}")
        print(f"  checksum:  0x{chunk.checksum:04x}")
        print(f"\nValidation: {'✓ PASS' if is_valid else '✗ FAIL'}")
        if not is_valid:
            print(f"  Stored:     0x{chunk.checksum:04x}")
            print(f"  Calculated: 0x{calc_crc:04x}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Decode and validate HomeStore superblock',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('filename', help='Disk dump file')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    subparsers = parser.add_subparsers(dest='command')

    # chunk command
    chunk_parser = subparsers.add_parser('chunk', help='Look up chunk')
    chunk_parser.add_argument('slot', type=int, help='Chunk slot number')

    args = parser.parse_args()

    if args.command == 'chunk':
        cmd_lookup_chunk(args)
    else:
        cmd_validate(args)


if __name__ == '__main__':
    main()
