#!/usr/bin/env python3
"""
EDT Encrypted Blob Analyzer
Helps diagnose decryption issues by analyzing the structure of encrypted files
"""

import sys
import os


def analyze_encrypted_blob(filepath: str):
    """Analyze an encrypted EDT blob to find potential IV/ciphertext boundaries"""

    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        return

    with open(filepath, 'rb') as f:
        data = f.read()

    print("=" * 70)
    print(f"ANALYZING: {filepath}")
    print("=" * 70)
    print(f"Total size: {len(data)} bytes")
    print(f"\nFirst 128 bytes (hex):")
    for i in range(0, min(128, len(data)), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i + 16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i + 16])
        print(f"  {i:04x}: {hex_part:<48} {ascii_part}")

    print(f"\nLast 64 bytes (hex):")
    start = max(0, len(data) - 64)
    for i in range(start, len(data), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i + 16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i + 16])
        print(f"  {i:04x}: {hex_part:<48} {ascii_part}")

    # Check for common patterns
    print("\n" + "=" * 70)
    print("PATTERN ANALYSIS")
    print("=" * 70)

    # Check for length prefix (common in many formats)
    if len(data) >= 4:
        # Try big-endian and little-endian interpretations
        be_len = int.from_bytes(data[0:4], 'big')
        le_len = int.from_bytes(data[0:4], 'little')
        print(f"First 4 bytes as length:")
        print(f"  Big-endian:    {be_len:,} (0x{be_len:08x})")
        print(f"  Little-endian: {le_len:,} (0x{le_len:08x})")
        print(f"  Actual data:   {len(data):,} bytes")

        if abs(be_len - len(data)) < 100:
            print(f"  → Big-endian length matches! Offset might be 4")
        if abs(le_len - len(data)) < 100:
            print(f"  → Little-endian length matches! Offset might be 4")

    # Check alignment for common offsets
    print(f"\nAlignment check (ciphertext must be multiple of 16):")
    for offset in [0, 4, 8, 12, 16, 20, 24]:
        if offset >= len(data):
            break
        iv = data[offset:offset + 16]
        ciphertext = data[offset + 16:]
        remainder = len(ciphertext) % 16
        marker = "✓" if remainder == 0 else "✗"
        print(f"  Offset {offset:2d}: IV={iv.hex()[:16]}... CT_len={len(ciphertext):,} remainder={remainder} {marker}")

    # Check for trailing garbage
    print(f"\nTrailing bytes check:")
    for suffix, name in [(b'\r\n\r', '\\r\\n\\r'), (b'\n\r\n', '\\n\\r\\n'),
                         (b'\r\n', '\\r\\n'), (b'\n', '\\n')]:
        if data.endswith(suffix):
            print(f"  ✓ Ends with {name} (remove {len(suffix)} bytes)")
            cleaned_len = len(data) - len(suffix)
            print(f"    After removal: {cleaned_len} bytes")
            for offset in [0, 4, 8]:
                ct_len = cleaned_len - offset - 16
                if ct_len > 0 and ct_len % 16 == 0:
                    print(f"    → With offset {offset}: ciphertext would be {ct_len} bytes (aligned!)")

    # Statistical analysis
    print(f"\nByte frequency (first 64 bytes):")
    freq = {}
    for b in data[:64]:
        freq[b] = freq.get(b, 0) + 1

    # Show top 5 most common bytes
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:5]
    for byte_val, count in sorted_freq:
        print(f"  0x{byte_val:02x}: {count} times")

    # Detect potential structure
    print("\n" + "=" * 70)
    print("RECOMMENDATIONS")
    print("=" * 70)

    # Check if starts with length
    if len(data) >= 4:
        be_len = int.from_bytes(data[0:4], 'big')
        if abs(be_len - (len(data) - 4)) < 16:
            print("✓ Likely has 4-byte big-endian length prefix")
            print("  Try: offset=4, then IV is bytes [4:20], ciphertext is [20:]")

        le_len = int.from_bytes(data[0:4], 'little')
        if abs(le_len - (len(data) - 4)) < 16:
            print("✓ Likely has 4-byte little-endian length prefix")
            print("  Try: offset=4, then IV is bytes [4:20], ciphertext is [20:]")

    # Check if it's aligned without offset
    if (len(data) - 16) % 16 == 0:
        print("✓ Data aligns perfectly with offset=0")
        print("  Try: IV is bytes [0:16], ciphertext is [16:]")

    # Check common offsets after cleaning
    for trail_len in [3, 2, 1, 0]:
        cleaned = len(data) - trail_len
        for offset in [0, 4, 8]:
            ct_len = cleaned - offset - 16
            if ct_len > 0 and ct_len % 16 == 0:
                print(f"✓ Perfect alignment: remove last {trail_len} bytes, use offset={offset}")
                print(f"  IV: bytes[{offset}:{offset + 16}], CT: bytes[{offset + 16}:{cleaned}]")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_edt_blob.py <encrypted_file>")
        print("\nExample:")
        print("  python3 analyze_edt_blob.py downloads/encrypted_debug_att0.bin")
        sys.exit(1)

    analyze_encrypted_blob(sys.argv[1])