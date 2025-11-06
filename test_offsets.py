#!/usr/bin/env python3
"""
Explicit EDT Decryption Tester
Tests specific offsets that the analyzer identified as aligned
"""

import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


def test_specific_offsets(encrypted_file: str, aes_key_hex_file: str):
    """
    Test decryption with specific offsets identified by the analyzer
    """

    # Load encrypted data
    with open(encrypted_file, 'rb') as f:
        data = f.read()

    # Load AES key
    with open(aes_key_hex_file, 'r') as f:
        aes_key = bytes.fromhex(f.read().strip())

    print(f"Loaded encrypted file: {len(data)} bytes")
    print(f"Loaded AES key: {len(aes_key)} bytes = {aes_key.hex()}")
    print(f"\nFirst 64 bytes of encrypted data:")
    print(f"  {data[:64].hex()}")

    # According to analyzer, these offsets are aligned:
    # - Offset 0: CT_len=112,688 remainder=0
    # - Offset 16: CT_len=112,672 remainder=0

    test_offsets = [0, 16, 4, 8, 12, 20, 24, 28, 32]

    print(f"\n{'=' * 70}")
    print("TESTING SPECIFIC OFFSETS")
    print(f"{'=' * 70}")

    for offset in test_offsets:
        if len(data) < offset + 32:
            print(f"\nOffset {offset}: Not enough data")
            continue

        iv = data[offset:offset + 16]
        ciphertext = data[offset + 16:]

        print(f"\n{'=' * 70}")
        print(f"OFFSET {offset}")
        print(f"{'=' * 70}")
        print(f"IV:         {iv.hex()}")
        print(f"CT length:  {len(ciphertext)} bytes (mod 16 = {len(ciphertext) % 16})")

        if len(ciphertext) % 16 != 0:
            print(f"❌ SKIPPED - Not aligned to 16-byte blocks")
            continue

        try:
            # Decrypt
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            print(f"Decrypted:  {len(padded_plaintext)} bytes")
            print(f"First 64 bytes (hex): {padded_plaintext[:64].hex()}")
            print(f"First 64 bytes (raw): {padded_plaintext[:64]}")

            # Check for PDF header
            if padded_plaintext.startswith(b'%PDF'):
                print(f"\n✓✓✓ SUCCESS! This is a valid PDF! ✓✓✓")

                # Try unpadding
                unpadder = sym_padding.PKCS7(128).unpadder()
                try:
                    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
                    print(f"After unpadding: {len(plaintext)} bytes")
                except Exception as e:
                    print(f"Unpadding failed (using padded): {e}")
                    plaintext = padded_plaintext

                # Save it
                output_path = f"downloads/decrypted_offset{offset}_SUCCESS.pdf"
                with open(output_path, 'wb') as f:
                    f.write(plaintext)
                print(f"\n✓ Saved to: {output_path}")

                return output_path
            else:
                print(f"❌ Not a PDF - First 4 bytes: {padded_plaintext[:4].hex()} (expected: 25504446)")

                # Save for inspection
                debug_path = f"downloads/decrypted_offset{offset}_FAILED.bin"
                with open(debug_path, 'wb') as f:
                    f.write(padded_plaintext[:1024])  # Save first 1KB
                print(f"   Saved first 1KB to: {debug_path}")

        except Exception as e:
            print(f"❌ EXCEPTION: {e}")
            import traceback
            traceback.print_exc()

    print(f"\n{'=' * 70}")
    print("❌ NO VALID PDF FOUND AT ANY OFFSET")
    print(f"{'=' * 70}")
    return None


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 3:
        print("Usage: python test_offsets.py <encrypted_file> <aes_key_hex_file>")
        print("\nExample:")
        print("  python test_offsets.py downloads/encrypted_debug_att0.bin downloads/aes_key_att0.hex")
        sys.exit(1)

    result = test_specific_offsets(sys.argv[1], sys.argv[2])

    if result:
        print(f"\n🎉 SUCCESS! Valid PDF created: {result}")
        print(f"\nVerify with:")
        print(f"  xxd -l 32 {result}")
        print(f"  file {result}")
        print(f"  xdg-open {result}")
    else:
        print(f"\n❌ Failed to decrypt PDF")
        print(f"\nNext steps:")
        print(f"  1. Check the decrypted_offset*_FAILED.bin files")
        print(f"  2. Verify the AES key is correct")
        print(f"  3. Check if the encrypted data has a different structure")