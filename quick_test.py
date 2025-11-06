#!/usr/bin/env python3
"""
Quick test - try offset 16 (which analyzer says is aligned)
"""

# Load the encrypted file
with open('downloads/encrypted_debug_att0.bin', 'rb') as f:
    data = f.read()

# Load AES key
with open('downloads/aes_key_att0.hex', 'r') as f:
    aes_key_hex = f.read().strip()
    aes_key = bytes.fromhex(aes_key_hex)

print(f"Data length: {len(data)}")
print(f"AES key: {aes_key_hex}")
print()

# The analyzer showed these offsets are aligned:
# Offset 0: IV at 0-16, CT at 16-112704
# Offset 16: IV at 16-32, CT at 32-112704

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


def try_decrypt(offset):
    print(f"{'=' * 60}")
    print(f"Trying offset {offset}")
    print(f"{'=' * 60}")

    iv = data[offset:offset + 16]
    ciphertext = data[offset + 16:]

    print(f"IV: {iv.hex()}")
    print(f"Ciphertext length: {len(ciphertext)} (mod 16 = {len(ciphertext) % 16})")

    if len(ciphertext) % 16 != 0:
        print("❌ Not aligned!")
        return None

    # Decrypt
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    print(f"Decrypted {len(plaintext)} bytes")
    print(f"First 64 bytes (hex): {plaintext[:64].hex()}")
    print(f"First 16 bytes (ascii): {plaintext[:16]}")

    # Check for PDF
    if plaintext.startswith(b'%PDF'):
        print("✓✓✓ THIS IS A PDF! ✓✓✓")

        # Try unpadding
        unpadder = sym_padding.PKCS7(128).unpadder()
        try:
            unpadded = unpadder.update(plaintext) + unpadder.finalize()
            plaintext = unpadded
            print(f"Unpadded to {len(plaintext)} bytes")
        except:
            print("Unpadding failed, using as-is")

        return plaintext
    else:
        print(f"❌ Not PDF. First 4 bytes: {plaintext[:4].hex()} (expected 25504446)")
        return None


# Try offset 0
result = try_decrypt(0)
if result:
    with open('downloads/decrypted_offset0.pdf', 'wb') as f:
        f.write(result)
    print(f"\n✓ Saved: downloads/decrypted_offset0.pdf")
    exit(0)

print()

# Try offset 16
result = try_decrypt(16)
if result:
    with open('downloads/decrypted_offset16.pdf', 'wb') as f:
        f.write(result)
    print(f"\n✓ Saved: downloads/decrypted_offset16.pdf")
    exit(0)

print()

# Try a few more just in case
for offset in [8, 12, 20, 24, 32]:
    result = try_decrypt(offset)
    if result:
        with open(f'downloads/decrypted_offset{offset}.pdf', 'wb') as f:
            f.write(result)
        print(f"\n✓ Saved: downloads/decrypted_offset{offset}.pdf")
        exit(0)
    print()

print("\n❌ No valid PDF found at any offset!")
print("\nThe issue might be:")
print("  1. Wrong AES key")
print("  2. Different encryption scheme")
print("  3. Corrupted encrypted data")
print("\nNext: Check if decrypted_offset0_FAILED.bin has any recognizable patterns")