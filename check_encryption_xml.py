#!/usr/bin/env python3
"""
Check what encryption algorithm the Ontario EDT XML specifies
"""

import sys,os
import xml.etree.ElementTree as ET
from xml.dom import minidom


def analyze_encryption_xml(xml_content: str):
    """Extract encryption details from Ontario EDT response XML"""

    print("=" * 70)
    print("ONTARIO EDT ENCRYPTION ANALYSIS")
    print("=" * 70)

    try:
        root = ET.fromstring(xml_content)
    except Exception as e:
        print(f"❌ XML parsing failed: {e}")
        return

    # Pretty print the XML (first 2000 chars)
    try:
        dom = minidom.parseString(xml_content)
        pretty = dom.toprettyxml(indent="  ")
        print("\nXML Structure (first 2000 chars):")
        print("-" * 70)
        print(pretty[:2000])
        print("-" * 70)
    except:
        pass

    print("\nENCRYPTION DETAILS:")
    print("-" * 70)

    # Find all encryption-related elements
    namespaces = {
        'xenc': 'http://www.w3.org/2001/04/xmlenc#',
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
        'edt': 'http://edt.health.ontario.ca/',
    }

    # Check for EncryptedData
    encrypted_data = root.findall('.//{http://www.w3.org/2001/04/xmlenc#}EncryptedData')
    print(f"EncryptedData elements found: {len(encrypted_data)}")

    for i, ed in enumerate(encrypted_data):
        print(f"\nEncryptedData #{i + 1}:")

        # Encryption method
        enc_method = ed.find('{http://www.w3.org/2001/04/xmlenc#}EncryptionMethod')
        if enc_method is not None:
            algorithm = enc_method.get('Algorithm', 'Not specified')
            print(f"  Algorithm: {algorithm}")

            # Decode algorithm
            if 'aes128-cbc' in algorithm.lower():
                print(f"    → AES-128-CBC ✓")
            elif 'aes256-cbc' in algorithm.lower():
                print(f"    → AES-256-CBC (key should be 32 bytes!)")
            elif 'aes192-cbc' in algorithm.lower():
                print(f"    → AES-192-CBC (key should be 24 bytes!)")
            elif 'tripledes-cbc' in algorithm.lower():
                print(f"    → 3DES-CBC")
            else:
                print(f"    → Unknown/Other")

        # Key info
        key_info = ed.find('{http://www.w3.org/2001/04/xmlenc#}KeyInfo')
        if key_info:
            print(f"  KeyInfo found: Yes")

    # Check for EncryptedKey
    encrypted_keys = root.findall('.//{http://www.w3.org/2001/04/xmlenc#}EncryptedKey')
    print(f"\n\nEncryptedKey elements found: {len(encrypted_keys)}")

    for i, ek in enumerate(encrypted_keys):
        print(f"\nEncryptedKey #{i + 1}:")

        # Encryption method for the key
        enc_method = ek.find('{http://www.w3.org/2001/04/xmlenc#}EncryptionMethod')
        if enc_method is not None:
            algorithm = enc_method.get('Algorithm', 'Not specified')
            print(f"  Key Encryption Algorithm: {algorithm}")

            if 'rsa-oaep' in algorithm.lower():
                print(f"    → RSA-OAEP")
            elif 'rsa-1_5' in algorithm.lower() or 'rsaes-pkcs1-v1_5' in algorithm.lower():
                print(f"    → RSA-PKCS1-v1.5 ✓")
            else:
                print(f"    → Other")

        # CipherValue (the encrypted key itself)
        cipher_value = ek.find('.//{http://www.w3.org/2001/04/xmlenc#}CipherValue')
        if cipher_value is not None and cipher_value.text:
            key_b64 = cipher_value.text.strip()
            import base64
            try:
                key_bytes = base64.b64decode(key_b64)
                print(f"  Encrypted Key Length: {len(key_bytes)} bytes")
                print(f"  First 32 bytes: {key_bytes[:32].hex()}")
            except:
                print(f"  Encrypted Key: {len(key_b64)} characters (base64)")

    # Check CipherData
    print("\n\nCIPHER DATA:")
    print("-" * 70)
    cipher_data = root.findall('.//{http://www.w3.org/2001/04/xmlenc#}CipherData')
    print(f"CipherData elements found: {len(cipher_data)}")

    for i, cd in enumerate(cipher_data):
        print(f"\nCipherData #{i + 1}:")

        # Check for CipherValue (inline encrypted data)
        cipher_value = cd.find('{http://www.w3.org/2001/04/xmlenc#}CipherValue')
        if cipher_value is not None:
            print(f"  Type: Inline (CipherValue)")
            if cipher_value.text:
                print(f"  Length: {len(cipher_value.text)} characters (base64)")

        # Check for CipherReference (external data)
        cipher_ref = cd.find('{http://www.w3.org/2001/04/xmlenc#}CipherReference')
        if cipher_ref is not None:
            uri = cipher_ref.get('URI', 'Not specified')
            print(f"  Type: External (CipherReference)")
            print(f"  URI: {uri}")

    # Check for description (filename hint)
    print("\n\nFILE INFO:")
    print("-" * 70)
    descriptions = root.findall('.//{http://edt.health.ontario.ca/}description')
    for i, desc in enumerate(descriptions):
        if desc.text:
            print(f"Description #{i + 1}: {desc.text}")

    print("\n" + "=" * 70)
    print("SUMMARY:")
    print("=" * 70)
    print(f"✓ Found {len(encrypted_keys)} encrypted key(s)")
    print(f"✓ Found {len(encrypted_data)} encrypted data element(s)")
    print(f"✓ Found {len(cipher_data)} cipher data element(s)")


if __name__ == '__main__':
    # Try to read from the response file
    import glob

    # Look for recent response files
    response_files = glob.glob('results/*OBECE*.xml') + glob.glob('results/*.xml')

    if response_files:
        print(f"Found {len(response_files)} response file(s)")
        latest = max(response_files, key=lambda x: os.path.getmtime(x))
        print(f"Using: {latest}\n")

        with open(latest, 'r') as f:
            content = f.read()

        # Try to extract just the SOAP body
        if 'soapenv:Body' in content or 'soap:Body' in content:
            analyze_encryption_xml(content)
        else:
            print("⚠️  This doesn't look like a SOAP response")
            print("Analyzing anyway...\n")
            analyze_encryption_xml(content)
    else:
        print("Usage: python check_encryption_xml.py")
        print("\nOr provide XML content:")
        print("  python check_encryption_xml.py < response.xml")

        if not sys.stdin.isatty():
            content = sys.stdin.read()
            analyze_encryption_xml(content)