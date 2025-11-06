import base64
import datetime
import hashlib
import random
import uuid
import xml.etree.ElementTree as ET
from typing import Tuple
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from lxml import etree  # For C14N canonicalization
from dotenv import load_dotenv
import os
import email
from email import message_from_bytes, message_from_string
import io

load_dotenv("local.env")

# Initialize with input parameters to this API
method = "download"
# method = "getTypeList"
directory = "MCEDT_Upload_Files"
file_to_process1 = "CLAIM FILE.txt"
claimfile = f'{directory}/{file_to_process1}'
current_number = '4.8'
responseFile = f'results/{current_number}_{directory}_{file_to_process1}'
responseFile = responseFile.replace(".txt", ".xml")
responseFile = responseFile.replace(".blob", ".xml")
responseFile = responseFile.replace(file_to_process1.split(".")[1], ".xml")
resourceID = "90253"
resourceID2 = "95284"
resourceID3 = "90242"
resourceID4 = "95654"
resourceID5 = "95655"
resourceID6 = "95656"
resourceID7 = "95657"

file_to_process2 = "2_OBECE.TXT"
file_to_process3 = "3_OBECE.TXT"
file_to_process4 = "4_OBECE.TXT"
file_to_process5 = "5_OBECE.TXT"
file_to_process6 = "6_OBECE.TXT"
claimfile2 = f'{directory}/{file_to_process2}'
claimfile3 = f'{directory}/{file_to_process3}'
claimfile4 = f'{directory}/{file_to_process4}'
claimfile5 = f'{directory}/{file_to_process5}'
claimfile6 = f'{directory}/{file_to_process6}'

# For list method
resourceType = 'CL'  # OPTIONAL can leave empty
resourceStatus = 'UPLOADED'
resourcePage = 1  # OPTIONAL can leave empty

# Scroll down to replace conformance testing key further down the code base
MOH_ID = os.getenv('MOH_ID')
username = os.getenv('username')
password = os.getenv('password')
conformance_key = os.getenv('conformance_key')
KEY = os.getenv('KEY')

# Load the PKCS#12 file
with open('teststore.p12', 'rb') as f:
    pkcs12 = f.read()

# Parse the PKCS#12 file to extract private key and certificate
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

private_key, certificate, _ = load_key_and_certificates(pkcs12, b'changeit')


def loadbody() -> str:
    global method, claimfile, resourceID, resourceType, resourceStatus, resourcePage
    if method == 'getTypeList':
        rawbody = """
         <soapenv:Body wsu:Id="id-5">
            <edt:getTypeList/>
         </soapenv:Body>
        """
    elif method == 'list':
        rawbody = f"""
         <soapenv:Body wsu:Id="id-5">
            <edt:list>
               <!--Optional:-->
               <resourceType>{resourceType}</resourceType>
               <!--Optional:-->
               <status>{resourceStatus}</status>
               <!--Optional:-->
               <pageNo>{resourcePage}</pageNo>
            </edt:list>
         </soapenv:Body>
        """
    elif method == 'upload':
        rawbody = f"""
            <soapenv:Body wsu:Id="id-5">

              <edt:upload>

                 <!--1 to 5 repetitions:-->
                 <upload>
                    <content>
                      <inc:Include href="cid:{claimfile}" xmlns:inc="http://www.w3.org/2004/08/xop/include" />
                    </content>
                    <!--Optional:-->
                    <description>{claimfile}</description>
                    <resourceType>{resourceType}</resourceType>
                 </upload>


              </edt:upload>
            </soapenv:Body>
        """
    elif method == 'update':
        rawbody = f"""
         <soapenv:Body wsu:Id="id-5">
          <edt:update>
             <!--1 to 5 repetitions:-->
             <updates>
                <content>
                    <inc:Include href="cid:{claimfile}" xmlns:inc="http://www.w3.org/2004/08/xop/include" />
                </content>
                <resourceID>{resourceID}</resourceID>
             </updates>

          </edt:update>
         </soapenv:Body>
        """
    elif method in ['info', 'delete', 'submit', 'download']:
        rawbody = f"""
         <soapenv:Body wsu:Id="id-5">
            <edt:{method}>
               <!--1 to 100 repetitions:-->
               <resourceIDs>{resourceID}</resourceIDs>
            </edt:{method}>
         </soapenv:Body>
        """
    else:
        raise ValueError("invalid method parameter")
    return rawbody.strip()


def loadtimestamp() -> str:
    # Create the first timestamp
    first_timestamp = datetime.datetime.now(datetime.timezone.utc)
    first_timestamp_str = first_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    # Create the second timestamp (10 minutes after the first one)
    second_timestamp = first_timestamp + datetime.timedelta(minutes=10)
    second_timestamp_str = second_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    timestamp = f"""
  <wsu:Timestamp wsu:Id="TS-1">
    <wsu:Created>{first_timestamp_str}</wsu:Created>
    <wsu:Expires>{second_timestamp_str}</wsu:Expires>
  </wsu:Timestamp>
    """
    return timestamp.strip()


def loadUsernameToken(username: str, password: str) -> str:
    usernameToken = f"""
  <wsse:UsernameToken wsu:Id="UsernameToken-2">
      <wsse:Username>{username}</wsse:Username>
      <wsse:Password 
      Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">{password}</wsse:Password>
  </wsse:UsernameToken>
    """
    return usernameToken.strip()


def loadIDP(MOH_ID: str) -> str:
    IDP = f"""
  <idp:IDP wsu:Id="id-3">
    <ServiceUserMUID>{MOH_ID}</ServiceUserMUID>
  </idp:IDP>
    """
    return IDP.strip()


def loadEBS() -> str:
    audit_id = str(uuid.uuid4())

    EBS = f"""
  <ebs:EBS wsu:Id="id-4">
      <SoftwareConformanceKey>{conformance_key}</SoftwareConformanceKey>
      <AuditId>{audit_id}</AuditId>
  </ebs:EBS>
    """
    return EBS.strip()


# given xml input, digestxml will canonicalize xml then hash it with SHA256, returning a hash value as digest string
def digestxml(xml: str) -> str:
    # Parse the XML
    parser = etree.XMLParser(remove_blank_text=True)
    root = etree.fromstring(xml.encode('utf-8'), parser)

    # Canonicalize the document using C14N version 1.0
    canonicalized_xml = etree.tostring(
        root,
        method="c14n",
        exclusive=False,  # We are using inclusive C14N as per WS-Security
        with_comments=False
    )

    # Calculate SHA-256 hash
    digest_value = base64.b64encode(hashlib.sha256(canonicalized_xml).digest()).decode('utf-8')
    return digest_value


def loadxmltemplate() -> str:
    root_namespaces = ' xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ebs="http://ebs.health.ontario.ca/" xmlns:edt="http://edt.health.ontario.ca/" xmlns:idp="http://idp.ebs.health.ontario.ca/" xmlns:msa="http://msa.ebs.health.ontario.ca/" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:inc="http://www.w3.org/2004/08/xop/include"'

    # insert namespace definition from all parent nodes ($root_namespaces) into the xml part to be canonicalized. this is required, otherwise wsu or soapenv namespace would be undefined.

    timestamp = loadtimestamp()
    modtimestamp = timestamp.replace('<wsu:Timestamp', f'<wsu:Timestamp{root_namespaces}', 1)
    digestvalue1 = digestxml(modtimestamp)

    usernameToken = loadUsernameToken(username, password)
    modusernameToken = usernameToken.replace('<wsse:UsernameToken', f'<wsse:UsernameToken{root_namespaces}', 1)
    digestvalue2 = digestxml(modusernameToken)

    IDP = loadIDP(MOH_ID)
    modifiedIDP = IDP.replace('<idp:IDP', f'<idp:IDP{root_namespaces}', 1)
    digestvalue3 = digestxml(modifiedIDP)

    EBS = loadEBS()
    modifiedEBS = EBS.replace('<ebs:EBS', f'<ebs:EBS{root_namespaces}', 1)
    digestvalue4 = digestxml(modifiedEBS)

    body = loadbody()
    modifiedbody = body.replace('<soapenv:Body', f'<soapenv:Body{root_namespaces}', 1)
    digestvalue5 = digestxml(modifiedbody)

    signedInfo = f"""
<ds:SignedInfo>
  <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
    <ec:InclusiveNamespaces PrefixList="ebs edt idp msa soapenv wsu"
    xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  </ds:CanonicalizationMethod>
  <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#TS-1">
    <ds:Transforms>
      <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
        <ec:InclusiveNamespaces PrefixList="ebs edt idp msa"
        xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </ds:Transform>
    </ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>{digestvalue1}</ds:DigestValue>
  </ds:Reference>
  <ds:Reference URI="#UsernameToken-2">
    <ds:Transforms>
      <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
        <ec:InclusiveNamespaces PrefixList="wsse ebs edt idp msa soapenv"
        xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </ds:Transform>
    </ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>{digestvalue2}</ds:DigestValue>
  </ds:Reference>
  <ds:Reference URI="#id-3">
    <ds:Transforms>
      <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
        <ec:InclusiveNamespaces PrefixList="ebs edt msa soapenv"
        xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </ds:Transform>
    </ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>{digestvalue3}</ds:DigestValue>
  </ds:Reference>
  <ds:Reference URI="#id-4">
    <ds:Transforms>
      <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
        <ec:InclusiveNamespaces PrefixList="edt idp msa soapenv"
        xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </ds:Transform>
    </ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>{digestvalue4}</ds:DigestValue>
  </ds:Reference>
  <ds:Reference URI="#id-5">
    <ds:Transforms>
      <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
        <ec:InclusiveNamespaces PrefixList="ebs edt idp msa soapenv"
        xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </ds:Transform>
    </ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>{digestvalue5}</ds:DigestValue>
  </ds:Reference>
</ds:SignedInfo>
    """.strip()

    # insert namespace from all parent nodes before canonicalization
    modsignedInfo = signedInfo.replace('<ds:SignedInfo', f'<ds:SignedInfo{root_namespaces}', 1)

    # Parse the XML for C14N
    parser = etree.XMLParser(remove_blank_text=True)
    root = etree.fromstring(modsignedInfo.encode('utf-8'), parser)

    # Canonicalize the document using C14N version 1.0
    canonicalized_xml = etree.tostring(root, method="c14n", exclusive=False, with_comments=False)
    # Calculate SHA-1 hash of $signedInfo
    digest = hashlib.sha1(canonicalized_xml).digest()

    # Sign the SHA-1 hash using private key and PKCS1 padding
    signature = private_key.sign(
        digest,
        padding.PKCS1v15(),
        hashes.SHA1()
    )
    signature = base64.b64encode(signature).decode('utf-8')

    rawxml = f"""
<soapenv:Envelope
xmlns:ebs="http://ebs.health.ontario.ca/"
xmlns:edt="http://edt.health.ontario.ca/"
xmlns:idp="http://idp.ebs.health.ontario.ca/"
xmlns:msa="http://msa.ebs.health.ontario.ca/"
xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
<soapenv:Header>
<wsse:Security
xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
<wsse:BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" wsu:Id="X509-4A6564966742022D8B170319672914254">{KEY}</wsse:BinarySecurityToken>
{loadUsernameToken(username, password)}
{loadtimestamp()}
<ds:Signature Id="SIG-6" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
{signedInfo}
<ds:SignatureValue>
{signature}
</ds:SignatureValue>
<ds:KeyInfo Id="KI-4A6564966742022D8B170319672914255">
  <wsse:SecurityTokenReference wsu:Id="STR-4A6564966742022D8B170319672914256">
    <wsse:Reference URI="#X509-4A6564966742022D8B170319672914254" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
  </wsse:SecurityTokenReference>
</ds:KeyInfo>
</ds:Signature>
</wsse:Security>
{loadIDP(MOH_ID)}
{loadEBS()}
</soapenv:Header>
{loadbody()}
</soapenv:Envelope>
    """.strip()
    return rawxml


def sendrequest(xmlPayload: str) -> Tuple[int, str, bytes]:
    """Send request and return status code, text response, and raw bytes"""
    url = 'https://ws.conf.ebs.health.gov.on.ca:1443/EDTService/EDTService'

    global method, claimfile
    if method in ['upload', 'update']:
        with open(claimfile, 'rb') as f:
            fileContent = f.read().decode('utf-8')  # Assuming text file, decode if needed

        # Boundary for the multipart message
        boundary = '----=Boundary_' + hashlib.md5(str(random.random()).encode()).hexdigest()

        # Construct the MIME message
        mimeMessage = f"--{boundary}\r\n"
        mimeMessage += "Content-Type: application/xop+xml; charset=UTF-8; type=\"text/xml\"\r\n"
        mimeMessage += "Content-Transfer-Encoding: 8bit\r\n"
        mimeMessage += "Content-ID: <rootpart@soapui.org>\r\n\r\n"
        mimeMessage += f"{xmlPayload}\r\n"
        mimeMessage += f"--{boundary}\r\n"
        mimeMessage += "Content-Type: text/plain; charset=us-ascii\r\n"
        mimeMessage += "Content-Transfer-Encoding: 7bit\r\n"
        mimeMessage += f"Content-ID: <{claimfile}>\r\n"
        mimeMessage += f"Content-Disposition: attachment;   name=\"{claimfile}\"\r\n\r\n"
        mimeMessage += f"{fileContent}\r\n"
        mimeMessage += f"--{boundary}--"

        headers = {
            "Content-Type": f"multipart/related; type=\"application/xop+xml\"; start=\"<rootpart@soapui.org>\"; start-info=\"text/xml\"; boundary=\"{boundary}\"",
            'MIME-Version': '1.0',
        }

        xmlPayload = mimeMessage
    else:
        headers = {
            'Content-Type': 'text/xml;charset=UTF-8',
        }

    # Send request
    response = requests.post(url, data=xmlPayload.encode('utf-8'), headers=headers, verify='cacert.pem')

    # Write to log file
    with open(responseFile, 'w') as httpLogFile:
        # Request
        httpLogFile.write(str(response.request.headers) + '\n\n')
        httpLogFile.write(xmlPayload + '\n\n\n')
        # Response
        httpLogFile.write(str(response.headers) + '\n\n')
        httpLogFile.write(response.text + '\n')

    return response.status_code, response.text, response.content


def parse_multipart_response(response_content: bytes) -> list:
    """Ontario EDT real response parser - works with their exact broken headers"""
    text = response_content.decode('utf-8', errors='ignore')
    boundary = None

    # Their server sends: boundary=MIMEBoundary_xxx WITHOUT quotes!
    for line in text.splitlines():
        if 'boundary=' in line and 'MIMEBoundary' in line:
            boundary = line.split('boundary=', 1)[1].split(';')[0].strip()
            break

    if not boundary:
        # Fallback: brute-force search for --MIMEBoundary
        import re
        match = re.search(br'--MIMEBoundary[-_a-zA-Z0-9]+', response_content)
        if match:
            boundary = match.group(0).decode().lstrip('-')
        else:
            print("Boundary detection failed completely")
            return []

    print(f"BOUNDARY FOUND: {boundary}")
    full_boundary = f"--{boundary}".encode()
    parts = response_content.split(full_boundary)
    cleaned_parts = []

    for i, part in enumerate(parts[1:]):  # skip first empty
        if b'--' in part[:10]:  # end marker
            part = part.split(b'--')[0]
        if not part.strip():
            continue

        # Split headers and body
        separator = b'\r\n\r\n' if b'\r\n\r\n' in part else b'\n\n'
        if separator not in part:
            continue
        headers, body = part.split(separator, 1)

        # Clean body
        body = body.strip()
        if body.endswith(b'\r\n'):
            body = body[:-2]

        headers_dict = {}
        for h in headers.split(b'\r\n'):
            if b':' in h:
                k, v = h.split(b':', 1)
                headers_dict[k.decode(errors='ignore').strip()] = v.decode(errors='ignore').strip()

        cid = headers_dict.get('Content-ID', '').strip('<>')
        ctype = headers_dict.get('Content-Type', 'application/octet-stream')

        cleaned_parts.append({
            'content': body,
            'content_id': cid,
            'content_type': ctype,
            'headers': headers_dict
        })
        print(f"Part {i + 1} | CID: {cid} | Type: {ctype} | Size: {len(body)} bytes")

    return cleaned_parts

def detect_file_type(data: bytes) -> str:
    """Detect file type from binary data using magic bytes"""

    # Common file signatures (magic bytes)
    if data.startswith(b'%PDF'):
        return '.pdf'
    elif data.startswith(b'\x89PNG'):
        return '.png'
    elif data.startswith(b'\xFF\xD8\xFF'):
        return '.jpg'
    elif data.startswith(b'GIF87a') or data.startswith(b'GIF89a'):
        return '.gif'
    elif data.startswith(b'PK\x03\x04'):
        # Could be zip, docx, xlsx, etc.
        if b'word/' in data[:1000]:
            return '.docx'
        elif b'xl/' in data[:1000]:
            return '.xlsx'
        elif b'ppt/' in data[:1000]:
            return '.pptx'
        else:
            return '.zip'
    elif data.startswith(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'):
        # Old Microsoft Office format
        return '.doc'  # Could also be .xls, .ppt
    elif data.startswith(b'<?xml') or data.startswith(b'<html'):
        return '.xml' if data.startswith(b'<?xml') else '.html'
    elif data.startswith(b'MSH|') or data.startswith(b'FHS|'):
        return '.hl7'  # HL7 message
    else:
        # Check if it's plain text
        try:
            data[:1000].decode('utf-8')
            return '.txt'
        except:
            # Default to .dat for unknown binary
            return '.dat'


def decryptResponse(responseXML: str, response_bytes: bytes = None) -> str:
    """
    Improved decryption that tries multiple offsets to find the correct IV position.
    Ontario EDT sometimes adds metadata/length prefixes before the IV+ciphertext.
    """
    if not response_bytes or b'MIMEBoundary' not in response_bytes:
        return responseXML

    print("Starting EDT decryption...")
    parts = parse_multipart_response(response_bytes)
    if len(parts) < 2:
        return "Parsing failed - no attachment found"

    xml_part = parts[0]['content'].decode('utf-8', 'ignore')
    attachments = parts[1:]

    try:
        root = ET.fromstring(xml_part)
    except Exception as e:
        return f"XML parse failed: {e}"

    # Find EncryptedKey CipherValue
    encrypted_key_b64 = None
    for elem in root.iter():
        if elem.tag.endswith('EncryptedKey'):
            cv = elem.find('.//{http://www.w3.org/2001/04/xmlenc#}CipherValue')
            if cv is not None and cv.text:
                encrypted_key_b64 = cv.text.strip()
                break

    if not encrypted_key_b64:
        return "No EncryptedKey found"

    try:
        aes_key = private_key.decrypt(base64.b64decode(encrypted_key_b64), padding.PKCS1v15())
        print(f"✓ AES key decrypted: {len(aes_key)} bytes")
        print(f"  Key (first 16 hex): {aes_key[:16].hex()}")
    except Exception as e:
        return f"RSA decrypt failed: {e}"

    os.makedirs("downloads", exist_ok=True)
    saved = []

    for i, att in enumerate(attachments):
        data = att['content']
        print(f"\n{'=' * 60}")
        print(f"Processing attachment {i + 1}")
        print(f"{'=' * 60}")
        print(f"Original length: {len(data)} bytes")
        print(f"First 64 bytes: {data[:64].hex()}")
        print(f"Last 16 bytes:  {data[-16:].hex()}")

        # Clean up trailing garbage
        original_len = len(data)
        for trailer in [b'\r\n\r', b'\n\r\n', b'\r\n', b'\n']:
            if data.endswith(trailer):
                data = data[:-len(trailer)]
                print(f"✓ Removed {repr(trailer)} trailer")
                break

        if len(data) != original_len:
            print(f"  New length: {len(data)} bytes")

        # Try multiple offsets to find where IV actually starts
        best_plaintext = None
        best_offset = None

        print(f"\nTrying offsets 0-32 to find valid PDF header...")
        for offset in range(33):
            if len(data) < offset + 16 + 16:  # Need at least IV + one block
                continue

            test_iv = data[offset:offset + 16]
            test_ciphertext = data[offset + 16:]

            # AES-CBC requires ciphertext to be multiple of 16
            if len(test_ciphertext) % 16 != 0:
                if offset < 5:
                    print(f"  [{offset:2d}] Skipped - ciphertext not aligned (len={len(test_ciphertext)})")
                continue

            try:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(test_iv))
                decryptor = cipher.decryptor()
                padded = decryptor.update(test_ciphertext) + decryptor.finalize()

                # Try PKCS7 unpadding
                from cryptography.hazmat.primitives import padding as sym_padding
                unpadder = sym_padding.PKCS7(128).unpadder()
                try:
                    plaintext = unpadder.update(padded) + unpadder.finalize()
                except:
                    # Unpadding failed, use padded data
                    plaintext = padded

                # Check for PDF magic bytes
                if plaintext.startswith(b'%PDF'):
                    print(f"  [{offset:2d}] ✓✓✓ FOUND VALID PDF! ✓✓✓")
                    print(f"       IV: {test_iv.hex()}")
                    print(f"       PDF header: {plaintext[:32]}")
                    best_plaintext = plaintext
                    best_offset = offset
                    break
                elif offset < 5:  # Only show first few failures
                    print(f"  [{offset:2d}] Decrypted but not PDF: {plaintext[:16].hex()}")

            except Exception as e:
                if offset < 5:
                    print(f"  [{offset:2d}] Error: {str(e)[:50]}")
                continue

        if best_plaintext is None:
            print("\n⚠️  WARNING: Could not find valid PDF at any offset!")
            print("   Saving encrypted blob for manual analysis...")
            debug_path = f"downloads/encrypted_debug_att{i}.bin"
            with open(debug_path, 'wb') as f:
                f.write(att['content'])
            print(f"   → {debug_path}")

            # Also save the AES key for debugging
            key_path = f"downloads/aes_key_att{i}.hex"
            with open(key_path, 'w') as f:
                f.write(aes_key.hex())
            print(f"   → {key_path}")
            continue

        # Get filename from XML description
        desc = root.find('.//{http://edt.health.ontario.ca/}description')
        name = desc.text.strip() if desc is not None and desc.text else f"resource_{i}.pdf"
        if not '.' in name:
            name += '.pdf'

        path = f"downloads/{name}"
        with open(path, 'wb') as f:
            f.write(best_plaintext)

        print(f"\n✓✓✓ SUCCESS! ✓✓✓")
        print(f"  File: {path}")
        print(f"  Size: {len(best_plaintext):,} bytes")
        print(f"  Offset: {best_offset} bytes before IV")
        print(f"  Header: {best_plaintext[:40]}")

        saved.append(path)

    print(f"\n{'=' * 60}")
    if saved:
        return f"✓ Decrypted {len(saved)} file(s):\n" + "\n".join(f"  → {os.path.abspath(p)}" for p in saved)
    else:
        return "✗ ERROR: Could not decrypt any files. Check debug output and encrypted_debug_*.bin files."


# USAGE: Replace the decryptResponse function in your script with this version# Main execution
rawxml = loadxmltemplate()
serverStatus, body, raw_bytes = sendrequest(rawxml)
print(f"Server Status: {serverStatus}")
print("-" * 50)

# For download method, use raw bytes for proper multipart handling
if method == 'download':
    decryptedResult = decryptResponse(body, raw_bytes)
else:
    decryptedResult = decryptResponse(body)

print(decryptedResult)


