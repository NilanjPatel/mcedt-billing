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
directory = "MCEDT_DOWNLOAD_SAMPLES"
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


def parse_multipart_response(response_content: bytes, boundary: str = None) -> list:
    """Parse MIME multipart response and extract parts"""

    # If boundary not provided, try to extract from content
    if boundary is None:
        # Look for boundary in the content - handling the case where first line includes headers
        if response_content.startswith(b'--MIMEBoundary'):
            # Extract just the boundary part from the first line
            first_line = response_content.split(b'\r\n')[0]
            boundary = first_line.decode('utf-8', errors='ignore')
        else:
            lines = response_content.split(b'\r\n')
            for line in lines:
                if line.startswith(b'--MIMEBoundary'):
                    boundary = line.decode('utf-8', errors='ignore')
                    break

    if not boundary:
        print("Could not find boundary in response")
        return []

    # Clean the boundary - remove any trailing content after the boundary ID
    if '\n' in boundary:
        boundary = boundary.split('\n')[0]
    if '\r' in boundary:
        boundary = boundary.split('\r')[0]

    print(f"Using cleaned boundary: {boundary}")

    # Split by boundary
    parts_raw = response_content.split(boundary.encode())
    parts = []

    for i, part_raw in enumerate(parts_raw):
        if not part_raw or part_raw == b'--' or part_raw == b'--\r\n' or len(part_raw) < 10:
            continue

        # Remove leading \r\n if present
        if part_raw.startswith(b'\r\n'):
            part_raw = part_raw[2:]
        elif part_raw.startswith(b'\n'):
            part_raw = part_raw[1:]

        # Split headers from content
        if b'\r\n\r\n' in part_raw:
            headers_raw, content = part_raw.split(b'\r\n\r\n', 1)
        elif b'\n\n' in part_raw:
            headers_raw, content = part_raw.split(b'\n\n', 1)
        else:
            print(f"Part {i}: No header/content separator found, skipping")
            continue

        # Parse headers
        headers = {}
        header_lines = headers_raw.split(b'\r\n') if b'\r\n' in headers_raw else headers_raw.split(b'\n')
        for header_line in header_lines:
            if b':' in header_line:
                key, value = header_line.decode('utf-8', errors='ignore').split(':', 1)
                headers[key.strip()] = value.strip()

        # Determine content type
        content_type = headers.get('Content-Type', '')
        content_id = headers.get('Content-ID', '').strip('<>')
        transfer_encoding = headers.get('Content-Transfer-Encoding', '')

        # Clean up content (remove trailing boundary markers)
        if content.endswith(b'\r\n--'):
            content = content[:-4]
        elif content.endswith(b'\r\n'):
            content = content[:-2]
        elif content.endswith(b'\n--'):
            content = content[:-3]
        elif content.endswith(b'\n'):
            content = content[:-1]

        part_data = {
            'content_type': content_type,
            'content_id': content_id,
            'content_transfer_encoding': transfer_encoding,
            'headers': headers,
            'content': content
        }

        parts.append(part_data)

        print(
            f"Found part {i + 1}: Type={content_type[:50] if content_type else 'Unknown'}, ID={content_id[:50] if content_id else 'None'}, Size={len(content)} bytes")

    return parts


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
    """Decrypt response - handles both simple XML and multipart responses"""

    # Check if this is a multipart response
    if response_bytes and b'--MIMEBoundary' in response_bytes:
        print("Detected multipart MIME response")

        # Find the boundary line
        boundary = None
        for line in response_bytes.split(b'\r\n'):
            if line.startswith(b'--MIMEBoundary'):
                boundary = line.decode('utf-8', errors='ignore')
                break

        if not boundary:
            print("Could not find MIME boundary")
            return responseXML

        print(f"Using boundary: {boundary[:50]}...")

        # Parse multipart
        parts = parse_multipart_response(response_bytes, boundary)

        if not parts:
            print("No parts found in multipart message")
            return responseXML

        # First part should be XML, other parts are attachments
        xml_part = None
        attachments = []

        for i, part in enumerate(parts):
            print(f"Processing part {i + 1}: {part['content_type'][:50] if part['content_type'] else 'Unknown type'}")

            # Check if this is the XML part
            if 'xml' in part['content_type'].lower() or i == 0:  # First part is usually XML
                xml_part = part['content']
                if isinstance(xml_part, bytes):
                    xml_part = xml_part.decode('utf-8', errors='ignore')
                print(f"Found XML part, length: {len(xml_part)}")
            elif part['content_type'] == 'application/octet-stream' or 'octet-stream' in part['content_type']:
                attachments.append(part)
                print(f"Found attachment, size: {len(part['content'])} bytes")

        if xml_part:
            try:
                # Parse XML to get encryption keys
                root = ET.fromstring(xml_part)

                # Find all EncryptedKey elements and extract their CipherValues
                encrypted_keys = []
                enc_key_elements = root.findall('.//{http://www.w3.org/2001/04/xmlenc#}EncryptedKey')

                print(f"Found {len(enc_key_elements)} EncryptedKey elements")

                for enc_key in enc_key_elements:
                    cipher_value = enc_key.find('.//{http://www.w3.org/2001/04/xmlenc#}CipherValue')
                    if cipher_value is not None and cipher_value.text:
                        encrypted_keys.append(cipher_value.text.strip())
                        print(f"Added encryption key {len(encrypted_keys)}: {cipher_value.text[:50]}...")

                # Process attachments
                decrypted_files = []
                for i, attachment in enumerate(attachments):
                    try:
                        # Get the encrypted content
                        encrypted_content = attachment['content']

                        print(f"Processing attachment {i + 1}, size: {len(encrypted_content)} bytes")

                        # Look for corresponding EncryptedData element in XML to get metadata
                        attachment_cid = attachment['content_id']
                        mime_type = None

                        # Check XML for MIME type information
                        for enc_data in encrypted_data_elements:
                            cipher_ref = enc_data.find('.//{http://www.w3.org/2001/04/xmlenc#}CipherReference')
                            if cipher_ref is not None:
                                uri = cipher_ref.get('URI', '')
                                if attachment_cid in uri:
                                    # Found matching encrypted data element
                                    mime_type = enc_data.get('MimeType', '')
                                    print(f"Found MIME type in XML: {mime_type}")
                                    break

                        # Try to decrypt the attachment with available keys
                        for j, key in enumerate(encrypted_keys):
                            try:
                                # Decrypt the AES key using RSA
                                encrypted_key = base64.b64decode(key)
                                decrypted_aes_key = private_key.decrypt(
                                    encrypted_key,
                                    padding.PKCS1v15()
                                )

                                print(f"Successfully decrypted AES key with key {j + 1}")

                                # Extract IV (first 16 bytes) and encrypted content
                                iv = encrypted_content[:16]
                                encrypted_data = encrypted_content[16:]

                                # Decrypt with AES-CBC
                                cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(iv))
                                decryptor = cipher.decryptor()
                                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

                                # Remove PKCS7 padding
                                if len(decrypted_data) > 0:
                                    padding_length = decrypted_data[-1]
                                    if padding_length <= len(decrypted_data) and padding_length <= 16:
                                        decrypted_data = decrypted_data[:-padding_length]

                                # Detect file type
                                file_extension = detect_file_type(decrypted_data)

                                # Override with MIME type if available
                                if mime_type:
                                    mime_to_ext = {
                                        'application/pdf': '.pdf',
                                        'application/octet-stream': file_extension,  # Use detected
                                        'text/plain': '.txt',
                                        'text/html': '.html',
                                        'text/xml': '.xml',
                                        'application/xml': '.xml',
                                        'application/msword': '.doc',
                                        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
                                        'application/vnd.ms-excel': '.xls',
                                        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
                                    }
                                    file_extension = mime_to_ext.get(mime_type, file_extension)

                                # Save decrypted file with proper extension
                                output_filename = f'downloaded_file_{i + 1}_{resourceID}{file_extension}'
                                with open(output_filename, 'wb') as f:
                                    f.write(decrypted_data)

                                print(f"Decrypted file saved as: {output_filename}")
                                print(f"File size: {len(decrypted_data)} bytes")
                                print(f"File type detected: {file_extension}")

                                # Show preview based on file type
                                if file_extension in ['.txt', '.xml', '.html', '.hl7']:
                                    preview = decrypted_data[:200].decode('utf-8', errors='ignore')
                                    print(f"Preview: {preview}...")
                                elif file_extension == '.pdf':
                                    print("File is a PDF document")
                                else:
                                    print(f"Binary file type: {file_extension}")

                                decrypted_files.append(output_filename)
                                break  # Successfully decrypted with this key

                            except Exception as e:
                                if j == len(encrypted_keys) - 1:  # Last key
                                    print(f"Could not decrypt attachment {i + 1} with any key: {str(e)}")
                                continue

                    except Exception as e:
                        print(f"Error processing attachment {i + 1}: {str(e)}")

                # Also try to decrypt the XML body if it contains encrypted data
                encrypted_data_elements = root.findall('.//{http://www.w3.org/2001/04/xmlenc#}EncryptedData')

                for enc_data in encrypted_data_elements:
                    # Check if this is referencing an attachment
                    cipher_ref = enc_data.find('.//{http://www.w3.org/2001/04/xmlenc#}CipherReference')
                    if cipher_ref is not None:
                        # This encrypted data references an attachment
                        uri = cipher_ref.get('URI', '')
                        print(f"EncryptedData references attachment: {uri}")
                        continue

                    # This is inline encrypted data
                    cipher_value = enc_data.find('.//{http://www.w3.org/2001/04/xmlenc#}CipherValue')
                    if cipher_value is not None and cipher_value.text and encrypted_keys:
                        try:
                            # Decrypt the body
                            encrypted_body = base64.b64decode(cipher_value.text)

                            # Try first available key
                            decrypted_aes_key = private_key.decrypt(
                                base64.b64decode(encrypted_keys[0]),
                                padding.PKCS1v15()
                            )

                            iv = encrypted_body[:16]
                            encrypted_content = encrypted_body[16:]

                            cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(iv))
                            decryptor = cipher.decryptor()
                            decrypted_data = decryptor.update(encrypted_content) + decryptor.finalize()

                            # Remove padding
                            padding_length = decrypted_data[-1]
                            if padding_length <= len(decrypted_data):
                                decrypted_data = decrypted_data[:-padding_length]

                            # Skip first 16 bytes if needed
                            xml_response = decrypted_data[16:].decode('utf-8', errors='ignore')

                            print(f"Decrypted XML response preview: {xml_response[:500]}...")

                            # Parse the decrypted response to get file details if available
                            try:
                                response_root = ET.fromstring(xml_response)

                                # Look for download details in the response
                                # Common patterns in MCEDT responses
                                for result in response_root.findall('.//{http://edt.health.ontario.ca/}result'):
                                    status = result.find('.//{http://edt.health.ontario.ca/}status')
                                    if status is not None:
                                        print(f"Download status: {status.text}")

                                    description = result.find('.//{http://edt.health.ontario.ca/}description')
                                    if description is not None:
                                        print(f"File description: {description.text}")

                                    file_type = result.find('.//{http://edt.health.ontario.ca/}resourceType')
                                    if file_type is not None:
                                        print(f"Resource type: {file_type.text}")

                            except Exception as e:
                                print(f"Could not parse response XML for additional details: {str(e)}")

                            if decrypted_files:
                                return f"Download complete!\n\nXML Response:\n{xml_response}\n\nDownloaded files saved as:\n" + '\n'.join(
                                    f"- {f}" for f in decrypted_files)
                            else:
                                return xml_response

                        except Exception as e:
                            print(f"Could not decrypt XML body: {str(e)}")

                if decrypted_files:
                    return f"Successfully processed download response. Decrypted files: {', '.join(decrypted_files)}"
                else:
                    return "Download response processed but no files could be decrypted"

            except ET.ParseError as e:
                print(f"Error parsing XML: {str(e)}")
                print(f"XML content: {xml_part[:500]}...")
                return "Error parsing XML response"
        else:
            print("No XML part found in multipart response")
            return "No XML part found in multipart response"

    # Handle simple XML response (non-multipart)
    else:
        print("Processing simple XML response")
        # Original decryption logic for simple XML responses
        try:
            root = ET.fromstring(responseXML)
            cipher_values = root.findall('.//{http://www.w3.org/2001/04/xmlenc#}CipherValue')

            if len(cipher_values) >= 2:
                # Decrypt AES key with RSA
                decrypted_aes_key = private_key.decrypt(
                    base64.b64decode(cipher_values[0].text),
                    padding.PKCS1v15()
                )

                # Extract IV and encrypted content
                encrypted_data = base64.b64decode(cipher_values[1].text)
                iv = encrypted_data[:16]
                encrypted_content = encrypted_data[16:]

                # Decrypt data with AES-CBC
                cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(iv))
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(encrypted_content) + decryptor.finalize()

                # Remove padding
                padding_length = decrypted_data[-1]
                decrypted_data = decrypted_data[:-padding_length]

                # Skip first 16 bytes
                responseXML = decrypted_data[16:].decode('utf-8')
                return responseXML
            else:
                print("No encryption found in response")
                return responseXML
        except Exception as e:
            print(f"Error processing XML: {str(e)}")
            return responseXML


# Main execution
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