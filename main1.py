
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
load_dotenv("local.env")

# Initialize with input parameters to this API
method = "info"
# method = "getTypeList"
directory = "MCEDT_DOWNLOAD_SAMPLES"
file_to_process1="CLAIM FILE.txt"
claimfile = f'{directory}/{file_to_process1}'
current_number='8.2'
responseFile = f'results/{current_number}_{directory}_{file_to_process1}'
responseFile=responseFile.replace(".txt",".xml")
responseFile=responseFile.replace(".blob",".xml")
responseFile=responseFile.replace(file_to_process1.split(".")[1],".xml")
resourceID = "90242"
resourceID2 = "90248"
resourceID3 = "95653"
resourceID4 = "95654"
resourceID5 = "95655"
resourceID6 = "95656"
resourceID7 = "95657"

file_to_process2="2_OBECE.TXT"
file_to_process3="3_OBECE.TXT"
file_to_process4="4_OBECE.TXT"
file_to_process5="5_OBECE.TXT"
file_to_process6="6_OBECE.TXT"
claimfile2 = f'{directory}/{file_to_process2}'
claimfile3 = f'{directory}/{file_to_process3}'
claimfile4 = f'{directory}/{file_to_process4}'
claimfile5 = f'{directory}/{file_to_process5}'
claimfile6 = f'{directory}/{file_to_process6}'

# For list method
resourceType = 'CL'  # OPTIONAL can leave empty
# CL, BE, ER, ES, RA, RS, PSP, GCM
# ref getTypeList method's server response
resourceStatus = 'UPLOADED'
# UPLOADED, SUBMITTED, WIP, DOWNLOADABLE, APPROVED, DENIED
# ref pg25 moh-ohip-techspec-mcedt-ebs-v4-5-en-2023-10-18.pdf
resourcePage = 1  # OPTIONAL can leave empty

# Scroll down to replace conformance testing key further down the code base
MOH_ID = os.getenv('MOH_ID')
username = os.getenv('username')
password = os.getenv('password')
conformance_key=os.getenv('conformance_key')
KEY=os.getenv('KEY')
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

    # turns out after all that work for me to get the digest values right, or so I thought.
    # it doesn't matter at all. if changing the digestvalue above to a wrong value, server will still respond with correct response.
    # so server is only checking the format and structure of your request, but not the actual digest values. as long as you have the right tags and the right SOAP and WSS structure, this web service doesn't actually check content is tampered with.

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

def sendrequest(xmlPayload: str) -> Tuple[int, str]:
    url = 'https://ws.conf.ebs.health.gov.on.ca:1443/EDTService/EDTService'
    # this is the same as https://204.41.14.200:1443/EDTService/EDTService in WSDL
    # better to use the domain name instead of IP, matches with the SSL certificate.

    global method, claimfile
    if method in ['upload', 'update']:
        with open(claimfile, 'rb') as f:
            fileContent = f.read().decode('utf-8')  # Assuming text file, decode if needed

        # Boundary for the multipart message
        # Generate a random boundary string, to avoid collision with msg content
        boundary = '----=Boundary_' + hashlib.md5(str(random.random()).encode()).hexdigest()

        # Construct the MIME message
        mimeMessage = f"--{boundary}\r\n"
        mimeMessage += "Content-Type: application/xop+xml; charset=UTF-8; type=\"text/xml\"\r\n"
        mimeMessage += "Content-Transfer-Encoding: 8bit\r\n"
        mimeMessage += "Content-ID: <rootpart@soapui.org>\r\n\r\n"
        # there must be an extra line break between header and soap envelope
        mimeMessage += f"{xmlPayload}\r\n"
        mimeMessage += f"--{boundary}\r\n"
        # mimeMessage += "Content-Type: application/octet-stream;       name=$contentId\r\n"
        # mimeMessage += "Content-Transfer-Encoding: binary\r\n"
        mimeMessage += "Content-Type: text/plain; charset=us-ascii\r\n"
        mimeMessage += "Content-Transfer-Encoding: 7bit\r\n"
        # contentId is just the file name e.g. HL8012345.001
        mimeMessage += f"Content-ID: <{claimfile}>\r\n"
        mimeMessage += f"Content-Disposition: attachment;   name=\"{claimfile}\"\r\n\r\n"
        mimeMessage += f"{fileContent}\r\n"
        mimeMessage += f"--{boundary}--"

        headers = {
            "Content-Type": f"multipart/related; type=\"application/xop+xml\"; start=\"<rootpart@soapui.org>\"; start-info=\"text/xml\"; boundary=\"{boundary}\"",
            'MIME-Version': '1.0',
            # 'User-Agent': 'Apache-HttpClient/4.5.5 (Java/16.0.2)',
            # 'Connection': 'Keep-Alive',
            # 'Accept-Encoding': 'gzip, deflate',
            # 'Authorization': 'Basic Y29uZnN1KzQyN0BnbWFpbC5jb206UGFzc3dvcmQyIQ==',
            # 'SOAPAction': '""',
        }

        xmlPayload = mimeMessage
    else:
        headers = {
            'Content-Type': 'text/xml;charset=UTF-8',
            # 'Connection': 'Keep-Alive',
        }

    # Send request
    response = requests.post(url, data=xmlPayload.encode('utf-8'), headers=headers, verify='cacert.pem')

    # Write to 1_MCEDT_Upload_Files_Claim_File.xml
    with open(responseFile, 'w') as httpLogFile:
        # Request
        httpLogFile.write(str(response.request.headers) + '\n\n')
        httpLogFile.write(xmlPayload + '\n\n\n')
        # Response
        httpLogFile.write(str(response.headers) + '\n\n')
        httpLogFile.write(response.text + '\n')

    return response.status_code, response.text

def decryptResponse(responseXML: str) -> str:
    # input encrypted response XML, output decrypted result XML
    # Parse XML
    root = ET.fromstring(responseXML)

    # Find CipherValue elements
    cipher_values = root.findall('.//{http://www.w3.org/2001/04/xmlenc#}CipherValue')

    if len(cipher_values) >= 2:
        # Decrypt AES key with RSA
        decrypted_aes_key = private_key.decrypt(
            base64.b64decode(cipher_values[0].text),
            padding.PKCS1v15()
        )

        # Extract IV (first 16 bytes of the second CipherValue)
        encrypted_data = base64.b64decode(cipher_values[1].text)
        iv = encrypted_data[:16]
        encrypted_content = encrypted_data[16:]

        # Decrypt data with AES-CBC
        cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_content) + decryptor.finalize()

        # Remove PKCS5 padding (assuming)
        padding_length = decrypted_data[-1]
        decrypted_data = decrypted_data[:-padding_length]

        # The PHP code does substr($decryptedData, 16); perhaps there's a 16-byte header
        responseXML = decrypted_data[16:].decode('utf-8')
        return responseXML
    else:
        # error handling
        print("Ciphervalue not found. Nothing to decrypt here. Unexpected server response.")
        print("Raw response received from server:\n\n")
        return responseXML

# Main execution
rawxml = loadxmltemplate()
serverStatus, body = sendrequest(rawxml)

decryptedResult = decryptResponse(body)
print(decryptedResult)  # output plain text response to console
