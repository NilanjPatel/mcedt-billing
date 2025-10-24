
import base64
import binascii
import datetime
import hashlib
import os
import random
import string
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET
from io import BytesIO
from typing import List, Tuple

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from lxml import etree  # For C14N canonicalization

# Initialize with input parameters to this API
method = "list"
# method = "getTypeList"
claimfile = 'MCEDT_DOWNLOAD_SAMPLES/STALE DATED CLAIM FILE.txt'
resourceID = "83351"

# For list method
resourceType = 'CL'  # OPTIONAL can leave empty
# CL, BE, ER, ES, RA, RS, PSP, GCM
# ref getTypeList method's server response
resourceStatus = 'SUBMITTED'
# UPLOADED, SUBMITTED, WIP, DOWNLOADABLE, APPROVED, DENIED
# ref pg25 moh-ohip-techspec-mcedt-ebs-v4-5-en-2023-10-18.pdf
resourcePage = 1  # OPTIONAL can leave empty

# Replace with your own conformance testing credentials
# Scroll down to replace conformance testing key further down the code base
MOH_ID = '619700'
username = 'confsu+412@gmail.com'
password = 'Password77!!'

# Load the PKCS#12 file
with open('teststore.p12', 'rb') as f:
    pkcs12 = f.read()

# Parse the PKCS#12 file to extract private key and certificate
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

private_key, certificate, _ = load_key_and_certificates(pkcs12, b'changeit')
KEY = "MIICcjCCAdugAwIBAgIII44ODmyZSbYwDQYJKoZIhvcNAQELBQAwajELMAkGA1UEBhMCQ0ExEDAOBgNVBAgTB09udGFyaW8xFDASBgNVBAcTC1NjYXJib3JvdWdoMQswCQYDVQQKEwJORDESMBAGA1UECxMJTkQgSGVhbHRoMRIwEAYDVQQDEwlORCBIZWFsdGgwHhcNMjUxMDI0MTcwNTIxWhcNNDUxMDE5MTcwNTIxWjBqMQswCQYDVQQGEwJDQTEQMA4GA1UECBMHT250YXJpbzEUMBIGA1UEBxMLU2NhcmJvcm91Z2gxCzAJBgNVBAoTAk5EMRIwEAYDVQQLEwlORCBIZWFsdGgxEjAQBgNVBAMTCU5EIEhlYWx0aDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAj4e/WyqYdREUvX2vlKZw9dxxOdKtjfKeqD3xf203SzWPU7KEzcJEgkLSPySzTHxoQf8irviPkBbDR4lEIn3uGHvOMVme3IPWPzBOLuLgvKkU+wGtOLzVmUtM4XvPnYtBLMBtXfb6xnSdp+3FBrn4+cTDMJOHAc6zuUM+hM5jH8MCAwEAAaMhMB8wHQYDVR0OBBYEFNVbLyOE9SSH+E4Ti2bzeuBToiSLMA0GCSqGSIb3DQEBCwUAA4GBACjA4NQYae6yUsW0OxWf+fqeI0r9pt60BOUoDBGEqh292XDQvSUpB1n5zYhbk7xEoKJ6N3tOhfvS7bkWdMEhc59MyC+OmUfcTbVWMURiyJmpDLkts1Y4Q7g8lj2NvwDjkGYYmH2K67c/5SSaGe4yEnthI9UdSQPQ99w2ysU7fTQ8"
# In replit functions can be collapsed. collapsing all functions will help you get a sense of the structure.
# first a number of functions defined to build different parts of the xml request. then all the parts are put together in loadxmltemplate()

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
            <resourceType>CL</resourceType>
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
    # IDP model is used, not MSA model. reference moh-tech-spec-electronic-business-services-en-2023-06-12.pdf page 10
    # The trusted external identity provider is referring to GoSecure at https://www.edt.health.gov.on.ca All doctors in Ontario get a username and password to GoSecure when they get licensed. Thus credentials to logging into GoSecure is considered high trust and a user there has rights to access patient health information.
    IDP = f"""
  <idp:IDP wsu:Id="id-3">
    <ServiceUserMUID>{MOH_ID}</ServiceUserMUID>
  </idp:IDP>
    """
    # per FAQ word document provided by MOH, serviceUserMUID is the same as MOH ID
    return IDP.strip()

def loadEBS() -> str:
    # generate uuid without external library because my server doesn't have composer
    audit_id = str(uuid.uuid4())

    # hardcode conformance key here, as it will be permanent
    # auditId is an arbitrary random unique ID sent with each request to identify each request. To pass ministry of health's conformance testing you must prove you can receive correct responses from the web service and the government team can verify against server log that you indeed sent the correct request identified by the AuditId.
    EBS = f"""
  <ebs:EBS wsu:Id="id-4">
      <SoftwareConformanceKey>0da8cda1-db02-4b8b-9425-f6e42c2548fa</SoftwareConformanceKey>
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
    with open('5_MCEDT_DOWNLOAD_SAMPLES_STALE DATED CLAIM FILE.xml', 'w') as httpLogFile:
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
