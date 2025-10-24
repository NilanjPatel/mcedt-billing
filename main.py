from datetime import datetime, timedelta, timezone
import base64, hashlib, re, uuid, requests, binascii
import xml.etree.ElementTree as ET
from lxml import etree
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Assuming you have already loaded the private key
# and imported any necessary modules

# Set values for variables
# healthcard = '1357557162'
# versionCode = ''
# serviceCode = 'P108'

# MOH_ID = '037262'
username = 'contact@mapleclinic.info'
password = 'Kingston#4560'

# KEY = 'MIICgDCCAemgAwIBAgIEDQJ8JzANBgkqhkiG9w0BAQsFADBzMQswCQYDVQQGEwJDQTEQMA4GA1UECBMHT250YXJpbzEdMBsGA1UEBxMUU2NhcmJvcm91Z2gsIE9udGFyaW8xEjAQBgNVBAoTCU5ELUhlYWx0aDELMAkGA1UECxMCTkQxEjAQBgNVBAMTCU5EIEhlYWx0aDAeFw0yNDA1MjQxOTE5NDVaFw00NDA1MTkxOTE5NDVaMHMxCzAJBgNVBAYTAkNBMRAwDgYDVQQIEwdPbnRhcmlvMR0wGwYDVQQHExRTY2FyYm9yb3VnaCwgT250YXJpbzESMBAGA1UEChMJTkQtSGVhbHRoMQswCQYDVQQLEwJORDESMBAGA1UEAxMJTkQgSGVhbHRoMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCTGDacVz4qTgk9iuxfUK5agahP4wxFs2Ci5kIm8H2FXZauZwwlfytUNlFIzqcxi/X2wVto9DSEirOgIxr6CDpja9UyM1UUQtqUxQFemBDe17euHlHzGG3MlkKOS9DOiRDWsRSllV9e+BMH1jn7F88nI5Rn+7v1YYciuxzNrcs2XQIDAQABoyEwHzAdBgNVHQ4EFgQUN/YGZLtHY0FFtkZn7nsPlelArE8wDQYJKoZIhvcNAQELBQADgYEAMhXGRb1Qo7EeorVL+o9K1Qlv+uGVgEp1qbrl49r2HofAsrLr+dqsmY60hCAKcFlCMqL8oyK+OMWEmQVrlF2QWmk1gC8J6loT9skd1+FOHTVn3rzrKOA8iog1nx1K/xbkYfo9jzVbsjzULsjQr3uiB37Hartg3+PfkolgtY0tOEU='
KEY = 'MIIDbzCCAlegAwIBAgIEShu/pDANBgkqhkiG9w0BAQsFADBoMQswCQYDVQQGEwJDQTEQMA4GA1UECBMHT250YXJpbzEUMBIGA1UEBxMLU2NhcmJvcm91Z2gxEjAQBgNVBAoTCU5EIEhlYWx0aDEMMAoGA1UECxMDMjA1MQ8wDQYDVQQDEwZOaWxhbmowHhcNMjUwMTAyMTgxNDUyWhcNNDQxMjI4MTgxNDUyWjBoMQswCQYDVQQGEwJDQTEQMA4GA1UECBMHT250YXJpbzEUMBIGA1UEBxMLU2NhcmJvcm91Z2gxEjAQBgNVBAoTCU5EIEhlYWx0aDEMMAoGA1UECxMDMjA1MQ8wDQYDVQQDEwZOaWxhbmowggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCARHBqmKpawwMs64qAyEsTZaT55MdO8SgmCizqNMlf72DQNm9A+Fd7yqvvF8u9HBg9MQI8P6nKgb8a1RHHEm8pHZ38wKvxRNe4B7Qk3c0PWqZ9JzZv27rVpZbclGF7hgntAKcCQXqUOFM0BWXt9t1RdjvQsMCG1Pd5BAR8Qj9k/WE0OvM4kWH7At6ov+QXiduvrXnHZ+DHiy/igX0IpY3yO7sKgMPYFLW5AgB56CzYLfENEqUK//qcPkhjKxeK9sfTXeg6GNvPcdI6k9sBcCzy7Yj5CX0y2W16GXrfVuKPssAMJIqEhWGtUg9p7JlH+OM/IP9TK+X5lEZ4h+y0jXIrAgMBAAGjITAfMB0GA1UdDgQWBBQxD3oJ9/go+eX2VCYfY29y4TqrBzANBgkqhkiG9w0BAQsFAAOCAQEAULEfBFs6vjUFwEYoe+sNNAmWnmBXDaKJJYaOm0UqS1yjjwvLlaz1tyd4/lylWHtYUDbr6am5ZkYeMkZ+a1d1dcgHVM2fDfIT672PBdOX7I+tDt+arrc7fguTXZjSvXV2kNMJH/ZACVPyjioIDRN+5TDt2gTTWWAi3NZgc2IEsDysXi7ErdID5agFxO5mXGwagZuOfjYcO1cwim/317GSheysqXXDOUhqd+/6xUVYMpaY0a9fLJvNf6LLy0I2f8CcEtq5MpX+G8+4xzyKDd+FaagQ3uDBHqMNeJiG55M+9ZP6/xT1PvaPMstFyvZA9qUfC5zLDcotOY2xZC0CnzLmRw=='

def loadbody(healthcard, versionCode, serviceCode):
    rawbody = f"""<soapenv:Body wsu:Id="id-5">
    <hcv:validate>
       <requests>
          <!--1 to 100 repetitions:-->
          <hcvRequest>
             <healthNumber>{healthcard}</healthNumber>
             <versionCode>{versionCode}</versionCode>
             <!--0 to 5 repetitions:-->
             <feeServiceCodes>{serviceCode}</feeServiceCodes>
          </hcvRequest>
       </requests>

       <!--Optional:-->
       <locale>en</locale>
    </hcv:validate>
 </soapenv:Body>"""

    return rawbody


def loadtimestamp():
    # Create the first timestamp
    first_timestamp = datetime.now(timezone.utc)
    first_timestamp_str = first_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    # Create the second timestamp (10 minutes after the first one)
    second_timestamp = first_timestamp + timedelta(minutes=10)
    second_timestamp_str = second_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    timestamp = f"""<wsu:Timestamp wsu:Id="id-3"><wsu:Created>{first_timestamp_str}</wsu:Created><wsu:Expires>{second_timestamp_str}</wsu:Expires></wsu:Timestamp>"""
    return timestamp


def loadIDP(MOH_ID):
    IDP = f'''
      <idp:IDP wsu:Id="id-2">
         <ServiceUserMUID>{MOH_ID}</ServiceUserMUID>
      </idp:IDP>
    '''
    return IDP


def loadEBS():
    # Generate UUID
    uuid_str = str(uuid.UUID(bytes=uuid.uuid4().bytes))
    # Hardcoded conformance key
    conformance_key ="eab943d7-43dd-4fac-9e11-fce1efd200a1" #"ec93aa8e-5347-43c3-955a-eec0e1a61bf7"
    # XML template with formatted UUID
    EBS = f"""<ebs:EBS wsu:Id="id-1">
         <SoftwareConformanceKey>{conformance_key}</SoftwareConformanceKey>
         <AuditId>{uuid_str}</AuditId>
      </ebs:EBS>"""
    return EBS


def loadUsernameToken(username, password):
    username_token = f"""<wsse:UsernameToken wsu:Id="id-4"><wsse:Username>{username}</wsse:Username><wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">{password}</wsse:Password></wsse:UsernameToken>"""
    return username_token


def digestxml(xml):
    # Parse the XML content
    dom = etree.fromstring(xml)

    # Canonicalize the document using C14N version 1.0
    canonicalized_xml = etree.tostring(dom, method="c14n")

    # Calculate SHA-256 hash and encode it in Base64
    digest_value = base64.b64encode(hashlib.sha256(canonicalized_xml).digest()).decode('utf-8')

    return digest_value


class Digester:
    def __init__(self, private_key_file):
        with open(private_key_file, "rb") as key_file:
            pkcs12_data = key_file.read()
            self.private_key = pkcs12.load_key_and_certificates(pkcs12_data, password, default_backend())

    def digestxml(self, xml):
        xml_digest = hashlib.sha1(etree.tostring(xml)).digest()
        return base64.b64encode(xml_digest).decode()

    def signxml(self, xml):
        signed_info_digest = self.digestxml(xml)
        signature = self.private_key.sign(
            signed_info_digest,
            hashes.SHA1(),
            padding.PKCS1v15()
        )
        return base64.b64encode(signature).decode()


def loadxmltemplate( healthcard, version_code, service_code,MOH_ID):
    private_key_pem = privateKey()
    private_key = private_key_pem.decode('utf-8')
    root_namespaces = """
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            xmlns:ebs="http://ebs.health.ontario.ca/"
            xmlns:hcv="http://hcv.health.ontario.ca/"
            xmlns:idp="http://idp.ebs.health.ontario.ca/"
            xmlns:msa="http://msa.ebs.health.ontario.ca/"
            xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
            xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
            """
    # Must declare variables as g   lobal to access them outside the function scope
    body = loadbody(healthcard, version_code, service_code)

    # Insert namespace definition from all parent nodes into the XML part to be canonicalized
    modifiedbody = re.sub(r'<soapenv:Body', r'<soapenv:Body' + root_namespaces, body)

    # Digest XML
    digestvalue5 = digestxml(modifiedbody)

    #sscontactcenter.moh@ontario.ca

    timestamp = loadtimestamp()
    modtimestamp = re.sub(r'<wsu:Timestamp', r'<wsu:Timestamp' + root_namespaces, timestamp)
    digestvalue3 = digestxml(modtimestamp)

    EBS = loadEBS()
    modifiedEBS = re.sub(r'<ebs:EBS', r'<ebs:EBS' + root_namespaces, EBS)
    digestvalue1 = digestxml(modifiedEBS)

    IDP = loadIDP(MOH_ID)
    modifiedIDP = re.sub(r'<idp:IDP', r'<idp:IDP' + root_namespaces, IDP)
    digestvalue2 = digestxml(modifiedIDP)

    global username, password
    usernameToken = loadUsernameToken(username, password)
    modusernameToken = re.sub(r'<wsse:UsernameToken', r'<wsse:UsernameToken' + root_namespaces, usernameToken)
    digestvalue4 = digestxml(modusernameToken)

    # Define the signed info XML string
    signed_info = f"""
    <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
        <ec:InclusiveNamespaces PrefixList="ebs hcv idp msa soapenv wsu" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    </ds:CanonicalizationMethod>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <ds:Reference URI="#id-5">
        <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
            <ec:InclusiveNamespaces PrefixList="ebs hcv idp msa" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transform>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>{digestvalue5}</ds:DigestValue>
    </ds:Reference>
    <ds:Reference URI="#id-1">
        <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
            <ec:InclusiveNamespaces PrefixList="hcv idp msa soapenv" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transform>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>{digestvalue1}</ds:DigestValue>
    </ds:Reference>
    <ds:Reference URI="#id-2">
        <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
            <ec:InclusiveNamespaces PrefixList="ebs hcv msa soapenv" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transform>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>{digestvalue2}</ds:DigestValue>
    </ds:Reference>
    <ds:Reference URI="#id-3">
        <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
            <ec:InclusiveNamespaces PrefixList="wsse ebs hcv idp msa soapenv" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transform>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>{digestvalue3}</ds:DigestValue>
    </ds:Reference>
    <ds:Reference URI="#id-4">
        <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
            <ec:InclusiveNamespaces PrefixList="ebs hcv idp msa soapenv" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transform>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>{digestvalue4}</ds:DigestValue>
    </ds:Reference>
    </ds:SignedInfo>
    """

    # Insert namespace from all parent nodes before canonicalization
    mod_signed_info = re.sub(r'<ds:SignedInfo', r'<ds:SignedInfo' + root_namespaces, signed_info)

    # Create a DOMDocument to prep for C14N canonicalization
    dom = etree.fromstring(mod_signed_info)
    # Canonicalize the document using C14N version 1.0
    canonicalized_xml = etree.tostring(dom, method="c14n").decode("utf-8")

    # Calculate SHA-1 hash of signedInfo
    digest = hashlib.sha1(canonicalized_xml.encode('utf-8')).digest()
    # Load private key

    # with open('testStore.p12', 'rb') as pkcs12_file:
    #     key_id = pkcs12_file.read()


    private_key = load_pem_private_key(private_key_pem, password=None)
    # private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key)

    # return signature is in binary string;
    signature_bin_str = private_key.sign(
        digest,
        padding.PKCS1v15(),
        hashes.SHA1()
    )
    # signature_bin_str = crypto.sign(private_key, digest, 'sha1')


    # Convert binary string to hexidecimal
    signature_hex = binascii.hexlify(signature_bin_str)
    # Convert binary to string;
    signature = signature_hex.decode("utf-8")
    # signature = base64.b64encode(signature_bin_str).decode('utf-8')

    # Define the raw XML string
    raw_xml = f"""
    <soapenv:Envelope xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ebs="http://ebs.health.ontario.ca/" xmlns:hcv="http://hcv.health.ontario.ca/" xmlns:idp="http://idp.ebs.health.ontario.ca/" xmlns:msa="http://msa.ebs.health.ontario.ca/" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    <soapenv:Header>
    <wsse:Security soapenv:mustUnderstand="1">
    <wsse:BinarySecurityToken
    EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
    ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
    wsu:Id="X509-NEWUNIQUEID4379885785">{KEY}</wsse:BinarySecurityToken>
    {usernameToken}{timestamp}<ds:Signature Id="SIG-28C9CE93E0A1F26FD917013530402876">{signed_info}<ds:SignatureValue>{signature}</ds:SignatureValue>
    <ds:KeyInfo Id="KI-28C9CE93E0A1F26FD917013530402454">
    <wsse:SecurityTokenReference wsu:Id="STR-28C9CE93E0A1F26FD917013530402475">
    <wsse:Reference URI="#X509-NEWUNIQUEID4379885785" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
    </wsse:SecurityTokenReference>
    </ds:KeyInfo>
    </ds:Signature>
    </wsse:Security>
    {EBS}
    {IDP}
    </soapenv:Header>
    {body}
    </soapenv:Envelope>
    """
    response = sendrequest(raw_xml)
    if response[0] < 300:
        decrypted_result = decryptResponse(response[1], private_key_pem)  # You need to define this function
        return buildresponseObj(decrypted_result)  # You need to define this function
    else:
        return errorhandling(response[0], response[1])  # You need to define this function

    # You can use the raw_xml string as needed in your application


def sendrequest(xmlPayload):
    # url = 'https://ws.conf.ebs.health.gov.on.ca:1444/HCVService/HCValidationService'
    url = 'https://ws.ebs.health.gov.on.ca:1444/HCVService/HCValidationService'

    headers = {
        'Content-Type': 'text/xml;charset=UTF-8',
        'Connection': 'Keep-Alive',
    }

    # Visit the endpoint URL in Chrome, download certificates from Chrome,
    # including Certificate Authority G2, intermediate L1K, and server certificate.
    # Open all three in notepad and paste together, save as cacert.pem

    # Set up SSL verification with custom certificate
    response = requests.post(url, data=xmlPayload, headers=headers, verify='cacert1.pem')

    # Check for HTTP errors
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        pass
        # err> #EHCAU0029 if this error handle in future as billing number is invalid

    server_status = response.status_code

    # Write request headers and payload to a log file
    with open('1_MCEDT_Upload_Files_Claim_File.xml', 'a') as httpLogFile:
        httpLogFile.write(str(response.request.headers) + '\n\n\n')
        httpLogFile.write(xmlPayload + '\n\n\n')

    # Extract response body
    body = response.text

    # Append response to log file
    with open('1_MCEDT_Upload_Files_Claim_File.xml', 'a') as httpLogFile:
        httpLogFile.write(str(response.headers) + '\n\n\n')
        httpLogFile.write(body)

    return [server_status, body]


def decryptResponse(responseXML, private_key):
    xml = ET.fromstring(responseXML)
    namespaces = {'xenc': 'http://www.w3.org/2001/04/xmlenc#'}

    ET.register_namespace('xenc', 'http://www.w3.org/2001/04/xmlenc#')

    cipherValues = xml.findall('.//{http://www.w3.org/2001/04/xmlenc#}CipherValue')

    if cipherValues:
        # Decrypt using private key
        # private_key_obj = RSA.import_key(private_key)
        cipher_rsa = PKCS1_v1_5.new(RSA.import_key(private_key))
        decrypted_aes_key = cipher_rsa.decrypt(base64.b64decode(cipherValues[0].text), None)

        # decrypted_aes_key = private_key_obj.decrypt(base64.b64decode(cipherValues[0].text), padding=False)

        # Extract the initialization vector required for AES decryption
        iv = base64.b64decode(cipherValues[1].text)[:16]

        # Decrypt using AES with CBC mode, PKCS5 padding, and the extracted IV
        decrypted_data = AES.new(decrypted_aes_key, AES.MODE_CBC, iv).decrypt(base64.b64decode(cipherValues[1].text))[
                         16:]

        return decrypted_data.decode()
    else:
        return None


def errorhandling(server_status, response):
    responseObj = {}
    # Set error flag to true

    responseObj['error'] = True
    responseObj['errorMsg'] = f"Server Error: {server_status}. "

    # Parse the response XML
    root = ET.fromstring(response)

    # Register namespaces
    namespaces = {'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/',
                  'ns1': 'http://ebs.health.ontario.ca/'}

    # Use XPath to extract <code> and <message> elements
    error_codes = root.findall('.//soapenv:Fault/code', namespaces)
    error_messages = root.findall('.//ns1:EBSFault/message', namespaces)

    # Extract error codes and messages
    error_codes = [code.text for code in error_codes]
    error_messages = [msg.text for msg in error_messages]

    # Concatenate values
    error_msg = f"Error: {', '.join(error_codes)} - {', '.join(error_messages)}"
    responseObj['errorMsg'] += error_msg


class XMLParser:
    def __init__(self, xml_string):
        self.xml_string = xml_string
        self.root = ET.fromstring(xml_string)
        self.remove_namespace_declarations()
        self.result = None

    def remove_namespace_declarations(self):
        for elem in self.root.iter():
            if elem.tag.startswith('{') and elem.tag.endswith('}'):
                del elem.tag

    def xml_to_dict(self, elem):
        d = {}
        for child in elem:
            if child.tag not in d:
                d[child.tag] = []
            d[child.tag].append(self.xml_to_dict(child))
        if len(d) == 1:
            return d[list(d.keys())[0]][0]
        return d

    def extract_values(self, elem, tag_name):
        values = []
        for child in elem:
            if child.tag == tag_name:
                values.append(child.text)
        return values

    def get_root_toresult(self):
        self.result = self.xml_to_dict(self.root.find('results'))

    def parse(self, name):
        if self.result is None:
            self.get_root_toresult()
        try:
            self.result[name] = self.extract_values(self.root.find('results'), name)[0]
        except IndexError:
            pass

    def get_result(self):
        return self.result


def removeLastdegit(string):
    control_characters_names = [
        '\x00',
        '\x01',
        '\x02',
        '\x03',
        '\x04',
        '\x05',
        '\x06',
        '\x07',
        '\x08',
        '\x09',
        '\x0A',
        '\x0B',
        '\x0C',
        '\x0D',
        '\x0E',
        '\x0F',
        '\x10',
        '\x11',
        '\x12',
        '\x13',
        '\x14',
        '\x15',
        '\x16',
        '\x17',
        '\x18',
        '\x19',
        '\x1A',
        '\x1B',
        '\x1C',
        '\x1D',
        '\x1E',
        '\x1F',
        '\x7F'
    ]
    for charc in control_characters_names:
        string = string.split(charc)[0]
    return string

def buildresponseObj(decryptedResult):
    # decryptedResult = decryptedResult.split('\x08')[0]
    # decryptedResult = decryptedResult.split('')[0]
    # decryptedResult = decryptedResult.split('')[0]
    # decryptedResult = decryptedResult.split('')[0]

    result = removeLastdegit(decryptedResult)
    # with open("File.xml", 'w') as f:
    #     f.write(decryptedResult)
    #     f.close()
    response_data = XMLParser(result)
    needed_results = ['feeServiceDetails', 'auditUID', 'dateOfBirth', 'expiryDate', 'firstName', 'gender',
                      'healthNumber',
                      'lastName', 'responseAction', 'responseCode', 'responseDescription', 'responseID', 'secondName',
                      'versionCode', 'feeServiceCode', 'feeServiceDate', 'feeServiceResponseCode',
                      'feeServiceResponseDescription']

    for name in needed_results:
        response_data.parse(name)

    return response_data.get_result()


def privateKey():
    # Load the PKCS#12 file
    private_key_pem = None
    with open('keyStore.p12', 'rb') as pkcs12_file:
        pkcs12_data = pkcs12_file.read()

    # Parse the PKCS#12 file to extract private key and certificate
    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
        pkcs12_data,
        b'gd131964',  # Password must be bytes
        default_backend()
    )
    if private_key:
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        return None #("No private key found")
    return private_key_pem




# loadxmltemplate(healthcard=1614271425, version_code='LH',service_code='A110', MOH_ID='034288')