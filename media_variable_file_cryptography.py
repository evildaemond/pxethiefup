# Copyright (C) 2022 Christopher Panayi, MWR CyberSec
#
# This file is part of PXEThief (https://github.com/MWR-CyberSec/PXEThief).
# 
# PXEThief is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.
# 
# PXEThief is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along with PXEThief. If not, see <https://www.gnu.org/licenses/>.

from Crypto.Cipher import AES, DES3
from hashlib import *
import math


def read_media_variable_file(filename):
    media_file = open(filename,'rb')
    # Skip the first 24 bytes of the file header
    media_file.seek(24)
    media_data = media_file.read()
    # Skip the last 8 bytes of the file footer
    return media_data[:-8]

def aes_des_key_derivation(password):
    # https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey
    # https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptcreatehash

    # https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey#remarks
    # Diversification is listed inside the documentation:
    key_sha1 = sha1(password).digest()
    
    b0 = b""
    for x in key_sha1:
        b0 += bytes((x ^ 0x36,))

    b1 = b""
    for x in key_sha1:
        b1 += bytes((x ^ 0x5c,))

    # pad remaining bytes with the appropriate value
    b0 += b"\x36"*(64 - len(b0))
    b1 += b"\x5c"*(64 - len(b1))

    b0_sha1 = sha1(b0).digest()
    b1_sha1 = sha1(b1).digest()

    return b0_sha1 + b1_sha1

def aes128_decrypt(data, key, iv = (b"\x00" * 16)):

    aes128 = AES.new(key, AES.MODE_CBC, iv)
    decrypted = aes128.decrypt(data)
    return decrypted.decode("utf-16-le")

def aes128_decrypt_raw(data, key, iv = (b"\x00" * 16)):

    aes128 = AES.new(key, AES.MODE_CBC, iv)
    decrypted = aes128.decrypt(data)
    return decrypted

def aes256_decrypt(data, key, iv = (b"\x00" * 16)):

    aes256 = AES.new(key, AES.MODE_CBC, iv)
    decrypted = aes256.decrypt(data)
    return decrypted.decode("utf-16-le")

def aes256_decrypt_raw(data, key, iv = (b"\x00" * 16)):

    aes256 = AES.new(key, AES.MODE_CBC, iv)
    decrypted = aes256.decrypt(data)
    return decrypted

def _3des_decrypt(data, key, iv = (b"\x00" * 8)):

    _3des = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted = _3des.decrypt(data)
    return decrypted.decode("utf-16-le")

def _3des_decrypt_raw(data, key, iv = (b"\x00" * 8)):

    _3des = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted = _3des.decrypt(data)
    return decrypted



hash_types = [
    {"name": 'CALG_AES_128' , "value": '0e66', "key_length": 16, "block_size": 16,  "hash_prefix": "aes128$"},
    {"name": 'CALG_AES_256' , "value": '1066', "key_length": 32, "block_size": 16,  "hash_prefix": "aes256$"},
    {"name": 'CALG_3DES'    , "value": '0366', "key_length": 21, "block_size": 8,   "hash_prefix": "3des..$"},
]

def read_media_variable_file_header(filename):
    media_file = open(filename,'rb')
    media_data = media_file.read(40).hex()
    encryption_value = media_data[32:36]
    encryption_information = None

    # https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id
    # Identifier 	    Value
    #   CALG_3DES 	    0x00006603
    #   CALG_AES_128 	0x0000660e
    #   CALG_AES_256 	0x00006610

    for i in hash_types:
        if encryption_value == i["value"]:
            encryption_information = i

    if (not encryption_information):
        # We have not identified the encryption type
        return None

    hash = '$sccm$' + encryption_information["hash_prefix"] + media_data
    return hash

def decrypt_file(algo, data, key, iv=None, decode=True):
    decrypt = None
    if algo == 'CALG_AES_128' or algo == 'CALG_AES_256':
        iv = b"\x00" * 16
        decrypt = AES.new(key, AES.MODE_CBC, iv)
    elif algo == 'CALG_3DES':
        iv = b"\x00" * 8
        decrypt = DES3.new(key, DES3.MODE_CBC, iv)

    decrypted_bytes = decrypt.decrypt(data)

    if decode:
        out = decrypted_bytes.decode("utf-16-le")
    else:
        out = decrypted_bytes

    return out

class media_decryption():
    def __init__(self, filepath=None, media_data=None):
        """
        Initialise the media decryption, either supply a filepath to the media variable file or the raw media data.
        
        :param filepath: OS Path to the media variable file (Optional if media_data is supplied)
        :param media_data: Raw media variable file contents (Optional if filepath is supplied)
        """

        self.filepath = filepath

        self.derived_key = None
        self.encryption_information = None

        if (media_data == None) and (filepath != None):
            self.media_data = self._read_media_file()
        else:
            self.media_data = media_data

    def _identify_encryption_type(self):
        if self.encryption_information != None:
            # Assume that the encryption type has already been set
            return
        
        media_file = open(self.filepath,'rb')
        media_data = media_file.read(40).hex()
        encryption_value = media_data[32:36]

        # Key lengths with algo values: https://learn.microsoft.com/en-us/windows/win32/seccrypto/aes-provider-algorithms
        # Algo IDs: https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id

        for i in hash_types:
            if encryption_value == i["value"]:
                self.encryption_information = i
                #print(f"[+] Identified encryption type: {i['name']}")
                break
    
    def set_encryption_type(self, name):
        for i in hash_types:
            if name == i["name"]:
                self.encryption_information = i
                break

        if not self.encryption_information:
            return False
        return True

    def _read_media_file(self):
        media_file = open(self.filepath,'rb')
        # Skip the first 24 bytes of the file header
        media_file.seek(24)
        media_data = media_file.read()
        # Skip the last 8 bytes of the file footer
        return media_data[:-8]
    
    def _key_derivation(self, password):
        # https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey
        # https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptcreatehash

        # https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey#remarks
        # Diversification is listed inside the documentation:

        # Catch for accidentally passing in a string
        if isinstance(password, str):
            password = password.encode('utf-16-le')

        key_sha1 = sha1(password).digest()
        
        b0 = b""
        for x in key_sha1:
            b0 += bytes((x ^ 0x36,))

        b1 = b""
        for x in key_sha1:
            b1 += bytes((x ^ 0x5c,))

        # pad remaining bytes with the appropriate value
        b0 += b"\x36"*(64 - len(b0))
        b1 += b"\x5c"*(64 - len(b1))

        b0_sha1 = sha1(b0).digest()
        b1_sha1 = sha1(b1).digest()

        self.derived_key = b0_sha1 + b1_sha1

    def decrypt_media_file(self, password, decode=True):
        # Identify the encryption type used for the media file 
        self._identify_encryption_type()

        if not self.encryption_information:
            # Unknown Encryption Type
            return False, None
        
        # Derive the key from the password
        self._key_derivation(password)
        key_length = self.encryption_information["key_length"]
        # Modify the derived key to key length expected for the encryption type
        derived_key = self.derived_key[:key_length]

        last_block_size = math.floor(len(self.media_data)/self.encryption_information["block_size"]) * self.encryption_information["block_size"]
        
        try:
            decrypted_file = decrypt_file(
                self.encryption_information["name"], 
                self.media_data[:last_block_size], 
                derived_key,
                decode=decode
            )
        except:
            decrypted_file = None

        if not decrypted_file:
            return False, None

        decrypted_file =  decrypted_file[:decrypted_file.rfind('\x00')]
        wf_decrypted_ts = "".join(c for c in decrypted_file if c.isprintable())

        return True, wf_decrypted_ts
