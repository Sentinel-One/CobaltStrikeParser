#!/usr/bin/python3
'''
By Gal Kristal from SentinelOne (gkristal.w@gmail.com) @gal_kristal
These were awesome reference material:
    https://research.nccgroup.com/2020/06/15/striking-back-at-retired-cobalt-strike-a-look-at-a-legacy-vulnerability/
    https://github.com/nccgroup/pybeacon
'''

import struct
import base64
import hashlib
import random
import os
import string
import M2Crypto
import requests

PUBLIC_KEY_TEMPLATE = "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----"

class Metadata(object):
    """
    Class to represent a beacon's metadata.
    This is specific to Cobalt 4 and up
    """
    def __init__(self, public_key, aes_source_bytes):
        """
        Generates a random beacon entry
        Args:
            public_key (bytes): The extracted public key from beacon configuration
            aes_source_bytes (bytes): 16 bytes used to generate AES keys from
        """
        self.public_key = public_key
        self.port = random.randint(40000,50000)
        self.ciphertext = ""
        self.charset = 20273
        self.ver = random.randint(1,10)
        self.ip = os.urandom(4)
        self.comp = ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))
        self.user = ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))
        self.pid = random.randint(1,50000) * 4 - 2  # ;)
        self.bid = random.randint(1,1000000) * 2
        self.barch = 1
        self.is64 = False
        self.high_integrity = False
        self.aes_source_bytes = aes_source_bytes
        self.junk = os.urandom(14)
        d = hashlib.sha256(aes_source_bytes).digest()        
        self.aes_key = d[0:16]
        self.hmac_key = d[16:]


    def rsa_encrypt(self, data):
        """Encrypt given data the way Cobalt's server likes
        
        Args:
            data (bytes): Data to encrypt
        
        Returns:
            bytes: 
        """
        bio = M2Crypto.BIO.MemoryBuffer(PUBLIC_KEY_TEMPLATE.format(base64.b64encode(self.public_key).decode()).encode())
        pubkey = M2Crypto.RSA.load_pub_key_bio(bio)
        # Format is: magic + dataLength + data
        # beef is the magic used by the server
        packed_data = b'\x00\x00\xBE\xEF' + struct.pack('>I', len(data)) + data
        return pubkey.public_encrypt(packed_data, M2Crypto.RSA.pkcs1_padding)


    def pack(self):
        data = self.aes_source_bytes + struct.pack('>hhIIHBH', self.charset, self.charset, self.bid, self.pid, self.port, self.is64, self.ver) + self.junk
        data += struct.pack('4s', self.ip)
        data += b'\x00' * (51 - len(data))
        data += '\t'.join([self.comp, self.user]).encode()
        return self.rsa_encrypt(data)


TERMINATION_STEPS = ['header', 'parameter', 'print']
TSTEPS = {1: "append", 2: "prepend", 3: "base64", 4: "print", 5: "parameter", 6: "header", 7: "build", 8: "netbios", 9: "const_parameter", 10: "const_header", 11: "netbiosu", 12: "uri_append", 13: "base64url", 14: "strrep", 15: "mask", 16: "const_host_header"}

# Could probably just be b'\x00'*4 + data
def mask(arg, data):
    key = os.urandom(4)
    data = data.encode('latin-1')
    return key.decode('latin-1') + ''.join(chr(c ^ key[i%4]) for i, c in enumerate(data))
    
def demask(arg, data):
    key = data[:4].encode('latin-1')
    data = data.encode('latin-1')
    return ''.join(chr(c ^ key[i%4]) for i, c in enumerate(data[4:]))

def netbios_decode(name, case):
    i = iter(name.upper())
    try:
        return ''.join([chr(((ord(c)-ord(case))<<4)+((ord(next(i))-ord(case))&0xF)) for c in i])
    except:
        return ''

func_dict_encode = {"append": lambda arg, data: data + arg,
"prepend": lambda arg, data: arg + data,
"base64": lambda arg, data: base64.b64encode(data),
"netbios": lambda arg, data: ''.join([chr((ord(c)>>4) + ord('a')) + chr((ord(c)&0xF) + ord('a')) for c in data]),
"netbiosu": lambda arg, data: ''.join([chr((ord(c)>>4) + ord('A')) + chr((ord(c)&0xF) + ord('A')) for c in data]),
"base64": lambda arg, data: base64.b64encode(data.encode('latin-1')).decode('latin-1'),
"base64url": lambda arg, data: base64.urlsafe_b64encode(data.encode('latin-1')).decode('latin-1').strip('='),
"mask": mask,
}

func_dict_decode = {"append": lambda arg, data: data[:-len(arg)],
"prepend": lambda arg, data: data[len(arg):],
"base64": lambda arg, data: base64.b64decode(data),
"netbios": lambda arg, data: netbios_decode(data, 'a'),
"netbiosu": lambda arg, data: netbios_decode(data, 'A'),
"base64": lambda arg, data: base64.b64decode(data.encode('latin-1')).decode('latin-1'),
"base64url": lambda arg, data: base64.urlsafe_b64decode(data.encode('latin-1')).decode('latin-1').strip('='),
"mask": demask,
}


class Transform(object):
    def __init__(self, trans_dict):
        """An helper class to tranform data according to cobalt's malleable profile
        
        Args:
            trans_dict (dict): A dictionary that came from packedSetting data. It's in the form of:
                                {'ConstHeaders':[], 'ConstParams': [], 'Metadata': [], 'SessionId': [], 'Output': []}
        """
        self.trans_dict = trans_dict

    def encode(self, metadata, output, sessionId):
        """
        
        Args:
            metadata (str): The metadata of a Beacon, usually given from Metadata.pack()
            output (str): If this is for a Beacon's response, then this is the response's data
            sessionId (str): the Beacon's ID
        
        Returns:
            (str, dict, dict): This is to be used in an HTTP request. The tuple is (request_body, request_headers, request_params)
        """
        params = {}
        headers = {}
        body = ''
        for step in self.trans_dict['Metadata']:
            action = step.split(' ')[0].lower()
            arg = step.lstrip(action).strip().strip('"')
            if action in TERMINATION_STEPS:
                if action == "header":
                    headers[arg] = metadata
                elif action == "parameter":
                    params[arg] = metadata
                elif action == "print":
                    body = metadata
            else:
                metadata = func_dict_encode[action](arg, metadata)

        for step in self.trans_dict['Output']:
            action = step.split(' ')[0].lower()
            arg = step.lstrip(action).strip().strip('"')
            if action in TERMINATION_STEPS:
                if action == "header":
                    headers[arg] = output
                elif action == "parameter":
                    params[arg] = output
                elif action == "print":
                    body = output
            else:
                output = func_dict_encode[action](arg, output)

        for step in self.trans_dict['SessionId']:
            action = step.split(' ')[0].lower()
            arg = step.lstrip(action).strip().strip('"')
            if action in TERMINATION_STEPS:
                if action == "header":
                    headers[arg] = sessionId
                elif action == "parameter":
                    params[arg] = sessionId
                elif action == "print":
                    body = sessionId
            else:
                sessionId = func_dict_encode[action](arg, sessionId)

        for step in self.trans_dict['ConstHeaders']:
            offset = step.find(': ')
            header, value = step[:offset], step[offset+2:]
            headers[header] = value

        for step in self.trans_dict['ConstParams']:
            offset = step.find('=')
            param, value = step[:offset], step[offset+1:]
            params[param] = value

        return body, headers, params

    def decode(self, body, headers, params):
        """
        Parses beacon's communication data from an HTTP request
        Args:
            body (str): The body of an HTTP request
            headers (dict): Headers dict from the HTTP request
            params (dict): Params dict from the HTTP request
        
        Returns:
            (str, str, str): The tuple is (metadata, output, sessionId)
        """
        metadata = ''
        output = ''
        sessionId = ''
        for step in self.trans_dict['Metadata'][::-1]:
            action = step.split(' ')[0].lower()
            arg = step.lstrip(action).strip().strip('"')
            if action in TERMINATION_STEPS:
                if action == "header":
                    metadata = headers[arg]
                elif action == "parameter":
                    metadata = params[arg]
                elif action == "print":
                    metadata = body
            else:
                metadata = func_dict_decode[action](arg, metadata)

        for step in self.trans_dict['Output'][::-1]:
            action = step.split(' ')[0].lower()
            arg = step.lstrip(action).strip().strip('"')
            if action in TERMINATION_STEPS:
                if action == "header":
                    output = headers[arg]
                elif action == "parameter":
                    output = params[arg]
                elif action == "print":
                    output = body
            else:
                output = func_dict_decode[action](arg, output)

        for step in self.trans_dict['SessionId'][::-1]:
            action = step.split(' ')[0].lower()
            arg = step.lstrip(action).strip().strip('"')
            if action in TERMINATION_STEPS:
                if action == "header":
                    sessionId = headers[arg]
                elif action == "parameter":
                    sessionId = params[arg]
                elif action == "print":
                    sessionId = body
            else:
                sessionId = func_dict_decode[action](arg, sessionId)

        return metadata, output, sessionId





        
