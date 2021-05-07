#!/usr/bin/python3
'''
By Gal Kristal from SentinelOne (gkristal.w@gmail.com) @gal_kristal
Refs: 
    https://github.com/RomanEmelyanov/CobaltStrikeForensic/blob/master/L8_get_beacon.py
    https://github.com/nccgroup/pybeacon
'''

import requests, struct, urllib3
import argparse
from urllib.parse import urljoin
import socket
import json
from base64 import b64encode
from struct import unpack, unpack_from

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
EMPTY_UA_HEADERS = {"User-Agent":""}
URL_PATHS = {'x86':'ab2g', 'x64':'ab2h'}

class Base64Encoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            return b64encode(o).decode()
        return json.JSONEncoder.default(self, o)


def _cli_print(msg, end='\n'):
    if __name__ == '__main__':
        print(msg, end=end)


def read_dword_be(fh):
    data = fh.read(4)
    if not data or len(data) != 4:
        return None
    return unpack(">I",data)[0]


def get_beacon_data(url, arch):
    full_url = urljoin(url, URL_PATHS[arch])
    try:
        resp = requests.get(full_url, timeout=30, headers=EMPTY_UA_HEADERS, verify=False)
    except requests.exceptions.RequestException as e:
        _cli_print('[-] Connection error: ', e)
        return

    if resp.status_code != 200:
        _cli_print('[-] Failed with HTTP status code: ', resp.status_code)
        return

    buf = resp.content

    # Check if it's a Trial beacon, therefore not xor encoded (not tested)
    eicar_offset = buf.find(b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE')
    if eicar_offset != -1:
        return buf
    return decrypt_beacon(buf)


def decrypt_beacon(buf):
    offset = buf.find(b'\xff\xff\xff')
    if offset == -1:
        _cli_print('[-] Unexpected buffer received')
        return
    offset += 3
    key = struct.unpack_from('<I', buf, offset)[0]
    size = struct.unpack_from('<I', buf, offset+4)[0] ^ key
    head_enc = struct.unpack_from('<I', buf, offset+8)[0] ^ key
    head = head_enc & 0xffff

    # Taken directly from L8_get_beacon.py
    if head == 0x5a4d or head ==0x9090:
        decoded_data = b''
        for i in range(2+offset//4, len(buf)//4-4):
            a = struct.unpack_from('<I', buf, i*4)[0]
            b = struct.unpack_from('<I', buf, i*4+4)[0]
            с = a ^ b
            decoded_data += struct.pack('<I', с)
        return decoded_data
