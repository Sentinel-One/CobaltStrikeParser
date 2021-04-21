#!/usr/bin/python3
'''
By Gal Kristal from SentinelOne (gkristal.w@gmail.com) @gal_kristal
Refs: 
    https://github.com/RomanEmelyanov/CobaltStrikeForensic/blob/master/L8_get_beacon.py
    https://github.com/nccgroup/pybeacon
'''

import requests, struct, sys, os, urllib3
import argparse
from parse_beacon_config import cobaltstrikeConfig
from urllib.parse import urljoin
from io import BytesIO
from Crypto.Cipher import AES
import hmac
import urllib
import socket
from comm import *

HASH_ALGO = hashlib.sha256
SIG_SIZE = HASH_ALGO().digest_size
CS_FIXED_IV = b"abcdefghijklmnop"

EMPTY_UA_HEADERS = {"User-Agent":""}
URL_PATHS = {'x86':'ab2g', 'x64':'ab2h'}

def get_beacon_data(url, arch):
    full_url = urljoin(url, URL_PATHS[arch])
    try:
        resp = requests.get(full_url, timeout=30, headers=EMPTY_UA_HEADERS, verify=False)
    except requests.exceptions.RequestException as e:
        print('[-] Connection error: ', e)
        return

    if resp.status_code != 200:
        print('[-] Failed with HTTP status code: ', resp.status_code)
        return

    buf = resp.content

    # Check if it's a Trial beacon, therefore not xor encoded (not tested)
    eicar_offset = buf.find(b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE')
    if eicar_offset != -1:
        return cobaltstrikeConfig(BytesIO(buf)).parse_config()

    offset = buf.find(b'\xff\xff\xff')
    if offset == -1:
        print('[-] Unexpected buffer received')
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

        return cobaltstrikeConfig(BytesIO(decoded_data)).parse_config()


def register_beacon(conf):
    """Registers a random beacon and sends a task data.
    This is a POC that shows how a beacon send its metadata and task results with Malleable profiles
    
    Args:
        conf (dict): Beacon configuration dict, from cobaltstrikeConfig parser
    """
    # Register new random beacon
    urljoin('http://'+conf['C2Server'].split(',')[0], conf['C2Server'].split(',')[1])
    aes_source = os.urandom(16)
    m = Metadata(conf['PublicKey'], aes_source)
    t = Transform(conf['HttpGet_Metadata'])
    body, headers, params = t.encode(m.pack().decode('latin-1'), '', str(m.bid))

    print('[+] Registering new random beacon: comp=%s user=%s' % (m.comp, m.user))
    try:
        req = requests.request('GET', urljoin('http://'+conf['C2Server'].split(',')[0], conf['C2Server'].split(',')[1]), params=params, data=body, headers=dict(**headers, **{'User-Agent':''}), timeout=5)
    except Exception as e:
        print('[-] Got excpetion from server: %s' % e)
        return

    # This is how to properly encrypt a task:
    # Tasks are encrypted with the session's aes key, decided and negotiated when we registered the beacon (it's part of the metadata)
    ## Here is where you'll build a proper task struct ##
    random_data = os.urandom(50)
    # session counter = 1
    data = struct.pack('>II', 1, len(random_data)) + random_data
    pad_size = AES.block_size - len(data) % AES.block_size
    data = data + pad_size * b'\x00'

    # encrypt the task data and wrap with hmac sig and encrypted data length
    cipher = AES.new(m.aes_key, AES.MODE_CBC, CS_FIXED_IV)
    enc_data = cipher.encrypt(data)
    sig = hmac.new(m.hmac_key, enc_data, HASH_ALGO).digest()[0:16]
    enc_data += sig
    enc_data = struct.pack('>I', len(enc_data)) + enc_data

    # task data is POSTed so we need to take the transformation steps of http-post.client
    t = Transform(conf['HttpPost_Metadata'])
    body, headers, params = t.encode(m.pack().decode('latin-1'), enc_data.decode('latin-1'), str(m.bid))

    print('[+] Sending task data')
    
    try:
        req = requests.request('POST', urljoin('http://'+conf['C2Server'].split(',')[0], conf['HttpPostUri'].split(',')[0]), params=params, data=body, headers=dict(**headers, **{'User-Agent':''}), timeout=5)
    except Exception as e:
        print('[-] Got excpetion from server while sending task: %s' % e)



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Parse CobaltStrike Beacon's configuration from C2 url and registers a beacon with it")
    parser.add_argument("url", help="Cobalt C2 server (e.g. http://1.1.1.1)")
    args = parser.parse_args()

    x86_beacon_conf = get_beacon_data(args.url, 'x86')
    x64_beacon_conf = get_beacon_data(args.url, 'x64')
    if not x86_beacon_conf and not x64_beacon_conf:
        print("[-] Failed finding any beacon configuration")
        exit(1)

    print("[+] Got beacon configuration successfully")
    conf = x86_beacon_conf or x64_beacon_conf
    register_beacon(conf)