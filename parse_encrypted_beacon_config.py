import pefile
from io import BytesIO
from parse_beacon_config import *
import argparse

THRESHOLD = 1100

def cli_print(msg):
    if __name__ == '__main__':
        print(msg)


class encryptedCobaltstrikeConfig:
    def __init__(self, f):
            '''
            f: file path
            '''
            self.path = f

    def parse_config(self, version=None, quiet=False, as_json=False):
        '''
        Parses beacon's configuration from stager dll or memory dump
        :bool quiet: Whether to print missing settings
        :bool as_json: Whether to dump as json
        '''

        pe = pefile.PE(args.path)
        data_sections = [s for s in pe.sections if s.Name.find(b'.data') != -1]
        if not data_sections:
            cli_print("Failed to find .data section")
            return False
        data = data_sections[0].get_data()

        offset = 0
        key_found = False
        while offset < len(data):
            key = data[offset:offset+4]
            if key != bytes(4):
                if data.count(key) >= THRESHOLD:
                    key_found = True
                    size = int.from_bytes(data[offset-4:offset], 'little')
                    encrypted_data_offset = offset+16 - (offset % 16)
                    break

            offset += 4

        if not key_found:
            cli_print("Failed to find encrypted data (try to lower the threshold constant)")
            return False

        ## decrypt and parse
        enc_data = data[encrypted_data_offset:encrypted_data_offset+size]
        dec_data = []
        for i,c in enumerate(enc_data):
            dec_data.append(c ^ key[i % 4])

        dec_data = bytes(dec_data)
        return cobaltstrikeConfig(BytesIO(dec_data)).parse_config(version=args.version, quiet=args.quiet, as_json=args.json)



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Parses CobaltStrike Beacon configuration from PE where it's stored as xored data")
    parser.add_argument("path", help="Sample file path (exe or dll)")
    parser.add_argument("--json", help="Print as json", action="store_true", default=False)
    parser.add_argument("--quiet", help="Do not print missing settings", action="store_true", default=False)
    parser.add_argument("--version", help="Try as specific cobalt version (3 or 4). If not specified, tries both. \nFor decoded configs, this must be set for accuracy.", type=int)
    args = parser.parse_args()

    encryptedCobaltstrikeConfig(args.path).parse_config(version=args.version, quiet=args.quiet, as_json=args.json)
    