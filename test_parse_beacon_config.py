#! /usr/bin/python3

import io
import os
import unittest

from parse_beacon_config import cobaltstrikeConfig

from zipfile import ZipFile


def decrypt_sample(zip_path):
    with ZipFile(zip_path) as z:
        for fn in z.namelist():
            return io.BytesIO(z.read(fn, pwd=bytes("infected", "ascii")))


class TestBeaconParsing(unittest.TestCase):
    def test_non_pe_x86(self):
        path = os.path.join(
            os.path.dirname(__file__),
            "samples",
            "13e954be0b0c022c392c956e9a800201a75dab7e288230b835bcdd4a9d68253d.zip",
        )
        f = decrypt_sample(path)
        parser = cobaltstrikeConfig(f)
        conf = parser.parse_encrypted_config()
        self.assertEqual(conf.get("HttpPostUri"), "/submit.php")


if __name__ == "__main__":
    unittest.main()
