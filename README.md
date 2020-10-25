# CobaltStrikeParser
Python parser for CobaltStrike Beacon's configuration

## Background
Use `parse_beacon_config.py` for stageless beacons or on memory dumps.

Many stageless beacons are PEs where the beacon code itself is stored in the `.data` section and xored with 4-byte key.
The `parse_encrypted_beacon_config.py` tries to find the xor key and data, decrypt the data and parse the configuration from it.
It's probably should be used when `parse_beacon_config.py` doesn't work.


## Usage
```
usage: parse_beacon_config.py [-h] [--json] [--quiet] [--version VERSION] path

Parses CobaltStrike Beacon's configuration from PE or memory dump.

positional arguments:
  path               Stager's file path

optional arguments:
  -h, --help         show this help message and exit
  --json             Print as json
  --quiet            Do not print missing settings
  --version VERSION  Try as specific cobalt version (3 or 4). If not specified, tries both. For decoded configs, this must be set for accuracy.
```
