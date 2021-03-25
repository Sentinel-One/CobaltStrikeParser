# CobaltStrikeParser
Python parser for CobaltStrike Beacon's configuration

## Background
Use `parse_beacon_config.py` for stageless beacons or on memory dumps.

Many stageless beacons are PEs where the beacon code itself is stored in the `.data` section and xored with 4-byte key.
The script tries to find the xor key and data heuristically, decrypt the data and parse the configuration from it.

This is designed so it can be used as a library too.

## Usage
```
usage: parse_beacon_config.py [-h] [--json] [--quiet] [--version VERSION] path

Parses CobaltStrike Beacon's configuration from PE or memory dump.

positional arguments:
  path               Beacon file path

optional arguments:
  -h, --help         show this help message and exit
  --json             Print as json
  --quiet            Do not print missing or empty settings
  --version VERSION  Try as specific cobalt version (3 or 4). If not specified, tries both.
```