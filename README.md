# CobaltStrikeParser
Python parser for CobaltStrike Beacon's configuration

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
