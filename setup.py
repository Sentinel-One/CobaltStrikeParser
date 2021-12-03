import setuptools
import sys

with open('README.md') as fh:
    long_description = fh.read()

setuptools.setup(
        name="CobaltStrikeParser",
        version="11721a49",
        description="Python parser for CobaltStrike Beacon's configuration",
        license="Attribution-NonCommercial-ShareAlike 4.0 International",
        long_description=long_description,
        url="https://github.com/Sentinel-One/CobaltStrikeParser",
        py_modules=["parse_beacon_config", "beacon_utils"],
        install_requires=["urllib3",
            "requests",
            "netstruct==1.1.2",
            "pefile==2019.4.18"]
        )
