#!/usr/bin/python3

"""
Script to generate a valid Application Identifier (AID) for an implementation
of a PGP Smart Cart (such as SmartPGP)

The AID is 16 bytes in length and must be unique (multiple cards should have different AIDs).
The AID is written to the Smart Card during application install, and can not be changed without
reinstalling the `SmartPGP.cap`

The structure of the AID is described as follows:
The first 6 bytes are static and always `0xD2 0x76 0x00 0x01 0x24 0x01`. The next 2 bytes represent
the version of the PGP Specification, which is `0x03 0x04` for SmartPGP (PGP 3.4)

The following 2 bytes are the "Manufacturer ID"; They're supposed to be registered by OpenPGP devs,
but using an unknown one doesn't cause issues, and it looks better than "Test Card". Additionally,
newer versions of OpenPGP include a new "Manufacturer Name" attribute, that is not part of the AID

The list of registered manufacturer ids can be found here:
https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=scd/app-openpgp.c;hb=HEAD#l292

The manufacturer id this script uses is `0xC0 0xDE`, feel free to change this to something else.

Following the manufacturer id, the next 4 bytes are for the serial number. This must be unique for
all cards that share the same manufacturer id. There are 2 bytes after the serial number, that are
static and always `0x00 0x00` (reserved for future use)

To generate the serial number, you must provide this script with the following information:

    1. The `ICSerialNumber` value from `gp -i`
    2. One or more domain names that you control

The UUID of `ICSerialNumber` will be created using the namespace of the IC Manufacturer; In this
case, we are using Infineon. You should define the namespace for your device if different.

For every domain name provided, its UUID will be calculated, in the DNS namespace.
All UUIDs will then be concatinated together, and the SHA1 hash will be taken from that.

The SHA1 hash will then have a UUID generated from that, in the SHA1 namespace.
The first 8 characters of the resulting UUID are the serial number.

A complete AID that could be produced by this script is: `d276000124010304c0decdf177610000`

Usage:
    aid_generator.py <ic_serial_number> <domain_name>...
    aid_generator.py (-h | --help)
    aid_generator.py --version

Options:
    -h --help     Show this screen
    --version     Show current version
"""

import uuid
import hashlib

from typing import Any

from docopt import docopt

AID_PREFIX = "d276000124010304"  # RID:10, APP:2, SPEC:4
AID_POSTFIX = "0000"  # RFU:4
MANUFACTURER_ID = "c0de"

NAMESPACE_INFINEON: uuid.UUID = uuid.uuid5(uuid.NAMESPACE_OID, "1.2.276.0.68")
"""UUID Namespace for Infineon devices, defined from OID Namespace

https://oid-rep.orange-labs.fr/get/1.2.276.0.68"""

NAMESPACE_SHAONE: uuid.UUID = uuid.uuid5(uuid.NAMESPACE_OID, "1.3.14.3.2.26")
"""UUID Namespace for SHA1 hashes, defined from OID Namespace

https://oid-rep.orange-labs.fr/get/1.3.14.3.2.26"""


def main(options: dict[str, Any]) -> None:
    """Main method"""

    uuid_hash = hashlib.sha1()
    uuid_result: uuid.UUID
    aid_result: str

    if (
        len(options.get("<ic_serial_number>", "")) > 0
        and len(options.get("<domain_name>", [])) > 0
    ):
        uuid_hash.update(
            uuid.uuid5(NAMESPACE_INFINEON, str(options["<ic_serial_number>"])).bytes
        )

        for domain in list(options["<domain_name>"]):
            uuid_hash.update(uuid.uuid5(uuid.NAMESPACE_DNS, str(domain)).bytes)

        uuid_result = uuid.uuid5(NAMESPACE_SHAONE, uuid_hash.hexdigest())
        aid_result = f"{AID_PREFIX}{MANUFACTURER_ID}{uuid_result.hex[:8]}{AID_POSTFIX}"
        print(f"Your AID is: {aid_result}")


if __name__ == "__main__":
    main(docopt(__doc__, version="2023.08.1"))
