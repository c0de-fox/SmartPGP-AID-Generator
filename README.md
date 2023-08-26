# PGP AID Generator

Script to generate a valid Application Identifier (AID) for an implementation
of a PGP Smart Card (such as SmartPGP)

The AID is 16 bytes in length and must be unique (multiple cards should have different AIDs).
The AID is written to the Smart Card during application install, and can not be changed without
reinstalling the `SmartPGP.cap`

## The structure of the AID is described as follows

The first 6 bytes are static and always `0xD2 0x76 0x00 0x01 0x24 0x01`. The next 2 bytes represent the version of the PGP Specification, which is `0x03 0x04` for SmartPGP (PGP 3.4)

The following 2 bytes are the "Manufacturer ID"; They're supposed to be registered by OpenPGP devs, but using an unknown one doesn't cause issues, and it looks better than "Test Card".

Additionally, newer versions of OpenPGP include a new "Manufacturer Name" attribute, that is not part of the AID

[Official Manufacturer IDs](https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=scd/app-openpgp.c;hb=HEAD#l292)

The manufacturer id this script uses is `0xC0 0xDE`, feel free to change this to something else.

Following the manufacturer id, the next 4 bytes are for the serial number. This must be unique for all cards that share the same manufacturer id.

There are 2 bytes after the serial number, that are static and always `0x00 0x00` (reserved for future use)

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

