#!/usr/bin/env python

from base64 import b64encode
from nacl.signing import SigningKey, SignedMessage
from pathlib import Path
import sys

from verify import verify
from read_and_parse_sshkey import read_and_parse_sshkey

messages = Path("./messages")
keys = Path("./keys")


def main() -> int:
    """
    Signing
    """
    s = read_and_parse_sshkey(Path("./keys/ed_25519.pub"))
    key_bytes = s.key.key_bytes

    key = SigningKey(key_bytes)
    verify_bytes = key.verify_key.encode()
    message: SignedMessage = key.sign(
        b"""
Certified Release of ECNBASIC2017.EC1700BASIC
by data provider: ECON

Verify Key for this signature file:
"""
        + b64encode(verify_bytes)
        + b"""

Ver. 1.1
Released 2018-08-22

Verified SHA-256 hash for this release:
sgjasoenaosemgasef;msefo;i1243i1qfjqw
    """
    )

    # with open(messages / "econ_test.mesg", "wb") as f:
    #     f.write(message)

    # Do I even care about the verification part?
    # print(f"omitting first 32 bytes: ", message[64:])

    """
    Verification
    """
    try:
        b = verify(message, verify_key_bytes=verify_bytes)
        print(f"verified bytes: \n{b}")
        sys.exit(0)
    except Exception as e:
        print(f"couldn't verify bytes: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
