from dataclasses import dataclass
from typing import Optional, Sequence, Type


class Ed25519Key:
    """
    Key for ed25519 format publickey

    https://security.stackexchange.com/questions/161105/ssh-ed25519-key-extract-pk-32-bytes
    """

    __original: bytes
    name: str
    key_bytes: bytes

    def __init__(self, incoming_bytes: bytes):
        self.__original = incoming_bytes

        # begin parsing name and key from bytes

        num_len = 4
        ptr = 0  # walking index

        # Get the name field

        name_len = int.from_bytes(incoming_bytes[ptr : ptr + num_len], byteorder="big")
        ptr += num_len

        self.name = str(incoming_bytes[ptr : ptr + name_len], encoding="utf-8")
        ptr += name_len

        # Get the key bytes field (should be 32b)

        key_len = int.from_bytes(incoming_bytes[ptr : ptr + num_len], byteorder="big")
        assert key_len == 32, "ed25519 key size should always be 32"
        ptr += num_len

        self.key_bytes = incoming_bytes[ptr : ptr + key_len]

        # let's compare to the last 32b just to be sure
        # maybe that's what we should be doing regardless
        assert (
            self.key_bytes == incoming_bytes[len(incoming_bytes) - 32 :]
        ), "Methods to get key should match easy way"


@dataclass
class SshKey:
    type: str
    key: Ed25519Key
    comment: str
