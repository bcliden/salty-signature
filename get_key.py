from base64 import b64decode
from pathlib import Path

from key_classes import SshKey, Ed25519Key


def read_and_parse_sshkey(path: Path) -> SshKey:
    """
    Get the key from current directory and return info struct
    """

    with open(path, "r") as f:
        parts = iter(f.read().split(" "))
        parts = map(lambda s: s.strip(), parts)

        return SshKey(
            type=next(parts),
            key=Ed25519Key(b64decode(next(parts))),
            comment=next(parts),
        )


if __name__ == "__main__":
    print(read_and_parse_sshkey(Path("./keys/ed_25519.pub")))
