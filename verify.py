from nacl.signing import VerifyKey


def verify(message: bytes, /, verify_key_bytes: bytes) -> bytes:
    try:
        verify_key = VerifyKey(verify_key_bytes)
        return verify_key.verify(message)
    except Exception as e:
        # print(f"couldn't verify bytes: {e}")
        raise e
