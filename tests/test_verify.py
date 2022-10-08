from verify import verify


class TestVerify:
    """
    Welcome to my very janky test suite
    """

    from pathlib import Path

    messages = Path("./messages")
    keys = Path("./keys")
    verification_keys = keys / "verify"

    def test_good_message(self):
        """Good message"""
        try:
            with open(self.messages / "good.mesg", "rb") as message, open(
                self.verification_keys / "primary_verification.key", "rb"
            ) as key:
                b = verify(message.read(), verify_key_bytes=key.read())
                print(
                    f"[✅] Correct, decoded nicely. the text is: {str(b, encoding='utf-8')}"
                )
                assert True
        except Exception as e:
            assert False, "[❌] should never reach this point"

    def test_bad_signature(self):
        """Bad message signature"""
        try:
            with open(self.messages / "bad_signature.mesg", "rb") as message, open(
                self.verification_keys / "primary_verification.key", "rb"
            ) as key:
                b = verify(message.read(), verify_key_bytes=key.read())
                assert False, "[❌] should never reach this point"
        except Exception as e:
            print(f"[✅] Correct, the key was bad. the error was: {e}")
            assert True

    def bad_message_body(self):
        """Bad message body"""
        try:
            with open(self.messages / "bad_message.mesg", "rb") as message, open(
                self.verification_keys / "primary_verification.key", "rb"
            ) as key:
                b = verify(message.read(), verify_key_bytes=key.read())
                assert False, "[❌] should never reach this point"
        except Exception as e:
            print(f"[✅] Correct, the key was bad. the error was: {e}")
            assert True

    def test_econ_message(self):
        try:
            with open(self.messages / "econ_test.mesg", "rb") as message, open(
                self.verification_keys / "primary_verification.key", "rb"
            ) as key:
                b = verify(message.read(), verify_key_bytes=key.read())
                print(
                    f"[✅] Correct, decoded nicely. the text is: {str(b, encoding='utf-8')}"
                )
                assert True
        except Exception as e:
            assert False, "[❌] should never reach this point"
