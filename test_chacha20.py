import unittest

from chacha20 import decrypt, encrypt


class ChaCha20Tests(unittest.TestCase):
    def test_encrypt_and_decrypt(self):
        key = bytes.fromhex("00" * 32)
        nonce = bytes.fromhex("00" * 8)
        message = b"Hello, ChaCha20!"

        ciphertext = encrypt(message, key, nonce)

        self.assertNotEqual(ciphertext, message)
        self.assertEqual(decrypt(ciphertext, key, nonce), message)

    def test_reference_vector(self):
        key = bytes.fromhex("00" * 32)
        nonce = bytes.fromhex("00" * 8)
        expected = bytes.fromhex(
            "76b8e0ada0f13d90405d6ae55386bd28"
            "bdd219b8a08ded1aa836efcc8b770dc7"
        )

        self.assertEqual(encrypt(b"\0" * 32, key, nonce), expected)


if __name__ == "__main__":
    unittest.main()
