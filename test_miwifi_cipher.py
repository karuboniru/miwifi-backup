"""Known-answer tests captured from RN02 1.0.64 with math.random fixed at 42."""

import unittest
from unittest.mock import patch

from miwifi_cipher import decrypt, encrypt


class FirmwareCompatibility(unittest.TestCase):
    def test_firmware_vectors(self):
        vectors = (
            (b"0123456789abcdef", b"12345678", "24146ebe9864b4915881fc1fc57efaef"),
            (b"fixture-seed", b"123456789",
             "241b32a59d5c110ffd05e3b400db55287e6e0bd5b36a87286897afcbc9b1962f"),
        )
        with patch("miwifi_cipher.secrets.token_bytes", side_effect=lambda n: b"*" * n):
            for seed, plain, hex_cipher in vectors:
                with self.subTest(seed=seed):
                    cipher = bytes.fromhex(hex_cipher)
                    self.assertEqual(encrypt(plain, seed), cipher)
                    self.assertEqual(decrypt(cipher, seed), plain)


if __name__ == "__main__":
    unittest.main()
