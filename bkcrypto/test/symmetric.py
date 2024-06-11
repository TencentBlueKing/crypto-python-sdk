import os

from bkcrypto import constants
from bkcrypto.contrib.basic.ciphers import get_symmetric_cipher
from bkcrypto.symmetric.ciphers import BaseSymmetricCipher


def test_symmetric_cipher():
    symmetric_cipher: BaseSymmetricCipher = get_symmetric_cipher(
        cipher_type=constants.SymmetricCipherType.SM4.value,
        common={"key": os.urandom(16)},
    )
    assert b"123" == symmetric_cipher.decrypt_b(symmetric_cipher.encrypt_b(b"123"))
