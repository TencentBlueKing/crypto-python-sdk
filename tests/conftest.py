import os

import pytest

from bkcrypto.asymmetric.ciphers import RSAAsymmetricCipher


@pytest.fixture(scope="session")
def rsa_private_key() -> str:
    return RSAAsymmetricCipher().export_private_key()


@pytest.fixture
def aes_key() -> bytes:
    return os.urandom(16)
