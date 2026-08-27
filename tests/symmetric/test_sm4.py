import hashlib
import os

import pytest

from bkcrypto import constants
from bkcrypto.symmetric.ciphers import SM4SymmetricCipher
from bkcrypto.utils.convertors import Base64Convertor
from tests.fixtures.legacy_vectors import LEGACY_CIPHERTEXTS, LEGACY_PLAINTEXT, SM4_CROSS_LANGUAGE_KEY


@pytest.mark.compatibility
class TestSM4LegacyVectors:
    @classmethod
    @pytest.mark.parametrize("name", ["text.sm4.cpp.encrypt", "text.sm4.nodejs.encrypt"])
    def test_decrypt__supports_cross_language_ciphertext(cls, name: str) -> None:
        cipher = SM4SymmetricCipher(key=SM4_CROSS_LANGUAGE_KEY)
        ciphertext = Base64Convertor.to_string(LEGACY_CIPHERTEXTS[name])

        assert cipher.decrypt(ciphertext) == LEGACY_PLAINTEXT.decode()

    @classmethod
    def test_fixture__preserves_java_ciphertext(cls) -> None:
        # The historical attachment contains this ciphertext but no corresponding key.
        ciphertext = LEGACY_CIPHERTEXTS["text.sm4.java.encrypt"]

        assert len(ciphertext) == 53
        assert (
            hashlib.sha256(ciphertext).hexdigest() == "8a0864fd3f6082b79a4457dc8219b2813f7566d708ecfe327ad3a4f446c6ffb4"
        )


@pytest.mark.compatibility
class TestSM4Roundtrip:
    @classmethod
    @pytest.mark.parametrize(
        "mode",
        [constants.SymmetricMode.CBC, constants.SymmetricMode.CTR, constants.SymmetricMode.CFB],
    )
    def test_encrypt__roundtrips_with_regenerated_key(cls, mode: constants.SymmetricMode) -> None:
        cipher = SM4SymmetricCipher(key=os.urandom(16), mode=mode)
        plaintext = "x" * 16 if mode == constants.SymmetricMode.CBC else "SM4 binary 中文"

        assert cipher.decrypt(cipher.encrypt(plaintext)) == plaintext

    @classmethod
    def test_gcm__roundtrips_with_regenerated_key(cls) -> None:
        cipher = SM4SymmetricCipher(
            key=os.urandom(16),
            mode=constants.SymmetricMode.GCM,
            aad=os.urandom(20),
        )

        assert cipher.decrypt(cipher.encrypt("SM4 GCM roundtrip")) == "SM4 GCM roundtrip"
