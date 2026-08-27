import pytest

from bkcrypto.asymmetric.ciphers import SM2AsymmetricCipher
from bkcrypto.asymmetric.interceptors import BaseAsymmetricInterceptor
from bkcrypto.utils.convertors import Base64Convertor
from tests.fixtures.legacy_vectors import LEGACY_CIPHERTEXTS, LEGACY_PLAINTEXT, SM2_PRIVATE_KEY


class PrefixInterceptor(BaseAsymmetricInterceptor):
    @classmethod
    def after_encrypt(cls, ciphertext: str, **kwargs) -> str:
        return f"bkcrypto${ciphertext}"

    @classmethod
    def before_decrypt(cls, ciphertext: str, **kwargs) -> str:
        return ciphertext[len("bkcrypto$") :]


@pytest.mark.compatibility
class TestSM2LegacyVectors:
    @classmethod
    @pytest.mark.parametrize("name", ["text.sm2.nodejs.encrypt", "text.sm2.python.encrypt"])
    def test_decrypt__supports_cross_language_ciphertext(cls, name: str) -> None:
        cipher = SM2AsymmetricCipher(private_key_string=SM2_PRIVATE_KEY)
        ciphertext = Base64Convertor.to_string(LEGACY_CIPHERTEXTS[name])

        assert cipher.decrypt(ciphertext) == LEGACY_PLAINTEXT.decode()


@pytest.mark.compatibility
class TestSM2Roundtrip:
    @classmethod
    def test_encrypt__roundtrips_with_regenerated_key(cls) -> None:
        cipher = SM2AsymmetricCipher()

        assert cipher.decrypt(cipher.encrypt("emoji 😄 中文 English")) == "emoji 😄 中文 English"

    @classmethod
    def test_encrypt__applies_interceptor(cls) -> None:
        cipher = SM2AsymmetricCipher(interceptor=PrefixInterceptor)
        ciphertext = cipher.encrypt("interceptor")

        assert ciphertext.startswith("bkcrypto$")
        assert cipher.decrypt(ciphertext) == "interceptor"

    @classmethod
    def test_sign__verifies_with_regenerated_key(cls) -> None:
        cipher = SM2AsymmetricCipher()
        signature = cipher.sign("message")

        assert cipher.verify("message", signature)
        assert not cipher.verify("other", signature)
