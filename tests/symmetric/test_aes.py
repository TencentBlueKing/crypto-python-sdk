import base64
import os

import pytest

from bkcrypto import constants
from bkcrypto.symmetric.ciphers import AESSymmetricCipher
from bkcrypto.symmetric.ciphers.base import EncryptionMetadata
from bkcrypto.symmetric.interceptors import BaseSymmetricInterceptor


class CiphertextOnlyInterceptor(BaseSymmetricInterceptor):
    @classmethod
    def after_encrypt(cls, ciphertext: str, **kwargs) -> str:
        cipher = kwargs["cipher"]
        ciphertext_bytes, _ = cipher.extract_encryption_metadata(ciphertext)
        return cipher.config.convertor.to_string(ciphertext_bytes)

    @classmethod
    def before_decrypt(cls, ciphertext: str, **kwargs) -> str:
        cipher = kwargs["cipher"]
        ciphertext_bytes = cipher.config.convertor.from_string(ciphertext)
        return cipher.combine_encryption_metadata(ciphertext_bytes, EncryptionMetadata(cipher.config.iv))


@pytest.mark.compatibility
class TestAESLegacyAPI:
    @classmethod
    def test_encrypt__keeps_default_ctr_string_roundtrip(cls, aes_key: bytes) -> None:
        cipher = AESSymmetricCipher(key=aes_key)

        ciphertext = cipher.encrypt("中文 and English")

        assert cipher.config.mode == constants.SymmetricMode.CTR
        assert cipher.decrypt(ciphertext) == "中文 and English"
        assert len(base64.b64decode(ciphertext)) > 16

    @classmethod
    def test_encrypt__keeps_cbc_without_padding(cls, aes_key: bytes) -> None:
        cipher = AESSymmetricCipher(key=aes_key, mode=constants.SymmetricMode.CBC)
        plaintext = "exactly-16-bytes"

        assert cipher.decrypt(cipher.encrypt(plaintext)) == plaintext

    @classmethod
    def test_encrypt__supports_cfb_interceptor_with_exact_aes192_key(cls) -> None:
        cipher = AESSymmetricCipher(
            key=os.urandom(24),
            key_size=24,
            iv=os.urandom(16),
            interceptor=CiphertextOnlyInterceptor,
            mode=constants.SymmetricMode.CFB,
        )

        ciphertext = cipher.encrypt("legacy interceptor")

        assert cipher.decrypt(ciphertext) == "legacy interceptor"


class TestAESBytesAPI:
    @classmethod
    @pytest.mark.parametrize("plaintext", [b"", b"1", b"x" * 15, b"x" * 16, b"x" * 17, b"\x00\xff\x80"])
    def test_cbc_pkcs7__roundtrips_binary_boundaries(cls, aes_key: bytes, plaintext: bytes) -> None:
        cipher = AESSymmetricCipher(
            key=aes_key,
            mode=constants.SymmetricMode.CBC,
            padding=constants.SymmetricPadding.PKCS7,
        )

        assert cipher.decrypt_bytes(cipher.encrypt_bytes(plaintext)) == plaintext

    @classmethod
    @pytest.mark.parametrize("plaintext", [b"", b"1", b"x" * 16, b"\x00\xff\x80"])
    def test_ctr__roundtrips_binary_boundaries(cls, aes_key: bytes, plaintext: bytes) -> None:
        cipher = AESSymmetricCipher(key=aes_key, mode=constants.SymmetricMode.CTR)

        assert cipher.decrypt_bytes(cipher.encrypt_bytes(plaintext)) == plaintext


class TestAESValidation:
    @classmethod
    @pytest.mark.parametrize("key", [b"x" * 15, b"x" * 17, b"x" * 32])
    def test_init__rejects_key_that_does_not_match_configured_size(cls, key: bytes) -> None:
        with pytest.raises(ValueError, match="AES key must be exactly 16 bytes"):
            AESSymmetricCipher(key=key)

    @classmethod
    @pytest.mark.parametrize("iv", [b"x" * 15, b"x" * 17])
    def test_init__rejects_invalid_cbc_or_ctr_iv(cls, aes_key: bytes, iv: bytes) -> None:
        with pytest.raises(ValueError, match="IV must be exactly 16 bytes"):
            AESSymmetricCipher(key=aes_key, iv=iv, mode=constants.SymmetricMode.CBC)

    @classmethod
    def test_decrypt_bytes__rejects_truncated_iv(cls, aes_key: bytes) -> None:
        cipher = AESSymmetricCipher(key=aes_key, mode=constants.SymmetricMode.CTR)

        with pytest.raises(ValueError, match="IV must be exactly 16 bytes"):
            cipher.decrypt_bytes(base64.b64encode(b"short iv").decode())

    @classmethod
    def test_decrypt_bytes__rejects_invalid_base64(cls, aes_key: bytes) -> None:
        cipher = AESSymmetricCipher(key=aes_key)

        with pytest.raises(ValueError):
            cipher.decrypt_bytes("not base64 %%%")

    @classmethod
    @pytest.mark.parametrize("ciphertext", [b"", b"not aligned"])
    def test_cbc__rejects_empty_or_unaligned_ciphertext(cls, aes_key: bytes, ciphertext: bytes) -> None:
        cipher = AESSymmetricCipher(
            key=aes_key,
            mode=constants.SymmetricMode.CBC,
            padding=constants.SymmetricPadding.PKCS7,
        )
        encoded = base64.b64encode(os.urandom(16) + ciphertext).decode()

        with pytest.raises(ValueError, match="non-empty and block-aligned"):
            cipher.decrypt_bytes(encoded)

    @classmethod
    def test_cbc_pkcs7__rejects_invalid_padding(cls, aes_key: bytes) -> None:
        iv = os.urandom(16)
        unpadded_cipher = AESSymmetricCipher(
            key=aes_key,
            iv=iv,
            mode=constants.SymmetricMode.CBC,
            padding=constants.SymmetricPadding.NONE,
        )
        padded_cipher = AESSymmetricCipher(
            key=aes_key,
            iv=iv,
            mode=constants.SymmetricMode.CBC,
            padding=constants.SymmetricPadding.PKCS7,
        )
        ciphertext = unpadded_cipher.encrypt_bytes(b"\x00" * 16)

        with pytest.raises(ValueError):
            padded_cipher.decrypt_bytes(ciphertext)
