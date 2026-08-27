import base64

import pytest
from Cryptodome.Hash import SHA256
from Cryptodome.IO import PEM
from Cryptodome.PublicKey import RSA

from bkcrypto import constants
from bkcrypto.asymmetric.ciphers import RSAAsymmetricCipher


class TestRSAKey:
    @classmethod
    def test_generate_key_pair__uses_bk_kms_formats(cls) -> None:
        cipher = RSAAsymmetricCipher()

        assert cipher.config.public_key.size_in_bits() == 2048
        assert cipher.config.public_key.e == 65537
        assert cipher.export_public_key().startswith("-----BEGIN PUBLIC KEY-----")
        assert cipher.export_private_key().startswith("-----BEGIN RSA PRIVATE KEY-----")

    @classmethod
    def test_load_private_key__accepts_pkcs1_and_pkcs8(cls, rsa_private_key: str) -> None:
        private_key = RSA.import_key(rsa_private_key)
        pkcs8_private_key = PEM.encode(private_key.export_key(format="DER", pkcs=8), "PRIVATE KEY")

        assert RSAAsymmetricCipher(private_key_string=rsa_private_key).config.private_key.has_private()
        assert RSAAsymmetricCipher(private_key_string=pkcs8_private_key).config.private_key.has_private()

    @classmethod
    def test_load_public_key__keeps_private_key_input_compatible(cls, rsa_private_key: str) -> None:
        cipher = RSAAsymmetricCipher(public_key_string=rsa_private_key)

        assert not cipher.config.public_key.has_private()

    @classmethod
    @pytest.mark.parametrize(
        ("argument", "value"),
        [("public_key_string", "invalid public key"), ("private_key_string", "invalid private key")],
    )
    def test_load_key__rejects_invalid_pem(cls, argument: str, value: str) -> None:
        with pytest.raises(ValueError, match="Invalid RSA"):
            RSAAsymmetricCipher(**{argument: value})


class TestRSALegacyAPI:
    @classmethod
    @pytest.mark.compatibility
    def test_encrypt__keeps_segmented_pkcs1_v1_5_roundtrip(cls, rsa_private_key: str) -> None:
        cipher = RSAAsymmetricCipher(private_key_string=rsa_private_key)
        plaintext = "中英文 mixed text " * 80

        assert cipher.decrypt(cipher.encrypt(plaintext)) == plaintext

    @classmethod
    def test_encrypt__can_disable_segmented_encryption(cls, rsa_private_key: str) -> None:
        cipher = RSAAsymmetricCipher(
            private_key_string=rsa_private_key,
            enable_segmented_encryption=False,
        )

        assert cipher.decrypt(cipher.encrypt("x" * 245)) == "x" * 245
        with pytest.raises(ValueError, match="too long"):
            cipher.encrypt("x" * 246)

    @classmethod
    def test_encrypt_bytes__roundtrips_non_utf8_data(cls, rsa_private_key: str) -> None:
        cipher = RSAAsymmetricCipher(private_key_string=rsa_private_key)
        plaintext = b"\x00\xff\x80binary"

        assert cipher.decrypt_bytes(cipher.encrypt_bytes(plaintext)) == plaintext

    @classmethod
    def test_decrypt__rejects_invalid_base64(cls, rsa_private_key: str) -> None:
        cipher = RSAAsymmetricCipher(private_key_string=rsa_private_key)

        with pytest.raises(ValueError):
            cipher.decrypt("not base64 %%%")


class TestRSAOAEP:
    @classmethod
    def make_cipher(cls, rsa_private_key: str, **options) -> RSAAsymmetricCipher:
        return RSAAsymmetricCipher(
            private_key_string=rsa_private_key,
            padding=constants.RSACipherPadding.PKCS1_OAEP,
            oaep_hash=SHA256,
            mgf1_hash=SHA256,
            **options,
        )

    @classmethod
    def test_encrypt_bytes__roundtrips_sha256_and_mgf1_sha256(cls, rsa_private_key: str) -> None:
        cipher = cls.make_cipher(rsa_private_key)
        plaintext = b"\x00\xffBK-KMS data key\x80"

        assert cipher.decrypt_bytes(cipher.encrypt_bytes(plaintext)) == plaintext

    @classmethod
    def test_encrypt_bytes__enforces_oaep_sha256_boundary(cls, rsa_private_key: str) -> None:
        cipher = cls.make_cipher(rsa_private_key)

        assert cipher.decrypt_bytes(cipher.encrypt_bytes(b"x" * 190)) == b"x" * 190
        with pytest.raises(ValueError, match="too long"):
            cipher.encrypt_bytes(b"x" * 191)

    @classmethod
    def test_decrypt_bytes__requires_one_modulus_block(cls, rsa_private_key: str) -> None:
        cipher = cls.make_cipher(rsa_private_key)

        with pytest.raises(ValueError, match="ciphertext length"):
            cipher.decrypt_bytes(base64.b64encode(b"short").decode())

    @classmethod
    def test_encrypt__keeps_segmented_string_api(cls, rsa_private_key: str) -> None:
        cipher = cls.make_cipher(rsa_private_key)
        plaintext = "x" * 400

        assert cipher.decrypt(cipher.encrypt(plaintext)) == plaintext

    @classmethod
    def test_oaep_label__must_match_for_decryption(cls, rsa_private_key: str) -> None:
        cipher = cls.make_cipher(rsa_private_key, oaep_label=b"bk-kms")
        ciphertext = cipher.encrypt_bytes(b"data key")

        assert cipher.decrypt_bytes(ciphertext) == b"data key"
        with pytest.raises(ValueError):
            cls.make_cipher(rsa_private_key, oaep_label=b"other").decrypt_bytes(ciphertext)
