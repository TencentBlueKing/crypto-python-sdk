import pytest
from Cryptodome.Hash import SHA256

from bkcrypto import constants
from bkcrypto.asymmetric.ciphers import RSAAsymmetricCipher
from bkcrypto.symmetric.ciphers import AESSymmetricCipher
from tests.fixtures.bk_kms_vectors import (
    AES_KEY,
    GO_AES_CBC_CIPHERTEXT,
    GO_AES_CTR_CIPHERTEXT,
    GO_RSA_CIPHERTEXT,
    PLAINTEXT,
    PYTHON_AES_CBC_CIPHERTEXT_VERIFIED_BY_GO,
    PYTHON_AES_CTR_CIPHERTEXT_VERIFIED_BY_GO,
    PYTHON_RSA_CIPHERTEXT_VERIFIED_BY_GO,
    RSA_PRIVATE_KEY,
)


class TestBKKMSRSAInterop:
    @classmethod
    def make_cipher(cls) -> RSAAsymmetricCipher:
        return RSAAsymmetricCipher(
            private_key_string=RSA_PRIVATE_KEY,
            padding=constants.RSACipherPadding.PKCS1_OAEP,
            oaep_hash=SHA256,
            mgf1_hash=SHA256,
            enable_segmented_encryption=False,
        )

    @classmethod
    @pytest.mark.parametrize(
        "ciphertext",
        [GO_RSA_CIPHERTEXT, PYTHON_RSA_CIPHERTEXT_VERIFIED_BY_GO],
    )
    def test_decrypt_bytes__reads_bk_kms_compatible_oaep_sha256(cls, ciphertext: str) -> None:
        assert cls.make_cipher().decrypt_bytes(ciphertext) == PLAINTEXT

    @classmethod
    def test_export_key__matches_bk_kms_pem_contract(cls) -> None:
        cipher = cls.make_cipher()

        assert cipher.export_public_key().startswith("-----BEGIN PUBLIC KEY-----")
        assert cipher.export_private_key().startswith("-----BEGIN RSA PRIVATE KEY-----")


class TestBKKMSAESInterop:
    @classmethod
    @pytest.mark.parametrize(
        ("mode", "padding", "ciphertext"),
        [
            (constants.SymmetricMode.CBC, constants.SymmetricPadding.PKCS7, GO_AES_CBC_CIPHERTEXT),
            (constants.SymmetricMode.CTR, constants.SymmetricPadding.NONE, GO_AES_CTR_CIPHERTEXT),
        ],
    )
    def test_decrypt_bytes__reads_go_ciphertext(
        cls,
        mode: constants.SymmetricMode,
        padding: constants.SymmetricPadding,
        ciphertext: str,
    ) -> None:
        cipher = AESSymmetricCipher(key=AES_KEY, mode=mode, padding=padding)

        assert cipher.decrypt_bytes(ciphertext) == PLAINTEXT

    @classmethod
    @pytest.mark.parametrize(
        ("mode", "padding", "expected"),
        [
            (
                constants.SymmetricMode.CBC,
                constants.SymmetricPadding.PKCS7,
                PYTHON_AES_CBC_CIPHERTEXT_VERIFIED_BY_GO,
            ),
            (
                constants.SymmetricMode.CTR,
                constants.SymmetricPadding.NONE,
                PYTHON_AES_CTR_CIPHERTEXT_VERIFIED_BY_GO,
            ),
        ],
    )
    def test_encrypt_bytes__matches_vector_decrypted_by_go(
        cls,
        mode: constants.SymmetricMode,
        padding: constants.SymmetricPadding,
        expected: str,
    ) -> None:
        cipher = AESSymmetricCipher(
            key=AES_KEY,
            iv=bytes(range(16)),
            mode=mode,
            padding=padding,
        )

        assert cipher.encrypt_bytes(PLAINTEXT) == expected
