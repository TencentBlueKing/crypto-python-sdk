import base64

import pytest
from bkcrypto import constants
from bkcrypto.asymmetric.ciphers import RSAAsymmetricCipher
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class TestRSASerialization:
    @classmethod
    def test_generate_key_pair__uses_bk_kms_formats(cls) -> None:
        cipher = RSAAsymmetricCipher()
        public_key = serialization.load_pem_public_key(
            cipher.export_public_key().encode()
        )
        private_key = serialization.load_pem_private_key(
            cipher.export_private_key().encode(), password=None
        )

        assert isinstance(public_key, rsa.RSAPublicKey)
        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert public_key.key_size == 2048
        assert public_key.public_numbers().e == 65537
        assert private_key.public_key().public_numbers() == public_key.public_numbers()
        assert cipher.export_public_key().startswith("-----BEGIN PUBLIC KEY-----")
        assert cipher.export_private_key().startswith("-----BEGIN RSA PRIVATE KEY-----")

    @classmethod
    def test_load_private_key__accepts_pkcs1_and_pkcs8(
        cls, rsa_private_key: str
    ) -> None:
        private_key = serialization.load_pem_private_key(
            rsa_private_key.encode(), password=None
        )
        assert isinstance(private_key, rsa.RSAPrivateKey)
        pkcs8_private_key: str = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        pkcs1_cipher = RSAAsymmetricCipher(private_key_string=rsa_private_key)
        pkcs8_cipher = RSAAsymmetricCipher(private_key_string=pkcs8_private_key)

        for cipher in (pkcs1_cipher, pkcs8_cipher):
            assert cipher.decrypt(cipher.encrypt("key format")) == "key format"
            assert cipher.export_private_key().startswith(
                "-----BEGIN RSA PRIVATE KEY-----"
            )

    @classmethod
    def test_load_public_key__keeps_private_key_input_compatible(
        cls, rsa_private_key: str
    ) -> None:
        private_cipher = RSAAsymmetricCipher(private_key_string=rsa_private_key)
        public_cipher = RSAAsymmetricCipher(public_key_string=rsa_private_key)
        ciphertext = public_cipher.encrypt("private PEM as public input")

        assert private_cipher.decrypt(ciphertext) == "private PEM as public input"
        assert public_cipher.export_public_key() == private_cipher.export_public_key()

    @classmethod
    def test_load_public_key__accepts_openssh_format(cls, rsa_private_key: str) -> None:
        private_cipher = RSAAsymmetricCipher(private_key_string=rsa_private_key)
        public_key = serialization.load_pem_public_key(
            private_cipher.export_public_key().encode()
        )
        assert isinstance(public_key, rsa.RSAPublicKey)
        openssh_public_key: str = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        ).decode()

        public_cipher = RSAAsymmetricCipher(public_key_string=openssh_public_key)
        ciphertext = public_cipher.encrypt("OpenSSH public key")

        assert private_cipher.decrypt(ciphertext) == "OpenSSH public key"
        assert public_cipher.export_public_key() == private_cipher.export_public_key()

    @classmethod
    @pytest.mark.parametrize(
        ("argument", "value"),
        [
            ("public_key_string", "invalid public key"),
            ("private_key_string", "invalid private key"),
        ],
    )
    def test_load_key__rejects_invalid_pem(cls, argument: str, value: str) -> None:
        with pytest.raises(ValueError, match="Invalid RSA"):
            RSAAsymmetricCipher(**{argument: value})


class TestRSALegacyAPI:
    @classmethod
    def test_block_list__accepts_legacy_lst_keyword(cls) -> None:
        blocks = RSAAsymmetricCipher.block_list(lst=b"abc", block_size=2)

        assert list(blocks) == [b"ab", b"c"]

    @classmethod
    def test_decrypt__requires_private_key(cls, rsa_private_key: str) -> None:
        private_cipher = RSAAsymmetricCipher(private_key_string=rsa_private_key)
        cipher = RSAAsymmetricCipher(
            public_key_string=private_cipher.export_public_key()
        )
        ciphertext = cipher.encrypt("message")

        with pytest.raises(ValueError, match="call decrypt"):
            cipher.decrypt(ciphertext)

    @classmethod
    def test_sign__requires_private_key(cls, rsa_private_key: str) -> None:
        private_cipher = RSAAsymmetricCipher(private_key_string=rsa_private_key)
        cipher = RSAAsymmetricCipher(
            public_key_string=private_cipher.export_public_key()
        )

        with pytest.raises(ValueError, match="call sign"):
            cipher.sign("message")

    @classmethod
    def test_sign__returns_boolean_verification_result(
        cls, rsa_private_key: str
    ) -> None:
        cipher = RSAAsymmetricCipher(private_key_string=rsa_private_key)
        signature = cipher.sign("message")

        assert cipher.verify("message", signature)
        assert not cipher.verify("other", signature)

    @classmethod
    @pytest.mark.compatibility
    def test_encrypt__keeps_segmented_pkcs1_v1_5_roundtrip(
        cls, rsa_private_key: str
    ) -> None:
        cipher = RSAAsymmetricCipher(private_key_string=rsa_private_key)
        plaintext = "中英文 mixed text " * 80

        assert cipher.decrypt(cipher.encrypt(plaintext)) == plaintext

    @classmethod
    def test_encrypt__can_disable_segmented_encryption(
        cls, rsa_private_key: str
    ) -> None:
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

        with pytest.raises(ValueError, match="base64"):
            cipher.decrypt("not base64 %%%")


class TestRSAOAEP:
    @classmethod
    def make_cipher(cls, rsa_private_key: str, **options) -> RSAAsymmetricCipher:
        return RSAAsymmetricCipher(
            private_key_string=rsa_private_key,
            padding=constants.RSACipherPadding.PKCS1_OAEP,
            oaep_hash=hashes.SHA256(),
            mgf1_hash=hashes.SHA256(),
            **options,
        )

    @classmethod
    def test_encrypt_bytes__roundtrips_sha256_and_mgf1_sha256(
        cls, rsa_private_key: str
    ) -> None:
        cipher = cls.make_cipher(rsa_private_key)
        plaintext = b"\x00\xffBK-KMS data key\x80"

        assert cipher.decrypt_bytes(cipher.encrypt_bytes(plaintext)) == plaintext

    @classmethod
    def test_encrypt_bytes__enforces_oaep_sha256_boundary(
        cls, rsa_private_key: str
    ) -> None:
        cipher = cls.make_cipher(rsa_private_key)

        assert cipher.decrypt_bytes(cipher.encrypt_bytes(b"x" * 190)) == b"x" * 190
        with pytest.raises(ValueError, match="too long"):
            cipher.encrypt_bytes(b"x" * 191)

    @classmethod
    def test_decrypt_bytes__requires_one_modulus_block(
        cls, rsa_private_key: str
    ) -> None:
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
        with pytest.raises(ValueError, match="Incorrect decryption"):
            cls.make_cipher(rsa_private_key, oaep_label=b"other").decrypt_bytes(
                ciphertext
            )
