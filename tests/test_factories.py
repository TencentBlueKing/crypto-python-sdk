from Cryptodome.Hash import SHA256

from bkcrypto import constants
from bkcrypto.asymmetric.options import RSAAsymmetricOptions
from bkcrypto.contrib.basic.ciphers import get_asymmetric_cipher, get_symmetric_cipher
from bkcrypto.symmetric.options import AESSymmetricOptions


class TestBasicFactory:
    @classmethod
    def test_get_asymmetric_cipher__supports_hash_module_options(cls, rsa_private_key: str) -> None:
        cipher = get_asymmetric_cipher(
            cipher_options={
                constants.AsymmetricCipherType.RSA.value: RSAAsymmetricOptions(
                    private_key_string=rsa_private_key,
                    padding=constants.RSACipherPadding.PKCS1_OAEP,
                    oaep_hash=SHA256,
                    mgf1_hash=SHA256,
                )
            }
        )

        assert cipher.decrypt_bytes(cipher.encrypt_bytes(b"factory")) == b"factory"

    @classmethod
    def test_get_symmetric_cipher__keeps_common_options_priority(cls, aes_key: bytes) -> None:
        cipher = get_symmetric_cipher(
            common={"key": aes_key, "mode": constants.SymmetricMode.CTR},
            cipher_options={
                constants.SymmetricCipherType.AES.value: AESSymmetricOptions(mode=constants.SymmetricMode.CBC)
            },
        )

        assert cipher.config.mode == constants.SymmetricMode.CTR
        assert cipher.decrypt(cipher.encrypt("factory")) == "factory"
