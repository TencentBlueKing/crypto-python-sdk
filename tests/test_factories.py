import typing

import pytest
from bkcrypto import constants
from bkcrypto.asymmetric.options import RSAAsymmetricOptions
from bkcrypto.contrib.basic.ciphers import get_asymmetric_cipher, get_symmetric_cipher
from bkcrypto.contrib.django.init_configs import SymmetricCipherInitConfig
from bkcrypto.contrib.django.settings import DEFAULTS, CryptoSettings
from bkcrypto.symmetric.options import AESSymmetricOptions
from Cryptodome.Hash import SHA256


class TestBasicFactory:
    @classmethod
    def test_get_symmetric_cipher__rejects_non_cipher_class(cls) -> None:
        invalid_cipher_classes: typing.Any = {
            constants.SymmetricCipherType.AES.value: object()
        }
        with pytest.raises(TypeError, match="must be a class"):
            get_symmetric_cipher(symmetric_cipher_classes=invalid_cipher_classes)

    @classmethod
    def test_get_asymmetric_cipher__supports_hash_module_options(
        cls, rsa_private_key: str
    ) -> None:
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
    def test_get_symmetric_cipher__keeps_common_options_priority(
        cls, aes_key: bytes
    ) -> None:
        cipher = get_symmetric_cipher(
            common={"key": aes_key, "mode": constants.SymmetricMode.CTR},
            cipher_options={
                constants.SymmetricCipherType.AES.value: AESSymmetricOptions(
                    mode=constants.SymmetricMode.CBC
                )
            },
        )

        assert cipher.config.mode == constants.SymmetricMode.CTR
        assert cipher.decrypt(cipher.encrypt("factory")) == "factory"


class TestDjangoFactory:
    @classmethod
    def test_init_config__passes_plain_mapping_to_factory(cls, aes_key: bytes) -> None:
        init_config = SymmetricCipherInitConfig(common={"key": aes_key})

        params = init_config.as_get_cipher_params(
            constants.SymmetricCipherType.AES.value
        )
        cipher = get_symmetric_cipher(**params)

        assert isinstance(params, dict)
        assert cipher.decrypt(cipher.encrypt("factory mapping")) == "factory mapping"

    @classmethod
    def test_init_config__rejects_non_callable_key_factory(cls) -> None:
        with pytest.raises(TypeError, match="must be callable"):
            SymmetricCipherInitConfig(
                get_key_config="bkcrypto.contrib.django.settings.DEFAULTS"
            )

    @classmethod
    def test_init_config__rejects_invalid_key_factory_result(cls) -> None:
        init_config = SymmetricCipherInitConfig(get_key_config="builtins.str")

        with pytest.raises(TypeError, match="returned an invalid config"):
            init_config.as_get_cipher_params(constants.SymmetricCipherType.AES.value)

    @classmethod
    def test_settings__builds_typed_symmetric_init_config(cls) -> None:
        crypto_settings = CryptoSettings(
            user_settings={"SYMMETRIC_CIPHERS": DEFAULTS["SYMMETRIC_CIPHERS"]},
            defaults=DEFAULTS,
        )

        init_config = crypto_settings.SYMMETRIC_CIPHERS["default"]

        assert isinstance(init_config, SymmetricCipherInitConfig)
        assert init_config.db_prefix_map["AES"] == "aes_str:::"

    @classmethod
    def test_settings__rejects_non_string_prefix(cls) -> None:
        crypto_settings = CryptoSettings(
            user_settings={
                "SYMMETRIC_CIPHERS": {"default": {"db_prefix_map": {"AES": 123}}}
            },
            defaults=DEFAULTS,
        )

        with pytest.raises(TypeError, match="values must be strings"):
            _ = crypto_settings.SYMMETRIC_CIPHERS
