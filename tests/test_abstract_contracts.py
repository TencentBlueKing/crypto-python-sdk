import inspect

import pytest
from bkcrypto.asymmetric.ciphers.base import (
    BaseAsymmetricCipher,
    BaseAsymmetricRuntimeConfig,
)
from bkcrypto.asymmetric.ciphers.rsa import RSAAsymmetricCipher
from bkcrypto.asymmetric.ciphers.sm2 import SM2AsymmetricCipher
from bkcrypto.contrib.django.ciphers import (
    AsymmetricCipherManager,
    BaseCipherManager,
    SymmetricCipherManager,
)
from bkcrypto.contrib.django.fields import SymmetricTextField
from bkcrypto.contrib.django.selectors import (
    AsymmetricCipherSelectorMixin,
    CipherSelectorMixin,
    SymmetricCipherSelectorMixin,
)
from bkcrypto.symmetric.ciphers.base import (
    BaseSymmetricCipher,
    BaseSymmetricRuntimeConfig,
)


@pytest.mark.parametrize(
    "abstract_class",
    [
        BaseAsymmetricCipher,
        BaseSymmetricCipher,
        BaseCipherManager,
        CipherSelectorMixin,
    ],
)
def test_abstract_classes__use_abc_meta(abstract_class: type[object]) -> None:
    assert inspect.isabstract(abstract_class)


def test_base_ciphers__keep_default_runtime_config_classes() -> None:
    assert vars(BaseAsymmetricCipher)["CONFIG_DATA_CLASS"] is BaseAsymmetricRuntimeConfig
    assert vars(BaseSymmetricCipher)["CONFIG_DATA_CLASS"] is BaseSymmetricRuntimeConfig


@pytest.mark.parametrize(
    "method_name",
    [
        "_get_init_configs_from_settings",
        "_get_cipher_type_from_settings",
        "_get_cipher",
    ],
)
def test_cipher_managers__keep_static_method_contract(method_name: str) -> None:
    assert isinstance(BaseCipherManager.__dict__[method_name], staticmethod)
    assert isinstance(SymmetricCipherManager.__dict__[method_name], staticmethod)
    assert isinstance(AsymmetricCipherManager.__dict__[method_name], staticmethod)


@pytest.mark.parametrize("method_name", ["_load_public_key", "_load_private_key"])
def test_asymmetric_ciphers__keep_instance_method_contract(method_name: str) -> None:
    assert not isinstance(BaseAsymmetricCipher.__dict__[method_name], staticmethod)
    assert not isinstance(RSAAsymmetricCipher.__dict__[method_name], staticmethod)
    assert not isinstance(SM2AsymmetricCipher.__dict__[method_name], staticmethod)


def test_cipher_selectors__keep_static_method_contract() -> None:
    method_name = "_get_cipher_type_from_settings"
    assert isinstance(CipherSelectorMixin.__dict__[method_name], staticmethod)
    assert isinstance(SymmetricCipherSelectorMixin.__dict__[method_name], staticmethod)
    assert isinstance(AsymmetricCipherSelectorMixin.__dict__[method_name], staticmethod)


def test_symmetric_text_field__uses_runtime_django_field_base() -> None:
    field = SymmetricTextField()

    _, import_path, args, kwargs = field.deconstruct()

    assert import_path == "bkcrypto.contrib.django.fields.SymmetricTextField"
    assert args == []
    assert kwargs["using"] == "default"
