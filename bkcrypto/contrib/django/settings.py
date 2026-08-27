"""TencentBlueKing is pleased to support the open source community.

蓝鲸智云 - crypto-python-sdk (BlueKing - crypto-python-sdk) is made available by
TencentBlueKing.

Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at
https://opensource.org/licenses/MIT.
Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""

import typing

from bkcrypto import constants
from bkcrypto.asymmetric.options import AsymmetricOptions
from bkcrypto.contrib.basic import ciphers as basic_ciphers
from bkcrypto.contrib.django.init_configs import (
    AsymmetricCipherInitConfig,
    CipherInitConfig,
    SymmetricCipherInitConfig,
)
from bkcrypto.symmetric.options import SymmetricOptions
from bkcrypto.utils import module_loding
from dacite import from_dict
from django.conf import settings
from django.test.signals import setting_changed

InitConfigT = typing.TypeVar("InitConfigT")
CipherClass = typing.Union[
    basic_ciphers.AsymmetricCipherClass,
    basic_ciphers.SymmetricCipherClass,
]


def _default_prefix(cipher_type: str) -> str:
    return f"{cipher_type.lower()}_str:::"


def _build_cipher_init_configs(
    value: dict[str, dict[str, typing.Any]],
    setting_name: str,
    cipher_classes: typing.Mapping[str, CipherClass],
    init_config_class: type[InitConfigT],
) -> dict[str, InitConfigT]:
    init_configs: dict[str, InitConfigT] = {}
    for using, init_config_params in value.items():
        prefix_cipher_type_map: dict[str, str] = {}
        db_prefix_map: dict[str, str] = init_config_params.get("db_prefix_map") or {}
        if any(
            not isinstance(cipher_type, str) or not isinstance(prefix, str)
            for cipher_type, prefix in db_prefix_map.items()
        ):
            raise TypeError(
                f"{setting_name}[{using!r}].db_prefix_map keys and values "
                "must be strings"
            )
        for cipher_type in cipher_classes:
            prefix = db_prefix_map.setdefault(
                cipher_type, f"{cipher_type.lower()}_str:::"
            )
            prefix_cipher_type_map[prefix] = cipher_type
        init_config_params["db_prefix_map"] = db_prefix_map
        init_config_params["prefix_cipher_type_map"] = prefix_cipher_type_map
        init_configs[using] = from_dict(init_config_class, init_config_params)
    return init_configs


DEFAULTS: dict[str, typing.Any] = {
    "SYMMETRIC_CIPHER_TYPE": constants.SymmetricCipherType.AES.value,
    "ASYMMETRIC_CIPHER_TYPE": constants.AsymmetricCipherType.RSA.value,
    "SYMMETRIC_CIPHER_CLASSES": dict(basic_ciphers.SYMMETRIC_CIPHER_CLASSES),
    "ASYMMETRIC_CIPHER_CLASSES": dict(basic_ciphers.ASYMMETRIC_CIPHER_CLASSES),
    "SYMMETRIC_CIPHERS": {
        "default": {
            # 可选，用于在 settings 没法直接获取 key 的情况
            "get_key_config": None,
            # 前缀和 cipher type 必须一一对应，且不能有前缀匹配关系
            "db_prefix_map": {
                constants.SymmetricCipherType.AES.value: _default_prefix(
                    constants.SymmetricCipherType.AES.value
                ),
                constants.SymmetricCipherType.SM4.value: _default_prefix(
                    constants.SymmetricCipherType.SM4.value
                ),
            },
        },
    },
    "ASYMMETRIC_CIPHERS": {
        "default": {
            # 可选，用于在 settings 没法直接获取 key 的情况
            "get_key_config": None,
            # 前缀和 cipher type 必须一一对应，且不能有前缀匹配关系
            "db_prefix_map": {
                constants.AsymmetricCipherType.RSA.value: _default_prefix(
                    constants.AsymmetricCipherType.RSA.value
                ),
                constants.AsymmetricCipherType.SM2.value: _default_prefix(
                    constants.AsymmetricCipherType.SM2.value
                ),
            },
        },
    },
}

IMPORT_STRINGS: list[str] = []

# List of settings that have been removed
REMOVED_SETTINGS: list[str] = []


def perform_import(val: object, setting_name: str) -> object:
    """Import one or more values expressed as dotted paths.

    Return non-string values unchanged.
    """
    if val is None:
        return None
    if isinstance(val, str):
        return import_from_string(val, setting_name)
    if isinstance(val, (list, tuple)):
        return [import_from_string(item, setting_name) for item in val]
    return val


def import_from_string(val: str, setting_name: str) -> object:
    """Attempt to import a class from a string representation."""
    try:
        return module_loding.import_string(val)
    except ImportError as err:
        message = (
            f"Could not import {val!r} for API setting {setting_name!r}. "
            f"{err.__class__.__name__}: {err}."
        )
        raise ImportError(message) from err


class CryptoSettings:
    """Resolve, normalize, and cache project-level crypto settings."""

    SYMMETRIC_CIPHER_TYPE: str
    ASYMMETRIC_CIPHER_TYPE: str
    SYMMETRIC_CIPHER_CLASSES: dict[str, basic_ciphers.SymmetricCipherClass]
    ASYMMETRIC_CIPHER_CLASSES: dict[str, basic_ciphers.AsymmetricCipherClass]
    SYMMETRIC_CIPHERS: dict[str, CipherInitConfig[SymmetricOptions]]
    ASYMMETRIC_CIPHERS: dict[str, CipherInitConfig[AsymmetricOptions]]

    def __init__(
        self,
        user_settings: typing.Optional[dict[str, typing.Any]] = None,
        defaults: typing.Optional[dict[str, typing.Any]] = None,
        import_strings: typing.Optional[list[str]] = None,
    ) -> None:
        if user_settings:
            self._user_settings = self.__check_user_settings(user_settings)
        self.defaults = defaults or DEFAULTS
        self.import_strings = import_strings or IMPORT_STRINGS
        self._cached_attrs: set[str] = set()

    @property
    def user_settings(self) -> dict[str, typing.Any]:
        if not hasattr(self, "_user_settings"):
            raw_user_settings: typing.Any = getattr(settings, "BKCRYPTO", {})
            if not isinstance(raw_user_settings, dict):
                raise TypeError("BKCRYPTO must be a dictionary")
            self._user_settings = raw_user_settings
        return self._user_settings

    def __getattr__(self, attr: str) -> object:
        if attr not in self.defaults:
            raise AttributeError(f"Invalid API setting: {attr}")

        try:
            # Check if present in user settings
            val = self.user_settings[attr]
        except KeyError:
            # Fall back to defaults
            val = self.defaults[attr]

        if attr == "SYMMETRIC_CIPHERS":
            val = _build_cipher_init_configs(
                val,
                attr,
                self.SYMMETRIC_CIPHER_CLASSES,
                SymmetricCipherInitConfig,
            )
        elif attr == "ASYMMETRIC_CIPHERS":
            val = _build_cipher_init_configs(
                val,
                attr,
                self.ASYMMETRIC_CIPHER_CLASSES,
                AsymmetricCipherInitConfig,
            )

        # Coerce import strings into classes
        if attr in self.import_strings:
            val = perform_import(val, attr)

        # Cache the result
        self._cached_attrs.add(attr)
        setattr(self, attr, val)
        return val

    @staticmethod
    def __check_user_settings(
        user_settings: dict[str, object],
    ) -> dict[str, typing.Any]:
        for setting in REMOVED_SETTINGS:
            if setting in user_settings:
                raise RuntimeError(
                    f"The {setting} setting has been removed. Please refer to [doc] "
                    "for available settings."
                )
        return user_settings

    def reload(self) -> None:
        for attr in self._cached_attrs:
            delattr(self, attr)
        self._cached_attrs.clear()
        if hasattr(self, "_user_settings"):
            del self._user_settings


crypto_settings = CryptoSettings(defaults=DEFAULTS, import_strings=IMPORT_STRINGS)


def reload_api_settings(*args: object, **kwargs: object) -> None:
    """Reload crypto settings after Django's ``BKCRYPTO`` setting changes."""
    setting: object = kwargs["setting"]
    if setting == "BKCRYPTO":
        crypto_settings.reload()


setting_changed.connect(reload_api_settings)
