# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making 蓝鲸智云 - crypto-python-sdk
(BlueKing - crypto-python-sdk) available.
Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
import typing

from dacite import from_dict
from django.conf import settings
from django.test.signals import setting_changed

from bkcrypto import constants
from bkcrypto.asymmetric.ciphers import RSAAsymmetricCipher, SM2AsymmetricCipher
from bkcrypto.contrib.django.init_configs import AsymmetricCipherInitConfig, CipherInitConfig, SymmetricCipherInitConfig
from bkcrypto.symmetric.ciphers import AESSymmetricCipher, SM4SymmetricCipher
from bkcrypto.utils import module_loding

DEFAULTS = {
    "SYMMETRIC_CIPHER_TYPE": constants.SymmetricCipherType.AES.value,
    "ASYMMETRIC_CIPHER_TYPE": constants.AsymmetricCipherType.RSA.value,
    "SYMMETRIC_CIPHER_CLASSES": {
        constants.SymmetricCipherType.AES.value: module_loding.get_import_path(AESSymmetricCipher),
        constants.SymmetricCipherType.SM4.value: module_loding.get_import_path(SM4SymmetricCipher),
    },
    "ASYMMETRIC_CIPHER_CLASSES": {
        constants.AsymmetricCipherType.RSA.value: module_loding.get_import_path(RSAAsymmetricCipher),
        constants.AsymmetricCipherType.SM2.value: module_loding.get_import_path(SM2AsymmetricCipher),
    },
    "SYMMETRIC_CIPHERS": {
        "default": {
            # 可选，用于在 settings 没法直接获取 key 的情况
            "get_key_config": None,
            # 前缀和 cipher type 必须一一对应，且不能有前缀匹配关系
            "db_prefix_map": {
                constants.SymmetricCipherType.AES.value: f"{constants.SymmetricCipherType.AES.value.lower()}_str:::",
                constants.SymmetricCipherType.SM4.value: f"{constants.SymmetricCipherType.SM4.value.lower()}_str:::",
            },
        },
    },
    "ASYMMETRIC_CIPHERS": {
        "default": {
            # 可选，用于在 settings 没法直接获取 key 的情况
            "get_key_config": None,
            # 前缀和 cipher type 必须一一对应，且不能有前缀匹配关系
            "db_prefix_map": {
                constants.AsymmetricCipherType.RSA.value: f"{constants.AsymmetricCipherType.RSA.value.lower()}_str:::",
                constants.AsymmetricCipherType.SM2.value: f"{constants.AsymmetricCipherType.SM2.value.lower()}_str:::",
            },
        },
    },
}

IMPORT_STRINGS = []

# List of settings that have been removed
REMOVED_SETTINGS = []


def perform_import(val, setting_name):
    """
    If the given setting is a string import notation,
    then perform the necessary import or imports.
    """
    if val is None:
        return None
    elif isinstance(val, str):
        return import_from_string(val, setting_name)
    elif isinstance(val, (list, tuple)):
        return [import_from_string(item, setting_name) for item in val]
    return val


def import_from_string(val, setting_name):
    """
    Attempt to import a class from a string representation.
    """
    try:
        return module_loding.import_string(val)
    except ImportError as e:
        msg = "Could not import '%s' for API setting '%s'. %s: %s." % (val, setting_name, e.__class__.__name__, e)
        raise ImportError(msg)


class CryptoSettings:
    def __init__(self, user_settings=None, defaults=None, import_strings=None):
        if user_settings:
            self._user_settings = self.__check_user_settings(user_settings)
        self.defaults = defaults or DEFAULTS
        self.import_strings = import_strings or IMPORT_STRINGS
        self._cached_attrs = set()

    @property
    def user_settings(self):
        if not hasattr(self, "_user_settings"):
            self._user_settings = getattr(settings, "BKCRYPTO", {})
        return self._user_settings

    def __getattr__(self, attr):
        if attr not in self.defaults:
            raise AttributeError(f"Invalid API setting: {attr}")

        try:
            # Check if present in user settings
            val = self.user_settings[attr]
        except KeyError:
            # Fall back to defaults
            val = self.defaults[attr]

        if attr in ["SYMMETRIC_CIPHER_CLASSES", "ASYMMETRIC_CIPHER_CLASSES"]:
            val = {
                cipher_type: module_loding.import_string(cipher_import_path)
                for cipher_type, cipher_import_path in val.items()
            }

        if attr in ["SYMMETRIC_CIPHERS", "ASYMMETRIC_CIPHERS"]:
            using__init_config_map: typing.Dict[str, CipherInitConfig] = {}
            for using, init_config_params in val.items():
                prefix_cipher_type_map: typing.Dict[str, str] = {}
                db_prefix_map: typing.Dict[str, str] = init_config_params.get("db_prefix_map") or {}
                cipher_types: typing.List[str] = [
                    self.SYMMETRIC_CIPHER_CLASSES.keys(),
                    self.ASYMMETRIC_CIPHER_CLASSES.keys(),
                ][attr == "ASYMMETRIC_CIPHERS"]
                for cipher_type in cipher_types:
                    if cipher_type in db_prefix_map:
                        prefix_cipher_type_map[db_prefix_map[cipher_type]] = cipher_type
                        continue
                    db_prefix_map[cipher_type] = f"{cipher_type.lower()}_str:::"
                    prefix_cipher_type_map[f"{cipher_type.lower()}_str:::"] = cipher_type
                init_config_params["db_prefix_map"] = db_prefix_map
                init_config_params["prefix_cipher_type_map"] = prefix_cipher_type_map
                using__init_config_map[using] = from_dict(
                    [SymmetricCipherInitConfig, AsymmetricCipherInitConfig][attr == "ASYMMETRIC_CIPHER_CLASSES"],
                    init_config_params,
                )
            val = using__init_config_map

        # Coerce import strings into classes
        if attr in self.import_strings:
            val = perform_import(val, attr)

        # Cache the result
        self._cached_attrs.add(attr)
        setattr(self, attr, val)
        return val

    def __check_user_settings(self, user_settings):
        for setting in REMOVED_SETTINGS:
            if setting in user_settings:
                raise RuntimeError(
                    f"The {setting} setting has been removed. Please refer to [doc] for available settings."
                )
        return user_settings

    def reload(self):
        for attr in self._cached_attrs:
            delattr(self, attr)
        self._cached_attrs.clear()
        if hasattr(self, "_user_settings"):
            delattr(self, "_user_settings")


crypto_settings = CryptoSettings(None, DEFAULTS, IMPORT_STRINGS)


def reload_api_settings(*args, **kwargs):
    setting = kwargs["setting"]
    if setting == "BKCRYPTO":
        crypto_settings.reload()


setting_changed.connect(reload_api_settings)
