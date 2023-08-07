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

from bkcrypto.asymmetric.ciphers import BaseAsymmetricCipher
from bkcrypto.asymmetric.options import AsymmetricOptions
from bkcrypto.contrib.basic import ciphers
from bkcrypto.symmetric.ciphers import BaseSymmetricCipher
from bkcrypto.symmetric.options import SymmetricOptions

from .init_configs import AsymmetricCipherInitConfig, SymmetricCipherInitConfig
from .settings import crypto_settings


def get_asymmetric_cipher(
    cipher_type: typing.Optional[str] = None,
    common: typing.Optional[typing.Dict[str, typing.Any]] = None,
    cipher_options: typing.Optional[typing.Dict[str, typing.Optional[AsymmetricOptions]]] = None,
) -> BaseAsymmetricCipher:
    return ciphers.get_asymmetric_cipher(
        cipher_type=cipher_type or crypto_settings.ASYMMETRIC_CIPHER_TYPE,
        common=common,
        cipher_options=cipher_options,
        asymmetric__cipher_classes=crypto_settings.ASYMMETRIC_CIPHER_CLASSES,
    )


def get_symmetric_cipher(
    cipher_type: typing.Optional[str] = None,
    common: typing.Optional[typing.Dict[str, typing.Any]] = None,
    cipher_options: typing.Optional[typing.Dict[str, typing.Optional[SymmetricOptions]]] = None,
) -> BaseSymmetricCipher:
    return ciphers.get_symmetric_cipher(
        cipher_type=cipher_type or crypto_settings.ASYMMETRIC_CIPHER_TYPE,
        common=common,
        cipher_options=cipher_options,
        symmetric_cipher_classes=crypto_settings.SYMMETRIC_CIPHER_CLASSES,
    )


class SymmetricCipherManager:
    _cache: typing.Optional[typing.Dict[str, BaseSymmetricCipher]] = None

    def __init__(self):
        self._cache: [str, BaseSymmetricCipher] = {}

    def cipher(
        self, using: typing.Optional[str] = None, cipher_type: typing.Optional[str] = None
    ) -> BaseSymmetricCipher:

        using: str = using or "default"
        if using not in crypto_settings.SYMMETRIC_CIPHERS:
            raise RuntimeError(f"Invalid using {using}")

        cipher_type: str = cipher_type or crypto_settings.SYMMETRIC_CIPHER_TYPE
        cache_key: str = f"{using}-{cipher_type}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        init_config: SymmetricCipherInitConfig = crypto_settings.SYMMETRIC_CIPHERS[using]
        cipher: BaseSymmetricCipher = get_symmetric_cipher(**init_config.as_get_cipher_params(cipher_type))
        self._cache[cache_key] = cipher
        return cipher


class AsymmetricCipherManager:
    _cache: typing.Optional[typing.Dict[str, BaseAsymmetricCipher]] = None

    def __init__(self):
        self._cache: [str, BaseAsymmetricCipher] = {}

    def cipher(
        self, using: typing.Optional[str] = None, cipher_type: typing.Optional[str] = None
    ) -> BaseAsymmetricCipher:

        using: str = using or "default"
        if using not in crypto_settings.ASYMMETRIC_CIPHERS:
            raise RuntimeError(f"Invalid using {using}")

        cipher_type: str = cipher_type or crypto_settings.ASYMMETRIC_CIPHER_TYPE
        cache_key: str = f"{using}-{cipher_type}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        init_config: AsymmetricCipherInitConfig = crypto_settings.ASYMMETRIC_CIPHERS[using]
        cipher: BaseAsymmetricCipher = get_asymmetric_cipher(**init_config.as_get_cipher_params(cipher_type))
        self._cache[cache_key] = cipher
        return cipher


symmetric_cipher_manager = SymmetricCipherManager()


asymmetric_cipher_manager = AsymmetricCipherManager()
