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
import abc
import typing

from bkcrypto.asymmetric.ciphers import BaseAsymmetricCipher
from bkcrypto.asymmetric.options import AsymmetricOptions
from bkcrypto.contrib.basic import ciphers
from bkcrypto.symmetric.ciphers import BaseSymmetricCipher
from bkcrypto.symmetric.options import SymmetricOptions

from .init_configs import CipherInitConfig
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
        cipher_type=cipher_type or crypto_settings.SYMMETRIC_CIPHER_TYPE,
        common=common,
        cipher_options=cipher_options,
        symmetric_cipher_classes=crypto_settings.SYMMETRIC_CIPHER_CLASSES,
    )


class BaseCipherManager(abc.ABC):

    _cache: typing.Dict[str, typing.Any] = None

    def __init__(self):
        self._cache = {}

    def _get_init_config(self, using: typing.Optional[str] = None) -> CipherInitConfig:
        using: str = using or "default"
        init_configs: typing.Dict[str, CipherInitConfig] = self._get_init_configs_from_settings()
        if using not in init_configs:
            raise RuntimeError(f"Invalid using {using}")
        return init_configs[using]

    @abc.abstractmethod
    def _get_init_configs_from_settings(self) -> typing.Dict[str, CipherInitConfig]:
        raise NotImplementedError

    @abc.abstractmethod
    def _get_cipher_type_from_settings(self) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def _get_cipher(self, cipher_type: str, init_config: CipherInitConfig):
        raise NotImplementedError

    def _cipher(self, using: typing.Optional[str] = None, cipher_type: typing.Optional[str] = None):

        # try to get cipher from cache
        cipher_type: str = cipher_type or self._get_cipher_type_from_settings()
        cache_key: str = f"{using}-{cipher_type}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # create & cache instance
        init_config: CipherInitConfig = self._get_init_config(using=using)
        self._cache[cache_key] = self._get_cipher(cipher_type, init_config)
        return self._cache[cache_key]

    @abc.abstractmethod
    def cipher(self, using: typing.Optional[str] = None, cipher_type: typing.Optional[str] = None):
        raise NotImplementedError


class SymmetricCipherManager(BaseCipherManager):

    _cache: typing.Optional[typing.Dict[str, BaseSymmetricCipher]] = None

    def _get_init_configs_from_settings(self) -> typing.Dict[str, CipherInitConfig]:
        return crypto_settings.SYMMETRIC_CIPHERS

    def _get_cipher_type_from_settings(self) -> str:
        return crypto_settings.SYMMETRIC_CIPHER_TYPE

    def _get_cipher(self, cipher_type: str, init_config: CipherInitConfig) -> BaseSymmetricCipher:
        return get_symmetric_cipher(**init_config.as_get_cipher_params(cipher_type))

    def cipher(
        self, using: typing.Optional[str] = None, cipher_type: typing.Optional[str] = None
    ) -> BaseSymmetricCipher:
        return self._cipher(using, cipher_type)


class AsymmetricCipherManager(BaseCipherManager):

    _cache: typing.Optional[typing.Dict[str, BaseAsymmetricCipher]] = None

    def _get_init_configs_from_settings(self) -> typing.Dict[str, CipherInitConfig]:
        return crypto_settings.ASYMMETRIC_CIPHERS

    def _get_cipher_type_from_settings(self) -> str:
        return crypto_settings.ASYMMETRIC_CIPHER_TYPE

    def _get_cipher(self, cipher_type: str, init_config: CipherInitConfig) -> BaseAsymmetricCipher:
        return get_asymmetric_cipher(**init_config.as_get_cipher_params(cipher_type))

    def cipher(
        self, using: typing.Optional[str] = None, cipher_type: typing.Optional[str] = None
    ) -> BaseAsymmetricCipher:
        return self._cipher(using, cipher_type)


symmetric_cipher_manager = SymmetricCipherManager()


asymmetric_cipher_manager = AsymmetricCipherManager()
