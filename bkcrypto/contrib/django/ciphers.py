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

import abc
import typing

from bkcrypto.asymmetric.ciphers import AsymmetricCipher
from bkcrypto.asymmetric.options import AsymmetricOptions
from bkcrypto.contrib.basic import ciphers
from bkcrypto.symmetric.ciphers import SymmetricCipher
from bkcrypto.symmetric.options import SymmetricOptions

from .init_configs import CipherInitConfig
from .settings import crypto_settings

CipherT = typing.TypeVar("CipherT", AsymmetricCipher, SymmetricCipher)
CipherOptionT = typing.TypeVar(
    "CipherOptionT", bound=typing.Union[AsymmetricOptions, SymmetricOptions]
)


def get_asymmetric_cipher(
    cipher_type: typing.Optional[str] = None,
    common: typing.Optional[dict[str, typing.Any]] = None,
    cipher_options: typing.Optional[
        dict[str, typing.Optional[AsymmetricOptions]]
    ] = None,
) -> AsymmetricCipher:
    """Build an asymmetric cipher using Django settings as defaults."""
    return ciphers.get_asymmetric_cipher(
        cipher_type=cipher_type or crypto_settings.ASYMMETRIC_CIPHER_TYPE,
        common=common,
        cipher_options=cipher_options,
        asymmetric__cipher_classes=crypto_settings.ASYMMETRIC_CIPHER_CLASSES,
    )


def get_symmetric_cipher(
    cipher_type: typing.Optional[str] = None,
    common: typing.Optional[dict[str, typing.Any]] = None,
    cipher_options: typing.Optional[dict[str, typing.Optional[SymmetricOptions]]] = None,
) -> SymmetricCipher:
    """Build a symmetric cipher using Django settings as defaults."""
    return ciphers.get_symmetric_cipher(
        cipher_type=cipher_type or crypto_settings.SYMMETRIC_CIPHER_TYPE,
        common=common,
        cipher_options=cipher_options,
        symmetric_cipher_classes=crypto_settings.SYMMETRIC_CIPHER_CLASSES,
    )


class BaseCipherManager(abc.ABC, typing.Generic[CipherT, CipherOptionT]):
    """Cache configured cipher instances by alias and algorithm."""

    _cache: dict[str, CipherT]

    def __init__(self) -> None:
        self._cache = {}

    def _get_init_config(
        self, using: typing.Optional[str] = None
    ) -> CipherInitConfig[CipherOptionT]:
        selected_using: str = using or "default"
        init_configs: dict[str, CipherInitConfig[CipherOptionT]] = (
            self._get_init_configs_from_settings()
        )
        if selected_using not in init_configs:
            raise RuntimeError(f"Invalid using {selected_using}")
        return init_configs[selected_using]

    @staticmethod
    @abc.abstractmethod
    def _get_init_configs_from_settings() -> dict[str, CipherInitConfig[CipherOptionT]]:
        raise NotImplementedError

    @staticmethod
    @abc.abstractmethod
    def _get_cipher_type_from_settings() -> str:
        raise NotImplementedError

    @staticmethod
    @abc.abstractmethod
    def _get_cipher(
        cipher_type: str, init_config: CipherInitConfig[CipherOptionT]
    ) -> CipherT:
        raise NotImplementedError

    def _cipher(
        self,
        using: typing.Optional[str] = None,
        cipher_type: typing.Optional[str] = None,
    ) -> CipherT:

        # try to get cipher from cache
        selected_using: str = using or "default"
        selected_cipher_type: str = cipher_type or self._get_cipher_type_from_settings()
        cache_key: str = f"{selected_using}-{selected_cipher_type}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # create & cache instance
        init_config = self._get_init_config(using=selected_using)
        self._cache[cache_key] = self._get_cipher(selected_cipher_type, init_config)
        return self._cache[cache_key]

    @abc.abstractmethod
    def cipher(
        self,
        using: typing.Optional[str] = None,
        cipher_type: typing.Optional[str] = None,
    ) -> CipherT:
        raise NotImplementedError


class SymmetricCipherManager(BaseCipherManager[SymmetricCipher, SymmetricOptions]):
    """Cache symmetric cipher instances configured through Django settings."""

    @staticmethod
    def _get_init_configs_from_settings() -> dict[
        str, CipherInitConfig[SymmetricOptions]
    ]:
        return crypto_settings.SYMMETRIC_CIPHERS

    @staticmethod
    def _get_cipher_type_from_settings() -> str:
        return crypto_settings.SYMMETRIC_CIPHER_TYPE

    @staticmethod
    def _get_cipher(
        cipher_type: str, init_config: CipherInitConfig[SymmetricOptions]
    ) -> SymmetricCipher:
        params = init_config.as_get_cipher_params(cipher_type)
        return get_symmetric_cipher(**params)

    def cipher(
        self,
        using: typing.Optional[str] = None,
        cipher_type: typing.Optional[str] = None,
    ) -> SymmetricCipher:
        return self._cipher(using, cipher_type)


class AsymmetricCipherManager(BaseCipherManager[AsymmetricCipher, AsymmetricOptions]):
    """Cache asymmetric cipher instances configured through Django settings."""

    @staticmethod
    def _get_init_configs_from_settings() -> dict[
        str, CipherInitConfig[AsymmetricOptions]
    ]:
        return crypto_settings.ASYMMETRIC_CIPHERS

    @staticmethod
    def _get_cipher_type_from_settings() -> str:
        return crypto_settings.ASYMMETRIC_CIPHER_TYPE

    @staticmethod
    def _get_cipher(
        cipher_type: str, init_config: CipherInitConfig[AsymmetricOptions]
    ) -> AsymmetricCipher:
        params = init_config.as_get_cipher_params(cipher_type)
        return get_asymmetric_cipher(**params)

    def cipher(
        self,
        using: typing.Optional[str] = None,
        cipher_type: typing.Optional[str] = None,
    ) -> AsymmetricCipher:
        return self._cipher(using, cipher_type)


symmetric_cipher_manager = SymmetricCipherManager()


asymmetric_cipher_manager = AsymmetricCipherManager()
