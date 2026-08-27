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
from bkcrypto.contrib.django.ciphers import (
    asymmetric_cipher_manager,
    symmetric_cipher_manager,
)
from bkcrypto.contrib.django.init_configs import CipherInitConfig
from bkcrypto.contrib.django.settings import crypto_settings
from bkcrypto.symmetric.ciphers.base import SymmetricCipher
from bkcrypto.symmetric.options import SymmetricOptions

CipherOptionT = typing.TypeVar(
    "CipherOptionT", bound=typing.Union[AsymmetricOptions, SymmetricOptions]
)


class CipherSelectorMixin(abc.ABC, typing.Generic[CipherOptionT]):
    """Select ciphers and prefixes for transparent field encryption."""

    init_config: typing.Optional[CipherInitConfig[CipherOptionT]] = None

    # 是否指定固定前缀，如果不为 None，密文将统一使用 prefix 作为前缀
    prefix: typing.Optional[str] = None
    # 指定对称加密实例，默认使用 `default`
    using: str = "default"

    @staticmethod
    @abc.abstractmethod
    def _get_cipher_type_from_settings() -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def get_cipher(
        self, cipher_type: typing.Optional[str] = None
    ) -> typing.Union[AsymmetricCipher, SymmetricCipher]:
        raise NotImplementedError

    @abc.abstractmethod
    def get_init_config(self) -> CipherInitConfig[CipherOptionT]:
        raise NotImplementedError

    def prefix_selector(
        self, ciphertext_with_prefix: str
    ) -> tuple[bool, str, typing.Optional[str]]:
        """Match a ciphertext prefix and extract its cipher type.

        :param ciphertext_with_prefix: Stored value that may start with a known prefix.
        :return: Match status, ciphertext without the prefix, and matched cipher type.
        """
        if self.prefix is not None:
            if ciphertext_with_prefix.startswith(self.prefix):
                return True, ciphertext_with_prefix[len(self.prefix) :], None
            return False, ciphertext_with_prefix, None
        for prefix, cipher_type in self.get_init_config().prefix_cipher_type_map.items():
            if ciphertext_with_prefix.startswith(prefix):
                return True, ciphertext_with_prefix[len(prefix) :], cipher_type
        return False, ciphertext_with_prefix, None

    def encrypt(self, plaintext: str) -> str:
        if self.prefix is not None:
            selected_prefix: str = self.prefix
        else:
            selected_prefix = self.get_init_config().db_prefix_map[
                self._get_cipher_type_from_settings()
            ]

        cipher = self.get_cipher()
        ciphertext_with_prefix: str = selected_prefix + cipher.encrypt(plaintext)
        return ciphertext_with_prefix

    def decrypt(self, ciphertext_with_prefix: str) -> str:

        is_match, trusted_value, cipher_type = self.prefix_selector(
            ciphertext_with_prefix
        )
        if is_match:
            try:
                # 解密时使用前缀匹配到的算法
                cipher = self.get_cipher(cipher_type=cipher_type)
                plaintext: str = cipher.decrypt(trusted_value)
            except Exception:
                return ciphertext_with_prefix
        else:
            return ciphertext_with_prefix

        return plaintext


class SymmetricCipherSelectorMixin(CipherSelectorMixin[SymmetricOptions]):
    """Select symmetric ciphers from Django settings."""

    @staticmethod
    def _get_cipher_type_from_settings() -> str:
        return crypto_settings.SYMMETRIC_CIPHER_TYPE

    def get_cipher(self, cipher_type: typing.Optional[str] = None) -> SymmetricCipher:
        return symmetric_cipher_manager.cipher(using=self.using, cipher_type=cipher_type)

    def get_init_config(self) -> CipherInitConfig[SymmetricOptions]:
        return crypto_settings.SYMMETRIC_CIPHERS[self.using]


class AsymmetricCipherSelectorMixin(CipherSelectorMixin[AsymmetricOptions]):
    """Select asymmetric ciphers from Django settings."""

    @staticmethod
    def _get_cipher_type_from_settings() -> str:
        return crypto_settings.ASYMMETRIC_CIPHER_TYPE

    def get_cipher(self, cipher_type: typing.Optional[str] = None) -> AsymmetricCipher:
        return asymmetric_cipher_manager.cipher(
            using=self.using, cipher_type=cipher_type
        )

    def get_init_config(self) -> CipherInitConfig[AsymmetricOptions]:
        return crypto_settings.ASYMMETRIC_CIPHERS[self.using]


class CipherSelector:
    """Store the selected cipher alias and optional ciphertext prefix."""

    def __init__(
        self, using: typing.Optional[str] = None, prefix: typing.Optional[str] = None
    ) -> None:
        """Initialize a cipher selector.

        :param using: Configured cipher alias; defaults to ``default``.
        :param prefix: Fixed ciphertext prefix, or ``None`` to use configured mappings.
        """
        self.prefix = prefix
        self.using = using or "default"


class SymmetricCipherSelector(SymmetricCipherSelectorMixin, CipherSelector):
    """Select a symmetric cipher outside of a model field."""


class AsymmetricCipherSelector(AsymmetricCipherSelectorMixin, CipherSelector):
    """Select an asymmetric cipher outside of a model field."""
