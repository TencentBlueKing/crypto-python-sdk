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
from bkcrypto.contrib.django.ciphers import asymmetric_cipher_manager, symmetric_cipher_manager
from bkcrypto.contrib.django.init_configs import CipherInitConfig
from bkcrypto.contrib.django.settings import crypto_settings
from bkcrypto.symmetric.ciphers.base import BaseSymmetricCipher


class CipherSelectorMixin:
    init_config: CipherInitConfig = None

    # 是否指定固定前缀，如果不为 None，密文将统一使用 prefix 作为前缀
    prefix: str = None
    # 指定对称加密实例，默认使用 `default`
    using: str = None

    @abc.abstractmethod
    def _get_cipher_type_from_settings(self) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def get_cipher(self, cipher_type: typing.Optional[str] = None):
        raise NotImplementedError

    @abc.abstractmethod
    def get_init_config(self) -> CipherInitConfig:
        raise NotImplementedError

    def prefix_selector(self, ciphertext_with_prefix: str) -> typing.Tuple[bool, str, typing.Optional[str]]:
        """
        密文前缀匹配，用于提取可能存在的加密类型
        :param ciphertext_with_prefix:
        :return:
        """
        if self.prefix is not None:
            if ciphertext_with_prefix.startswith(self.prefix):
                return True, ciphertext_with_prefix[len(self.prefix) :], None
            else:
                return False, ciphertext_with_prefix, None
        else:
            for prefix, cipher_type in self.get_init_config().prefix_cipher_type_map.items():
                if ciphertext_with_prefix.startswith(prefix):
                    return True, ciphertext_with_prefix[len(prefix) :], cipher_type
            return False, ciphertext_with_prefix, None

    def encrypt(self, plaintext: str) -> str:
        if self.prefix is not None:
            prefix: str = self.prefix
        else:
            prefix: str = self.get_init_config().db_prefix_map[self._get_cipher_type_from_settings()]

        cipher = self.get_cipher()
        ciphertext_with_prefix: str = prefix + cipher.encrypt(plaintext)
        return ciphertext_with_prefix

    def decrypt(self, ciphertext_with_prefix: str) -> str:

        is_match, trusted_value, cipher_type = self.prefix_selector(ciphertext_with_prefix)
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


class SymmetricCipherSelectorMixin(CipherSelectorMixin):
    def _get_cipher_type_from_settings(self) -> str:
        return crypto_settings.SYMMETRIC_CIPHER_TYPE

    def get_cipher(self, cipher_type: typing.Optional[str] = None) -> BaseSymmetricCipher:
        return symmetric_cipher_manager.cipher(using=self.using, cipher_type=cipher_type)

    def get_init_config(self) -> CipherInitConfig:
        return crypto_settings.SYMMETRIC_CIPHERS[self.using]


class AsymmetricCipherSelectorMixin(CipherSelectorMixin):
    def _get_cipher_type_from_settings(self) -> str:
        return crypto_settings.ASYMMETRIC_CIPHER_TYPE

    def get_cipher(self, cipher_type: typing.Optional[str] = None) -> BaseAsymmetricCipher:
        return asymmetric_cipher_manager.cipher(using=self.using, cipher_type=cipher_type)

    def get_init_config(self) -> CipherInitConfig:
        return crypto_settings.ASYMMETRIC_CIPHERS[self.using]


class CipherSelector:
    def __init__(self, using: typing.Optional[str] = None, prefix: typing.Optional[str] = None):
        """
        对称加密
        :param using: 指定对称加密实例，默认使用 `default`
        :param prefix: 是否指定固定前缀，如果不为 None，密文将统一使用 prefix 作为前缀
        """
        self.prefix = prefix
        self.using = using or "default"


class SymmetricCipherSelector(SymmetricCipherSelectorMixin, CipherSelector):
    pass


class AsymmetricCipherSelector(AsymmetricCipherSelectorMixin, CipherSelector):
    pass
