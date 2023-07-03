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

from django.db import models

from bkcrypto.contrib.django.ciphers import symmetric_cipher_manager
from bkcrypto.contrib.django.init_configs import SymmetricCipherInitConfig
from bkcrypto.contrib.django.settings import crypto_settings
from bkcrypto.symmetric.ciphers.base import BaseSymmetricCipher


class SymmetricFieldMixin:

    cipher: BaseSymmetricCipher = None

    # 是否指定固定前缀，如果不为 None，密文将统一使用 prefix 作为前缀
    prefix: str = None
    # 指定对称加密实例，默认使用 `default`
    using: str = None

    def prefix_selector(self, value: str) -> typing.Tuple[bool, str, typing.Optional[str]]:
        """
        密文前缀匹配，用于提取可能存在的加密类型
        :param value:
        :return:
        """
        if self.prefix is not None:
            if value.startswith(self.prefix):
                return True, value[len(self.prefix) :], None
            else:
                return False, value, None
        else:
            init_config: SymmetricCipherInitConfig = crypto_settings.SYMMETRIC_CIPHERS[self.using]
            for prefix, cipher_type in init_config.prefix_cipher_type_map.items():
                if value.startswith(prefix):
                    return True, value[len(prefix) :], cipher_type
            return False, value, None

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        if self.prefix is not None:
            kwargs["prefix"] = self.prefix
        kwargs["using"] = self.using
        return name, path, args, kwargs

    def get_decrypted_value(self, value):
        """
        获取解密处理后的数据
        :param value:
        :return:
        """

        if value is None:
            return value

        is_match, trusted_value, cipher_type = self.prefix_selector(value)
        if is_match:
            try:
                cipher: BaseSymmetricCipher = symmetric_cipher_manager.cipher(using=self.using, cipher_type=cipher_type)
                value = cipher.decrypt(trusted_value)
            except Exception:
                pass

        return value

    def from_db_value(self, value, expression, connection, context=None):
        """出库后解密数据"""

        value = self.get_decrypted_value(value)

        sp = super()
        if hasattr(sp, "from_db_value"):
            value = sp.from_db_value(value, expression, connection, context)
        return value

    def to_python(self, value):
        """反序列化和 Form clean() 时调用，解密数据"""

        value = self.get_decrypted_value(value)

        sp = super()
        if hasattr(sp, "to_python"):
            value = sp.to_python(value)
        return value

    def get_prep_value(self, value):
        """入库前加密数据"""
        if value is None:
            return value

        sp = super()
        if hasattr(sp, "get_prep_value"):
            value = sp.get_prep_value(value)

        if self.prefix is not None:
            prefix: str = self.prefix
        else:
            init_config: SymmetricCipherInitConfig = crypto_settings.SYMMETRIC_CIPHERS[self.using]
            prefix: str = init_config.db_prefix_map[crypto_settings.SYMMETRIC_CIPHER_TYPE]

        cipher: BaseSymmetricCipher = symmetric_cipher_manager.cipher(using=self.using)
        value = prefix + cipher.encrypt(value)

        return value


class SymmetricTextField(SymmetricFieldMixin, models.TextField):
    def __init__(self, *args, using: typing.Optional[str] = None, prefix: typing.Optional[str] = None, **kwargs):
        """
        对称加密 ModelField，基于 BKCRYPTO.SYMMETRIC_CIPHERS 的配置提供敏感信息加解密的能力
        :param using: 指定对称加密实例，默认使用 `default`
        :param prefix: 是否指定固定前缀，如果不为 None，密文将统一使用 prefix 作为前缀
        :param args:
        :param kwargs:
        """
        self.prefix = prefix
        self.using = using or "default"

        super(SymmetricTextField, self).__init__(*args, **kwargs)
