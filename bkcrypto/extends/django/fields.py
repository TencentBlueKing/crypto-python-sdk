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

from bkcrypto.symmetric.ciphers.base import BaseSymmetricCipher


class SymmetricFieldMixin:

    cipher: BaseSymmetricCipher = None
    prefix: str = None
    get_cipher: typing.Callable[[], BaseSymmetricCipher] = None

    DEFAULT_PREFIX: str = "bkcrypto:::"

    def get_or_cache_cipher(self):
        if self.cipher:
            return self.cipher
        self.cipher = self.get_cipher()
        return self.cipher

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        if self.prefix != self.DEFAULT_PREFIX:
            kwargs["prefix"] = self.prefix
        kwargs["get_cipher"] = self.get_cipher
        return name, path, args, kwargs

    def from_db_value(self, value, expression, connection, context=None):
        """出库后解密数据"""
        if value is None:
            return value
        if value.startswith(self.prefix):
            value = value[len(self.prefix) :]
            # 解密失败时展示密文
            try:
                value = self.get_or_cache_cipher().decrypt(value)
            except Exception:
                value = value

        sp = super()
        if hasattr(sp, "from_db_value"):
            value = sp.from_db_value(value, expression, connection, context)
        return value

    def to_python(self, value):
        """反序列化和 Form clean() 时调用，解密数据"""
        if value is None:
            return value
        elif value.startswith(self.prefix):
            value = value[len(self.prefix) :]
            try:
                value = self.get_or_cache_cipher().decrypt(value)
            except Exception:
                value = value

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

        value = self.get_or_cache_cipher().encrypt(value)
        value = self.prefix + value

        return value


class SymmetricTextField(SymmetricFieldMixin, models.TextField):
    def __init__(
        self, *args, get_cipher: typing.Callable[[], BaseSymmetricCipher], prefix: typing.Optional[str] = None, **kwargs
    ):
        """
        初始化
        :param prefix: 加密串前缀
        """

        if prefix is None:
            self.prefix = self.DEFAULT_PREFIX
        else:
            self.prefix = prefix

        self.get_cipher = get_cipher

        super(SymmetricTextField, self).__init__(*args, **kwargs)
