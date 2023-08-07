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

from bkcrypto.contrib.django.selectors import SymmetricCipherSelectorMixin


class SymmetricFieldMixin(SymmetricCipherSelectorMixin):
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

        return self.decrypt(value)

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

        return self.encrypt(value)


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
