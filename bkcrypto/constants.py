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

from enum import Enum

from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Cipher import PKCS1_v1_5 as PKCS1_v1_5_cipher
from Cryptodome.Signature import PKCS1_PSS
from Cryptodome.Signature import PKCS1_v1_5 as PKCS1_v1_5_sig_scheme

from . import types


class AsymmetricKeyAttribute(Enum):
    """密钥对象类型"""

    PRIVATE_KEY = "private_key"
    PUBLIC_KEY = "public_key"


class RSACipherPadding(Enum):
    """填充标志"""

    PKCS1_v1_5 = "PKCS1_v1_5"
    PKCS1_OAEP = "PKCS1_OAEP"

    @classmethod
    def get_cipher_maker_by_member(cls, member: "RSACipherPadding") -> types.RSACipherMaker:
        return {cls.PKCS1_OAEP: PKCS1_OAEP, cls.PKCS1_v1_5: PKCS1_v1_5_cipher}[member].new


class RSASigScheme(Enum):
    """签名对象"""

    PKCS1_v1_5 = "PKCS1_v1_5"
    PKCS1_PSS = "PKCS1_PSS"

    @classmethod
    def get_sig_scheme_maker_by_member(cls, member: "RSASigScheme") -> types.RSASigSchemeMaker:
        return {cls.PKCS1_PSS: PKCS1_PSS, cls.PKCS1_v1_5: PKCS1_v1_5_sig_scheme}[member].new
