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

from enum import Enum
from functools import cache


class AsymmetricKeyAttribute(Enum):
    """密钥对象类型."""

    PRIVATE_KEY = "private_key"
    PUBLIC_KEY = "public_key"


class RSACipherPadding(Enum):
    """填充标志."""

    PKCS1_v1_5 = "PKCS1_v1_5"
    PKCS1_OAEP = "PKCS1_OAEP"


class RSASigScheme(Enum):
    """签名对象."""

    PKCS1_v1_5 = "PKCS1_v1_5"
    PKCS1_PSS = "PKCS1_PSS"


class SymmetricMode(Enum):
    """非对称块加密模式."""

    CTR = "CTR"
    CBC = "CBC"
    GCM = "GCM"
    CFB = "CFB"

    @classmethod
    @cache
    def members(cls) -> frozenset["SymmetricMode"]:
        """Return all supported symmetric modes."""
        return frozenset(cls)

    @classmethod
    @cache
    def block_size_iv_modes(cls) -> frozenset["SymmetricMode"]:
        """Return modes whose IV must match the cipher block size."""
        return frozenset({cls.CBC, cls.CFB, cls.CTR})


class SymmetricPadding(Enum):
    """对称加密填充方案."""

    NONE = "NONE"
    PKCS7 = "PKCS7"


class EncryptionMetadataCombinationMode(Enum):
    """iv、tag 携带模式."""

    # 各自编码为字符串后按特定分隔符进行拼接
    STRING_SEP = "string_sep"
    # 字节拼接
    BYTES = "bytes"


class SymmetricCipherType(Enum):
    """对称加密类型."""

    SM4 = "SM4"
    AES = "AES"


class AsymmetricCipherType(Enum):
    """非对称加密类型."""

    SM2 = "SM2"
    RSA = "RSA"
