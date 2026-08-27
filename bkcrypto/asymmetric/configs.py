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

import typing
from dataclasses import dataclass, field

from bkcrypto import constants, types
from bkcrypto.utils import convertors
from cryptography.hazmat.primitives import hashes

from . import interceptors

DEFAULT_RSA_HASH: hashes.HashAlgorithm = hashes.SHA1()


@dataclass
class KeyConfig:
    """Configure asymmetric key sources.

    1. 优先使用 string 进行加载
    2. 若私钥已传入，公钥可以不传，会基于私钥生成
    3. 都不传时将随机生成密钥对.
    """

    # 公钥（字符串）
    public_key_string: typing.Optional[types.PublicKeyString] = None
    # 私钥（字符串）
    private_key_string: typing.Optional[types.PrivateKeyString] = None
    # 公钥文件路径
    public_key_file: typing.Optional[str] = None
    # 私钥文件路径
    private_key_file: typing.Optional[str] = None


@dataclass
class BaseAsymmetricConfig:
    """Configure behavior shared by all asymmetric ciphers."""

    # 编码，默认为 `utf-8`
    encoding: str = "utf-8"
    # 字节序列转换器，默认使用 `Base64Convertor`
    convertor: type[convertors.BaseConvertor] = convertors.Base64Convertor
    # 拦截器用于在加解密、签名验签操作前后添加自定义操作。
    interceptor: type[interceptors.BaseAsymmetricInterceptor] = (
        interceptors.BaseAsymmetricInterceptor
    )


@dataclass
class BaseRSAAsymmetricConfig(BaseAsymmetricConfig):
    """Configure RSA padding, hashing, signatures, and key generation."""

    # 加解密填充方案，默认为 `PKCS1_v1_5`
    padding: constants.RSACipherPadding = constants.RSACipherPadding.PKCS1_v1_5
    # OAEP 哈希算法，默认保留历史 SHA-1 行为
    oaep_hash: hashes.HashAlgorithm = field(default_factory=hashes.SHA1)
    # MGF1 哈希算法，默认与历史 OAEP 行为一致
    mgf1_hash: hashes.HashAlgorithm = field(default_factory=hashes.SHA1)
    # OAEP label，None 表示空 label
    oaep_label: typing.Optional[bytes] = None
    # 是否按 RSA 最大明文长度分段，默认保留历史行为
    enable_segmented_encryption: bool = True
    # 签名方案，默认为 `PKCS1_v1_5`
    sig_scheme: constants.RSASigScheme = constants.RSASigScheme.PKCS1_v1_5
    # 密钥长度（bit）
    # In 2017, a sufficient length is deemed to be 2048 bits.
    # 具体参考 -> https://cryptography.io/en/stable/hazmat/primitives/asymmetric/rsa/
    pkey_bits: int = 2048


@dataclass
class BaseSM2AsymmetricConfig(BaseAsymmetricConfig):
    """Configure SM2 asymmetric cipher behavior."""
