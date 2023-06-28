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
from dataclasses import dataclass

from bkcrypto import constants, types
from bkcrypto.utils import convertors

from . import interceptors


@dataclass
class KeyConfig:
    """
    1. 优先使用 string 进行加载
    2. 若私钥已传入，公钥可以不传，会基于私钥生成
    3. 都不传时将随机生成密钥对
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
    # 编码，默认为 `utf-8`
    encoding: str = "utf-8"
    # 字节序列转换器，默认使用 `Base64Convertor`
    convertor: typing.Type[convertors.BaseConvertor] = convertors.Base64Convertor
    # 拦截器，用于在加解密、签名验签操作前后添加自定义操作，默认使用 `BaseAsymmetricInterceptor`
    interceptor: typing.Type[interceptors.BaseAsymmetricInterceptor] = interceptors.BaseAsymmetricInterceptor


@dataclass
class BaseRSAAsymmetricConfig(BaseAsymmetricConfig):

    # 加解密填充方案，默认为 `PKCS1_v1_5`
    padding: constants.RSACipherPadding = constants.RSACipherPadding.PKCS1_v1_5
    # 签名方案，默认为 `PKCS1_v1_5`
    sig_scheme: constants.RSASigScheme = constants.RSASigScheme.PKCS1_v1_5
    # 密钥长度（bit）
    # In 2017, a sufficient length is deemed to be 2048 bits.
    # 具体参考 -> https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html
    pkey_bits: int = 2048


@dataclass
class BaseSM2AsymmetricConfig(BaseAsymmetricConfig):
    pass
