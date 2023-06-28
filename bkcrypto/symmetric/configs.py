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
    # 密钥，为空时随机生成，可通过 key_size 指定密钥长度
    key: typing.Optional[typing.Union[bytes, str]] = None


@dataclass
class BaseSymmetricConfig:

    # 块密码模式
    mode: constants.SymmetricMode = constants.SymmetricMode.CTR
    # 密钥长度
    key_size: int = 16

    # 是否启用 iv
    enable_iv: bool = True
    # enable_random_iv = `True` 时可选，默认为 16 字节
    # 对于 CBC、CFB 和 OFB 模式：IV 的长度应与 AES 加密的分组大小相同，即 128 位（16 字节）
    # 对于 CTR 模式：IV（通常称为 nonce）的长度可以灵活设置。通常长度为 64 位到 128 位（8 - 16 字节)
    # 对于 GCM 模式：IV（通常称为 nonce）的长度通常为 96 位（12 字节）
    iv_size: int = 16
    # 固定初始向量，为空时每次加密随机生成
    iv: typing.Optional[types.SymmetricIv] = None

    # aad 仅 GCM 模式
    # aad 长度，enable_random_aad = True 时必填，长度没有限制
    aad_size: int = 20
    # 是否启用 aad
    enable_aad: bool = True
    # 生成 GCM 关联数据，为空时每次加密随机生成
    aad: typing.Optional[types.SymmetricAad] = None

    # encryption_metadata_combination_mode="bytes" 时，会使用该值作为 tag 的固定填充长度
    # 一般 tag 的长度为 4 ~ 16，padded_tag_size 的最优取值是 max_pad_size * 2
    padded_tag_size = 32

    # 加密元数据携带模式
    encryption_metadata_combination_mode: constants.EncryptionMetadataCombinationMode = (
        constants.EncryptionMetadataCombinationMode.BYTES
    )
    # encryption_metadata_combination_mode 为 `bytes` 时所使用的分隔符
    metadata_combination_separator: str = "$bkcrypto$"

    encoding: str = "utf-8"
    convertor: typing.Type[convertors.BaseConvertor] = convertors.Base64Convertor
    interceptor: typing.Type[interceptors.BaseSymmetricInterceptor] = interceptors.BaseSymmetricInterceptor


@dataclass
class BaseAESSymmetricConfig(BaseSymmetricConfig):
    pass


@dataclass
class BaseSM4SymmetricConfig(BaseSymmetricConfig):
    pass
