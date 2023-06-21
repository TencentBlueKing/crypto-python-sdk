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
import copy
import os
import typing
from dataclasses import dataclass

from Cryptodome.Util.Padding import pad, unpad
from dacite import from_dict

from bkcrypto import constants, types
from bkcrypto.utils import convertors

from .. import interceptors


@dataclass
class EncryptionMetadata:
    iv: typing.Optional[types.SymmetricIv] = None
    tag: typing.Optional[types.SymmetricTag] = None
    aad: typing.Optional[types.SymmetricAad] = None


@dataclass
class BaseSymmetricConfig:

    # 块密码模式
    mode: typing.Union[constants.AESMode, constants.SM4Mode] = constants.AESMode.CTR
    # 对称加密密钥
    key: types.SymmetricKey = None
    key_size: int = 16

    enable_iv: bool = True
    # enable_random_iv = `True` 时可选，默认为 16 字节
    # 对于 CBC、CFB 和 OFB 模式：IV 的长度应与 AES 加密的分组大小相同，即 128 位（16 字节）
    # 对于 CTR 模式：IV（通常称为 nonce）的长度可以灵活设置。通常长度为 64 位到 128 位（8 - 16 字节)
    # 对于 GCM 模式：IV（通常称为 nonce）的长度通常为 96 位（12 字节）
    iv_size: int = 16
    # 固定初始向量，为空时随机生成
    iv: typing.Optional[types.SymmetricIv] = None

    # aad 仅 GCM 模式
    # aad 长度，enable_random_aad = True 时必填，长度没有限制
    aad_size: int = 20
    # 是否启用 aad
    enable_aad: bool = True
    # 生成 GCM 关联数据，为空时随机生成
    aad: typing.Optional[types.SymmetricAad] = None

    # encryption_metadata_combination_mode="bytes" 时，会使用该值作为 tag 的固定填充长度
    # 一般 tag 的长度为 4 ~ 16，padded_tag_size 的最优取值是 max_pad_size * 2
    padded_tag_size = 32

    # 加密元数据携带模式
    encryption_metadata_combination_mode: constants.EncryptionMetadataCombinationMode = (
        constants.EncryptionMetadataCombinationMode.BYTES
    )
    metadata_combination_separator: str = "$bkcrypto$"

    encoding: str = "utf-8"
    convertor: typing.Type[convertors.BaseConvertor] = convertors.Base64Convertor
    interceptor: typing.Type[interceptors.BaseSymmetricInterceptor] = interceptors.BaseSymmetricInterceptor

    def __post_init__(self):

        if self.iv and self.enable_iv:
            self.iv_size = len(self.iv)

        if self.mode.value not in [constants.AESMode.GCM.value]:
            self.enable_aad = False

        if self.aad and self.enable_aad:
            self.aad_size = len(self.aad)


class BaseSymmetricCipher:

    CONFIG_DATA_CLASS: typing.Type[BaseSymmetricConfig] = BaseSymmetricConfig

    config: BaseSymmetricConfig = None

    @abc.abstractmethod
    def get_block_size(self) -> int:
        raise NotImplementedError

    @abc.abstractmethod
    def _encrypt(self, plaintext_bytes: bytes, encryption_metadata: EncryptionMetadata) -> bytes:
        raise NotImplementedError

    @abc.abstractmethod
    def _decrypt(self, ciphertext_bytes: bytes, encryption_metadata: EncryptionMetadata) -> bytes:
        raise NotImplementedError

    def __init__(
        self,
        key: typing.Optional[typing.Union[bytes, str]] = None,
        **options,
    ):
        options: typing.Dict[str, typing.Any] = copy.deepcopy(options)

        # init config
        self.config = from_dict(self.CONFIG_DATA_CLASS, options)

        if key is None:
            key = self.generate_key()

        if isinstance(key, str):
            key = key.encode(self.config.encoding)

        self.config.key = key[: self.config.key_size]

    def generate_key(self) -> types.SymmetricKey:
        """
        生成密钥
        :return: key_string
        """
        return os.urandom(self.config.key_size)

    def generate_iv(self) -> types.SymmetricIv:
        """
        生成初始向量
        :return:
        """
        return os.urandom(self.config.iv_size)

    def generate_aad(self) -> types.SymmetricAad:
        """
        生成 GCM 关联数据
        :return:
        """
        return os.urandom(self.config.aad_size)

    def combine_encryption_metadata_with_bytes(
        self, ciphertext_bytes: bytes, encryption_metadata: EncryptionMetadata
    ) -> str:
        combination_bytes: bytes = b""
        if encryption_metadata.iv:
            combination_bytes += encryption_metadata.iv
        if encryption_metadata.tag:
            # padded_tag_size >= 2 * length(tag)，填充后长度固定为 padded_tag_size
            combination_bytes += pad(encryption_metadata.tag, block_size=self.config.padded_tag_size, style="iso7816")
        if encryption_metadata.aad:
            combination_bytes += encryption_metadata.aad

        combination_bytes += ciphertext_bytes

        ciphertext: str = self.config.convertor.to_string(combination_bytes)
        return ciphertext

    def combine_encryption_metadata_with_string_sep(
        self, ciphertext_bytes: bytes, encryption_metadata: EncryptionMetadata
    ) -> str:
        iv_str_or_none: typing.Optional[str] = None
        tag_str_or_none: typing.Optional[str] = None
        aad_str_or_none: typing.Optional[str] = None

        if encryption_metadata.iv is not None:
            iv_str_or_none = self.config.convertor.to_string(encryption_metadata.iv)
        if encryption_metadata.tag is not None:
            tag_str_or_none = self.config.convertor.to_string(encryption_metadata.tag)
        if encryption_metadata.aad is not None:
            aad_str_or_none = self.config.convertor.to_string(encryption_metadata.aad)

        ciphertext: str = self.config.convertor.to_string(ciphertext_bytes)
        combination: typing.List[typing.Optional[str]] = [iv_str_or_none, tag_str_or_none, aad_str_or_none, ciphertext]
        # 仅过滤 None 值，密文可能是空串，也需要进行分隔
        ciphertext: str = self.config.metadata_combination_separator.join(
            list(filter(lambda x: x is not None, combination))
        )
        return ciphertext

    def extract_encryption_metadata_from_bytes(self, ciphertext: str) -> typing.Tuple[bytes, EncryptionMetadata]:
        tag_or_none: typing.Optional[types.SymmetricTag] = None
        aad_or_none: typing.Optional[types.SymmetricAad] = None
        iv_or_none: typing.Optional[types.SymmetricIv] = None
        ciphertext_bytes: bytes = self.config.convertor.from_string(ciphertext)

        pointer: int = 0
        if self.config.enable_iv:
            iv_or_none: types.SymmetricIv = ciphertext_bytes[pointer : pointer + self.config.iv_size]
            pointer += self.config.iv_size

        # 只有 GCM 模式支持 tag 和 aad
        if self.config.mode.value in [constants.AESMode.GCM.value]:
            tag_or_none = unpad(
                ciphertext_bytes[pointer : pointer + self.config.padded_tag_size],
                self.config.padded_tag_size,
                style="iso7816",
            )
            pointer += self.config.padded_tag_size
            if self.config.enable_aad:
                aad_or_none = ciphertext_bytes[pointer : pointer + self.config.aad_size]
                pointer += self.config.aad_size

        ciphertext_bytes = ciphertext_bytes[pointer:]

        return ciphertext_bytes, EncryptionMetadata(iv_or_none, tag_or_none, aad_or_none)

    def extract_encryption_metadata_from_string_sep(self, ciphertext: str) -> typing.Tuple[bytes, EncryptionMetadata]:

        iv_or_none: typing.Optional[types.SymmetricIv] = None
        tag_or_none: typing.Optional[types.SymmetricTag] = None
        aad_or_none: typing.Optional[types.SymmetricAad] = None

        if self.config.enable_iv:
            iv_str, ciphertext = ciphertext.split(self.config.metadata_combination_separator, 1)
            iv_or_none = self.config.convertor.from_string(iv_str)
        # 只有 GCM 模式支持 tag 和 aad
        if self.config.mode.value in [constants.AESMode.GCM.value]:
            tag_str, ciphertext = ciphertext.split(self.config.metadata_combination_separator, 1)
            tag_or_none = self.config.convertor.from_string(tag_str)
            if self.config.enable_aad:
                aad_str, ciphertext = ciphertext.split(self.config.metadata_combination_separator, 1)
                aad_or_none = self.config.convertor.from_string(aad_str)

        ciphertext_bytes = self.config.convertor.from_string(ciphertext)

        return ciphertext_bytes, EncryptionMetadata(iv_or_none, tag_or_none, aad_or_none)

    def encrypt(self, plaintext: str) -> str:
        """
        加密
        :param plaintext: 待加密的字符串
        :return: 密文
        """
        plaintext: str = self.config.interceptor.before_encrypt(plaintext)
        plaintext_bytes: bytes = self.config.convertor.encode_plaintext(plaintext, encoding=self.config.encoding)

        if not self.config.enable_iv:
            iv = None
        elif self.config.iv:
            iv = self.config.iv
        else:
            iv = self.generate_iv()

        if not self.config.enable_aad:
            aad = None
        elif self.config.aad:
            aad = self.config.aad
        else:
            aad = self.generate_aad()

        encryption_metadata: EncryptionMetadata = EncryptionMetadata(iv=iv, aad=aad)
        ciphertext_bytes = self._encrypt(plaintext_bytes, encryption_metadata)
        combine_encryption_metadata_handle: typing.Callable[[bytes, EncryptionMetadata], str] = getattr(
            self, f"combine_encryption_metadata_with_{self.config.encryption_metadata_combination_mode.value}"
        )
        ciphertext: str = combine_encryption_metadata_handle(ciphertext_bytes, encryption_metadata)
        return self.config.interceptor.after_encrypt(ciphertext)

    def decrypt(self, ciphertext: str) -> str:
        """
        解密
        :param ciphertext: 密文
        :return: 解密后的信息
        """

        ciphertext: str = self.config.interceptor.before_decrypt(ciphertext)
        extract_encryption_metadata_handle: typing.Callable[[str], typing.Tuple[bytes, EncryptionMetadata]] = getattr(
            self, f"extract_encryption_metadata_from_{self.config.encryption_metadata_combination_mode.value}"
        )
        ciphertext_bytes, encryption_metadata = extract_encryption_metadata_handle(ciphertext)
        plaintext_bytes: bytes = self._decrypt(ciphertext_bytes, encryption_metadata)
        plaintext: str = self.config.convertor.decode_plaintext(plaintext_bytes, encoding=self.config.encoding)
        return self.config.interceptor.after_decrypt(plaintext)
