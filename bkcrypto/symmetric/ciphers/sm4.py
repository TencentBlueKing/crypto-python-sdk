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

from tongsuopy.crypto.ciphers import AEADEncryptionContext, Cipher, CipherContext, algorithms

from bkcrypto import constants, types

from . import base
from .base import EncryptionMetadata


@dataclass
class SM4SymmetricConfig(base.BaseSymmetricConfig):

    sm4_mode: constants.SM4Mode = constants.SM4Mode.CTR
    sm4_key: types.SymmetricKey = None

    sm4_enable_iv: bool = True
    sm4_iv_size: int = 16
    sm4_iv: typing.Optional[types.SymmetricIv] = None

    sm4_aad_size: int = 20
    sm4_aad: typing.Optional[types.SymmetricAad] = None
    sm4_enable_random_aad: bool = True

    sm4_encryption_metadata_combination_mode: constants.EncryptionMetadataCombinationMode = (
        constants.EncryptionMetadataCombinationMode.BYTES
    )
    sm4_metadata_combination_separator: str = "$bkcrypto$"

    mode_class: types.SM4ModeClass = None

    def __post_init__(self):
        self.mode = self.sm4_mode
        self.key = self.sm4_key
        # SM4 算法密钥长度固定
        self.key_size = algorithms.SM4.key_size // 8

        self.iv_size = self.sm4_iv_size
        self.iv = self.sm4_iv

        self.aad_size = self.sm4_aad_size
        self.aad = self.sm4_aad

        self.encryption_metadata_combination_mode = self.sm4_encryption_metadata_combination_mode
        self.metadata_combination_separator = self.sm4_metadata_combination_separator

        self.mode_class: types.SM4ModeClass = constants.SM4Mode.get_mode_class_by_member(self.mode)

        super().__post_init__()


class SM4SymmetricCipher(base.BaseSymmetricCipher):

    CONFIG_DATA_CLASS: typing.Type[SM4SymmetricConfig] = SM4SymmetricConfig

    config: SM4SymmetricConfig = None

    def __init__(
        self,
        key: typing.Optional[typing.Union[bytes, str]] = None,
        **options,
    ):
        super().__init__(key, **options)
        if self.config.key and len(self.config.key) < self.config.key_size:
            self.config.key += b"\x00" * (self.config.key_size - len(self.config.key))

    def get_block_size(self) -> int:
        return algorithms.SM4.block_size // 8

    def _encrypt(self, plaintext_bytes: bytes, encryption_metadata: EncryptionMetadata) -> bytes:

        mode_init_args: typing.List[bytes] = []
        if self.config.enable_iv:
            mode_init_args.append(encryption_metadata.iv)
        cipher: Cipher = Cipher(algorithms.SM4(self.config.key), self.config.mode_class(*mode_init_args))
        cipher_ctx: typing.Union[CipherContext, AEADEncryptionContext] = cipher.encryptor()
        if self.config.enable_aad:
            cipher_ctx.authenticate_additional_data(encryption_metadata.aad)
        ciphertext_bytes: bytes = cipher_ctx.update(plaintext_bytes)
        ciphertext_bytes += cipher_ctx.finalize()

        if self.config.mode == constants.SM4Mode.GCM:
            encryption_metadata.tag = cipher_ctx.tag
        return ciphertext_bytes

    def _decrypt(self, ciphertext_bytes: bytes, encryption_metadata: EncryptionMetadata) -> bytes:

        mode_init_args: typing.List[bytes] = []
        if self.config.enable_iv:
            mode_init_args.append(encryption_metadata.iv)
        if encryption_metadata.tag:
            mode_init_args.append(encryption_metadata.tag)

        cipher: Cipher = Cipher(algorithms.SM4(self.config.key), self.config.mode_class(*mode_init_args))
        cipher_ctx: typing.Union[CipherContext, AEADEncryptionContext] = cipher.decryptor()
        if self.config.enable_aad:
            cipher_ctx.authenticate_additional_data(encryption_metadata.aad)
        plaintext_bytes = cipher_ctx.update(ciphertext_bytes)
        plaintext_bytes += cipher_ctx.finalize()
        return plaintext_bytes
