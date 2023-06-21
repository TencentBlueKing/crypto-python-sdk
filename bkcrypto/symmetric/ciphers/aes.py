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

from Cryptodome.Cipher import AES

from bkcrypto import constants, types

from . import base
from .base import EncryptionMetadata


@dataclass
class AESSymmetricConfig(base.BaseSymmetricConfig):

    aes_mode: constants.AESMode = constants.AESMode.CTR
    aes_key: types.SymmetricKey = None
    aes_key_size: int = 16

    aes_enable_iv: bool = True
    aes_iv_size: int = 16
    aes_iv: typing.Optional[types.SymmetricIv] = None

    aes_aad_size: int = 20
    aes_aad: typing.Optional[types.SymmetricAad] = None
    aes_enable_random_aad: bool = True

    aes_encryption_metadata_combination_mode: constants.EncryptionMetadataCombinationMode = (
        constants.EncryptionMetadataCombinationMode.BYTES
    )
    aes_metadata_combination_separator: str = "$bkcrypto$"

    mode_class: types.SM4ModeClass = None

    def __post_init__(self):
        self.mode = self.aes_mode
        self.key = self.aes_key
        self.key_size = self.aes_key_size

        self.iv_size = self.aes_iv_size
        self.iv = self.aes_iv

        self.aad_size = self.aes_aad_size
        self.aad = self.aes_aad

        self.encryption_metadata_combination_mode = self.aes_encryption_metadata_combination_mode
        self.metadata_combination_separator = self.aes_metadata_combination_separator

        self.mode_class: types.AESModeClass = constants.AESMode.get_mode_class_by_member(self.mode)

        super().__post_init__()


class AESSymmetricCipher(base.BaseSymmetricCipher):

    CONFIG_DATA_CLASS: typing.Type[AESSymmetricConfig] = AESSymmetricConfig

    config: AESSymmetricConfig = None

    def get_block_size(self) -> int:
        return self.config.key_size

    def _encrypt(self, plaintext_bytes: bytes, encryption_metadata: EncryptionMetadata) -> bytes:

        mode_init_args: typing.List[bytes] = []
        if self.config.enable_iv:
            mode_init_args.append(encryption_metadata.iv)

        cipher_ctx = AES.new(self.config.key, self.config.mode_class, *mode_init_args)
        if self.config.enable_aad:
            cipher_ctx.update(encryption_metadata.aad)

        if self.config.mode == constants.AESMode.GCM:
            ciphertext_bytes, tag = cipher_ctx.encrypt_and_digest(plaintext_bytes)
            encryption_metadata.tag = tag
            return ciphertext_bytes
        else:
            return cipher_ctx.encrypt(plaintext_bytes)

    def _decrypt(self, ciphertext_bytes: bytes, encryption_metadata: EncryptionMetadata) -> bytes:

        mode_init_args: typing.List[bytes] = []
        if self.config.enable_iv:
            mode_init_args.append(encryption_metadata.iv)

        cipher_ctx = AES.new(self.config.key, self.config.mode_class, *mode_init_args)
        if self.config.enable_aad:
            cipher_ctx.update(encryption_metadata.aad)

        if self.config.mode == constants.AESMode.GCM:
            plaintext_bytes: bytes = cipher_ctx.decrypt_and_verify(ciphertext_bytes, encryption_metadata.tag)
            return plaintext_bytes
        else:
            return cipher_ctx.decrypt(ciphertext_bytes)
