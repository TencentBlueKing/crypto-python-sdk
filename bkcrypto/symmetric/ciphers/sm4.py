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

from tongsuopy.crypto.ciphers import AEADEncryptionContext, Cipher, CipherContext, algorithms, modes

from bkcrypto import constants, types

from .. import configs
from ..options import SM4SymmetricOptions
from . import base


@dataclass
class SM4SymmetricRuntimeConfig(configs.BaseSM4SymmetricConfig, base.BaseSymmetricRuntimeConfig):

    mode_class: types.SM4ModeClass = None

    def __post_init__(self):
        super().__post_init__()

        key_sizes: typing.Set[int] = {key_size // 8 for key_size in algorithms.SM4.key_sizes}
        if self.key_size not in key_sizes:
            raise ValueError(f"Optional key sizes are {key_sizes}, but got {self.key_size}")

        try:
            self.mode_class = {
                constants.SymmetricMode.CTR: modes.CTR,
                constants.SymmetricMode.CBC: modes.CBC,
                constants.SymmetricMode.GCM: modes.GCM,
                constants.SymmetricMode.CFB: modes.CFB,
            }[self.mode]

        except KeyError:
            raise ValueError(f"Unsupported mode: {self.mode}")


class SM4SymmetricCipher(base.BaseSymmetricCipher):

    CIPHER_TYPE: str = constants.SymmetricCipherType.SM4.value

    CONFIG_DATA_CLASS: typing.Type[SM4SymmetricRuntimeConfig] = SM4SymmetricRuntimeConfig

    OPTIONS_DATA_CLASS: typing.Type[SM4SymmetricOptions] = SM4SymmetricOptions

    config: SM4SymmetricRuntimeConfig = None

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

    def _encrypt(self, plaintext_bytes: bytes, encryption_metadata: base.EncryptionMetadata) -> bytes:

        mode_init_args: typing.List[bytes] = []
        if self.config.enable_iv:
            mode_init_args.append(encryption_metadata.iv)
        cipher: Cipher = Cipher(algorithms.SM4(self.config.key), self.config.mode_class(*mode_init_args))
        cipher_ctx: typing.Union[CipherContext, AEADEncryptionContext] = cipher.encryptor()
        if self.config.enable_aad:
            cipher_ctx.authenticate_additional_data(encryption_metadata.aad)
        ciphertext_bytes: bytes = cipher_ctx.update(plaintext_bytes)
        ciphertext_bytes += cipher_ctx.finalize()

        if self.config.mode == constants.SymmetricMode.GCM:
            encryption_metadata.tag = cipher_ctx.tag
        return ciphertext_bytes

    def _decrypt(self, ciphertext_bytes: bytes, encryption_metadata: base.EncryptionMetadata) -> bytes:

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
