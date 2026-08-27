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
from Cryptodome.Util import Counter
from Cryptodome.Util.Padding import pad, unpad

from bkcrypto import constants, types

from .. import configs, options
from . import base


@dataclass
class AESSymmetricRuntimeConfig(configs.BaseAESSymmetricConfig, base.BaseSymmetricRuntimeConfig):

    mode_class: types.AESModeClass = None

    def __post_init__(self):
        super().__post_init__()

        if self.key_size not in AES.key_size:
            raise ValueError(f"Optional key sizes are {AES.key_size}, but got {self.key_size}")

        if self.mode in [constants.SymmetricMode.CBC, constants.SymmetricMode.CTR] and self.iv_size != AES.block_size:
            raise ValueError(f"AES {self.mode.value} IV must be exactly {AES.block_size} bytes")

        try:
            self.mode_class = {
                constants.SymmetricMode.CTR: AES.MODE_CTR,
                constants.SymmetricMode.CBC: AES.MODE_CBC,
                constants.SymmetricMode.GCM: AES.MODE_GCM,
                constants.SymmetricMode.CFB: AES.MODE_CFB,
            }[self.mode]

        except KeyError:
            raise ValueError(f"Unsupported mode: {self.mode}")


class AESSymmetricCipher(base.BaseSymmetricCipher):

    CIPHER_TYPE: str = constants.SymmetricCipherType.AES.value

    CONFIG_DATA_CLASS: typing.Type[AESSymmetricRuntimeConfig] = AESSymmetricRuntimeConfig

    OPTIONS_DATA_CLASS: typing.Type[options.AESSymmetricOptions] = options.AESSymmetricOptions

    config: AESSymmetricRuntimeConfig = None

    def __init__(self, key: typing.Optional[typing.Union[bytes, str]] = None, **options):
        key_bytes: typing.Optional[bytes] = (
            key.encode(options.get("encoding", "utf-8")) if isinstance(key, str) else key
        )
        key_size: int = options.get("key_size", 16)
        if key_bytes is not None and len(key_bytes) != key_size:
            raise ValueError(f"AES key must be exactly {key_size} bytes")
        super().__init__(key, **options)

    def get_block_size(self) -> int:
        return AES.block_size

    def init_ctx(self, encryption_metadata: base.EncryptionMetadata):
        mode_init_args: typing.List[bytes] = []
        mode_init_kwargs: typing.Dict[str : typing.Any] = {}

        if self.config.enable_iv:
            if (
                self.config.mode in [constants.SymmetricMode.CBC, constants.SymmetricMode.CTR]
                and len(encryption_metadata.iv) != AES.block_size
            ):
                raise ValueError(f"AES {self.config.mode.value} IV must be exactly {AES.block_size} bytes")
            if self.config.mode == constants.SymmetricMode.CTR:
                # Size of the counter block must match block size
                mode_init_kwargs["counter"] = Counter.new(
                    self.get_block_size() * 8, initial_value=int.from_bytes(encryption_metadata.iv, byteorder="big")
                )
            else:
                mode_init_args.append(encryption_metadata.iv)

        cipher_ctx = AES.new(self.config.key, self.config.mode_class, *mode_init_args, **mode_init_kwargs)
        if self.config.enable_aad:
            cipher_ctx.update(encryption_metadata.aad)

        return cipher_ctx

    def _encrypt(self, plaintext_bytes: bytes, encryption_metadata: base.EncryptionMetadata) -> bytes:

        cipher_ctx = self.init_ctx(encryption_metadata)

        if self.config.mode == constants.SymmetricMode.CBC and self.config.padding == constants.SymmetricPadding.PKCS7:
            plaintext_bytes = pad(plaintext_bytes, AES.block_size, style="pkcs7")

        if self.config.mode == constants.SymmetricMode.GCM:
            ciphertext_bytes, tag = cipher_ctx.encrypt_and_digest(plaintext_bytes)
            encryption_metadata.tag = tag
            return ciphertext_bytes
        else:
            return cipher_ctx.encrypt(plaintext_bytes)

    def _decrypt(self, ciphertext_bytes: bytes, encryption_metadata: base.EncryptionMetadata) -> bytes:

        if self.config.mode == constants.SymmetricMode.CBC and (
            not ciphertext_bytes or len(ciphertext_bytes) % AES.block_size
        ):
            raise ValueError("AES CBC ciphertext must be non-empty and block-aligned")

        cipher_ctx = self.init_ctx(encryption_metadata)

        if self.config.mode == constants.SymmetricMode.GCM:
            plaintext_bytes: bytes = cipher_ctx.decrypt_and_verify(ciphertext_bytes, encryption_metadata.tag)
            return plaintext_bytes
        else:
            plaintext_bytes: bytes = cipher_ctx.decrypt(ciphertext_bytes)
            if (
                self.config.mode == constants.SymmetricMode.CBC
                and self.config.padding == constants.SymmetricPadding.PKCS7
            ):
                return unpad(plaintext_bytes, AES.block_size, style="pkcs7")
            return plaintext_bytes
