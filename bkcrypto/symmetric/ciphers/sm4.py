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
from dataclasses import dataclass

from bkcrypto import constants
from tongsuopy.crypto.ciphers import (
    AEADDecryptionContext,
    AEADEncryptionContext,
    Cipher,
    CipherContext,
    algorithms,
    modes,
)
from typing_extensions import TypeAlias

from .. import configs
from ..options import SM4SymmetricOptions
from . import base

SM4Mode: TypeAlias = typing.Union[modes.CTR, modes.CBC, modes.CFB]
SM4_BLOCK_SIZE = 16
SM4_KEY_SIZES = {16}


@dataclass
class SM4SymmetricRuntimeConfig(
    configs.BaseSM4SymmetricConfig, base.BaseSymmetricRuntimeConfig
):
    """Store normalized SM4 runtime configuration."""

    def __post_init__(self) -> None:
        super().__post_init__()

        if self.key_size not in SM4_KEY_SIZES:
            raise ValueError(
                f"Optional key sizes are {SM4_KEY_SIZES}, but got {self.key_size}"
            )

        if self.mode not in {
            constants.SymmetricMode.CTR,
            constants.SymmetricMode.CBC,
            constants.SymmetricMode.GCM,
            constants.SymmetricMode.CFB,
        }:
            raise ValueError(f"Unsupported mode: {self.mode}")


class SM4SymmetricCipher(base.BaseSymmetricCipher[SM4SymmetricRuntimeConfig]):
    """Encrypt and decrypt data with SM4."""

    CIPHER_TYPE: str = constants.SymmetricCipherType.SM4.value

    CONFIG_DATA_CLASS = SM4SymmetricRuntimeConfig

    OPTIONS_DATA_CLASS = SM4SymmetricOptions

    def __init__(
        self,
        key: typing.Optional[typing.Union[bytes, str]] = None,
        **options: object,
    ) -> None:
        super().__init__(key, **options)
        if self.config.key and len(self.config.key) < self.config.key_size:
            self.config.key += b"\x00" * (self.config.key_size - len(self.config.key))

    @staticmethod
    def get_block_size() -> int:
        return SM4_BLOCK_SIZE

    @staticmethod
    def _get_iv(encryption_metadata: base.EncryptionMetadata) -> bytes:
        iv = encryption_metadata.iv
        if iv is None:
            raise ValueError("SM4 IV is required")
        return iv

    def _create_mode(self, iv: bytes) -> SM4Mode:
        if self.config.mode == constants.SymmetricMode.CTR:
            return modes.CTR(iv)
        if self.config.mode == constants.SymmetricMode.CBC:
            return modes.CBC(iv)
        return modes.CFB(iv)

    @staticmethod
    def _update_and_finalize(context: CipherContext, data: bytes) -> bytes:
        updated: bytes = context.update(data)
        finalized: bytes = context.finalize()
        return updated + finalized

    def _encrypt(
        self, plaintext_bytes: bytes, encryption_metadata: base.EncryptionMetadata
    ) -> bytes:
        iv = self._get_iv(encryption_metadata)
        algorithm = algorithms.SM4(self.config.key)
        if self.config.mode == constants.SymmetricMode.GCM:
            gcm_ctx: AEADEncryptionContext = Cipher(algorithm, modes.GCM(iv)).encryptor()
            if self.config.enable_aad:
                aad = encryption_metadata.aad
                if aad is None:
                    raise ValueError("SM4 AAD is required when AAD support is enabled")
                gcm_ctx.authenticate_additional_data(aad)
            ciphertext_bytes = self._update_and_finalize(gcm_ctx, plaintext_bytes)
            encryption_metadata.tag = gcm_ctx.tag
            return ciphertext_bytes

        cipher_ctx: CipherContext = Cipher(algorithm, self._create_mode(iv)).encryptor()
        return self._update_and_finalize(cipher_ctx, plaintext_bytes)

    def _decrypt(
        self, ciphertext_bytes: bytes, encryption_metadata: base.EncryptionMetadata
    ) -> bytes:
        iv = self._get_iv(encryption_metadata)
        algorithm = algorithms.SM4(self.config.key)
        if self.config.mode == constants.SymmetricMode.GCM:
            tag = encryption_metadata.tag
            if tag is None:
                raise ValueError("SM4 GCM authentication tag is required")
            gcm_ctx: AEADDecryptionContext = Cipher(
                algorithm, modes.GCM(iv, tag)
            ).decryptor()
            if self.config.enable_aad:
                aad = encryption_metadata.aad
                if aad is None:
                    raise ValueError("SM4 AAD is required when AAD support is enabled")
                gcm_ctx.authenticate_additional_data(aad)
            return self._update_and_finalize(gcm_ctx, ciphertext_bytes)

        cipher_ctx: CipherContext = Cipher(algorithm, self._create_mode(iv)).decryptor()
        return self._update_and_finalize(cipher_ctx, ciphertext_bytes)
