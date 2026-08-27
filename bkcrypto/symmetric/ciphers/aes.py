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
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter
from Cryptodome.Util.Padding import pad, unpad
from typing_extensions import TypeAlias

from .. import configs, options
from . import base

if typing.TYPE_CHECKING:
    # PyCryptodome's public overloads name their return types from these modules.
    from Cryptodome.Cipher._mode_cbc import CbcMode
    from Cryptodome.Cipher._mode_cfb import CfbMode
    from Cryptodome.Cipher._mode_ctr import CtrMode
    from Cryptodome.Cipher._mode_gcm import GcmMode

AESStandardModeContext: TypeAlias = typing.Union["CtrMode", "CbcMode", "CfbMode"]
AESModeContext: TypeAlias = typing.Union[AESStandardModeContext, "GcmMode"]


@dataclass
class AESSymmetricRuntimeConfig(
    configs.BaseAESSymmetricConfig, base.BaseSymmetricRuntimeConfig
):
    """Store normalized AES runtime configuration."""

    def __post_init__(self) -> None:
        super().__post_init__()

        if self.key_size not in AES.key_size:
            raise ValueError(
                f"Optional key sizes are {AES.key_size}, but got {self.key_size}"
            )

        if (
            self.mode in {constants.SymmetricMode.CBC, constants.SymmetricMode.CTR}
            and self.iv_size != AES.block_size
        ):
            raise ValueError(
                f"AES {self.mode.value} IV must be exactly {AES.block_size} bytes"
            )

        if self.mode not in {
            constants.SymmetricMode.CTR,
            constants.SymmetricMode.CBC,
            constants.SymmetricMode.GCM,
            constants.SymmetricMode.CFB,
        }:
            raise ValueError(f"Unsupported mode: {self.mode}")


class AESSymmetricCipher(base.BaseSymmetricCipher[AESSymmetricRuntimeConfig]):
    """Encrypt and decrypt data with AES."""

    CIPHER_TYPE: str = constants.SymmetricCipherType.AES.value

    CONFIG_DATA_CLASS = AESSymmetricRuntimeConfig

    OPTIONS_DATA_CLASS = options.AESSymmetricOptions

    def __init__(
        self,
        key: typing.Optional[typing.Union[bytes, str]] = None,
        **options: object,
    ) -> None:
        encoding_option: object = options.get("encoding", "utf-8")
        if not isinstance(encoding_option, str):
            raise TypeError("AES encoding must be a string")
        encoding: str = encoding_option
        key_bytes: typing.Optional[bytes] = (
            key.encode(encoding) if isinstance(key, str) else key
        )
        key_size_option: object = options.get("key_size", 16)
        if not isinstance(key_size_option, int):
            raise TypeError("AES key size must be an integer")
        key_size: int = key_size_option
        if key_bytes is not None and len(key_bytes) != key_size:
            raise ValueError(f"AES key must be exactly {key_size} bytes")
        super().__init__(key, **options)

    @staticmethod
    def get_block_size() -> int:
        return AES.block_size

    def _get_iv(
        self, encryption_metadata: base.EncryptionMetadata
    ) -> typing.Optional[bytes]:
        if not self.config.enable_iv:
            return None
        iv = encryption_metadata.iv
        if iv is None:
            raise ValueError("AES IV is required when IV support is enabled")
        if (
            self.config.mode
            in {constants.SymmetricMode.CBC, constants.SymmetricMode.CTR}
            and len(iv) != AES.block_size
        ):
            raise ValueError(
                f"AES {self.config.mode.value} IV must be exactly {AES.block_size} bytes"
            )
        return iv

    def _create_ctx(self, iv: typing.Optional[bytes]) -> AESStandardModeContext:
        if self.config.mode == constants.SymmetricMode.CTR:
            if iv is None:
                return AES.new(self.config.key, AES.MODE_CTR)
            # Size of the counter block must match block size.
            counter = Counter.new(
                self.get_block_size() * 8,
                initial_value=int.from_bytes(iv, byteorder="big"),
            )
            return AES.new(self.config.key, AES.MODE_CTR, counter=counter)
        if self.config.mode == constants.SymmetricMode.CBC:
            return AES.new(self.config.key, AES.MODE_CBC, iv)
        return AES.new(self.config.key, AES.MODE_CFB, iv)

    def _create_gcm_ctx(self, iv: typing.Optional[bytes]) -> "GcmMode":
        if iv is None:
            return AES.new(self.config.key, AES.MODE_GCM)
        return AES.new(self.config.key, AES.MODE_GCM, nonce=iv)

    def _init_gcm_ctx(self, encryption_metadata: base.EncryptionMetadata) -> "GcmMode":
        cipher_ctx = self._create_gcm_ctx(self._get_iv(encryption_metadata))
        if self.config.enable_aad:
            aad = encryption_metadata.aad
            if aad is None:
                raise ValueError("AES AAD is required when AAD support is enabled")
            cipher_ctx.update(aad)
        return cipher_ctx

    def init_ctx(self, encryption_metadata: base.EncryptionMetadata) -> AESModeContext:
        if self.config.mode == constants.SymmetricMode.GCM:
            return self._init_gcm_ctx(encryption_metadata)
        return self._create_ctx(self._get_iv(encryption_metadata))

    def _encrypt(
        self, plaintext_bytes: bytes, encryption_metadata: base.EncryptionMetadata
    ) -> bytes:
        if self.config.mode == constants.SymmetricMode.GCM:
            cipher_ctx = self._init_gcm_ctx(encryption_metadata)
            ciphertext_bytes, tag = cipher_ctx.encrypt_and_digest(plaintext_bytes)
            encryption_metadata.tag = tag
            return ciphertext_bytes

        if (
            self.config.mode == constants.SymmetricMode.CBC
            and self.config.padding == constants.SymmetricPadding.PKCS7
        ):
            plaintext_bytes = pad(plaintext_bytes, AES.block_size, style="pkcs7")

        standard_ctx = self.init_ctx(encryption_metadata)
        return standard_ctx.encrypt(plaintext_bytes)

    def _decrypt(
        self, ciphertext_bytes: bytes, encryption_metadata: base.EncryptionMetadata
    ) -> bytes:
        if self.config.mode == constants.SymmetricMode.CBC and (
            not ciphertext_bytes or len(ciphertext_bytes) % AES.block_size
        ):
            raise ValueError("AES CBC ciphertext must be non-empty and block-aligned")

        if self.config.mode == constants.SymmetricMode.GCM:
            cipher_ctx = self._init_gcm_ctx(encryption_metadata)
            tag = encryption_metadata.tag
            if tag is None:
                raise ValueError("AES GCM authentication tag is required")
            return cipher_ctx.decrypt_and_verify(ciphertext_bytes, tag)

        standard_ctx = self.init_ctx(encryption_metadata)
        decrypted_bytes: bytes = standard_ctx.decrypt(ciphertext_bytes)
        if (
            self.config.mode == constants.SymmetricMode.CBC
            and self.config.padding == constants.SymmetricPadding.PKCS7
        ):
            return unpad(decrypted_bytes, AES.block_size, style="pkcs7")
        return decrypted_bytes
