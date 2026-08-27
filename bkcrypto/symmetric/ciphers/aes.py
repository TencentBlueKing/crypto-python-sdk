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
from cryptography import exceptions
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing_extensions import TypeAlias

from .. import configs, options
from . import base

if typing.TYPE_CHECKING:
    from cryptography.hazmat.decrepit.ciphers import modes as legacy_modes
    from cryptography.hazmat.primitives.ciphers.base import (
        AEADDecryptionContext,
        AEADEncryptionContext,
    )
else:
    try:
        from cryptography.hazmat.decrepit.ciphers import modes as legacy_modes
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import modes as legacy_modes

AES_BLOCK_SIZE = 16
AES_KEY_SIZES = (16, 24, 32)

AESMode: TypeAlias = typing.Union[
    modes.CBC,
    modes.CTR,
    legacy_modes.CFB8,
    modes.GCM,
]


@dataclass
class AESSymmetricRuntimeConfig(
    configs.BaseAESSymmetricConfig, base.BaseSymmetricRuntimeConfig
):
    """Store normalized AES runtime configuration."""

    def __post_init__(self) -> None:
        super().__post_init__()

        if self.key_size not in AES_KEY_SIZES:
            raise ValueError(
                f"Optional key sizes are {AES_KEY_SIZES}, but got {self.key_size}"
            )

        if (
            self.mode in constants.SymmetricMode.block_size_iv_modes()
            and self.iv_size != AES_BLOCK_SIZE
        ):
            raise ValueError(
                f"AES {self.mode.value} IV must be exactly {AES_BLOCK_SIZE} bytes"
            )

        if self.mode not in constants.SymmetricMode.members():
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
        return AES_BLOCK_SIZE

    def _get_iv(
        self, encryption_metadata: base.EncryptionMetadata
    ) -> typing.Optional[bytes]:
        if not self.config.enable_iv:
            return None
        iv = encryption_metadata.iv
        if iv is None:
            raise ValueError("AES IV is required when IV support is enabled")
        if (
            self.config.mode in constants.SymmetricMode.block_size_iv_modes()
            and len(iv) != AES_BLOCK_SIZE
        ):
            raise ValueError(
                f"AES {self.config.mode.value} IV must be exactly {AES_BLOCK_SIZE} bytes"
            )
        return iv

    def _create_cipher(
        self, iv: typing.Optional[bytes], tag: typing.Optional[bytes] = None
    ) -> Cipher[AESMode]:
        if iv is None:
            raise ValueError("AES IV is required")

        if self.config.mode == constants.SymmetricMode.CTR:
            mode: AESMode = modes.CTR(iv)
        elif self.config.mode == constants.SymmetricMode.CBC:
            mode = modes.CBC(iv)
        elif self.config.mode == constants.SymmetricMode.CFB:
            # The legacy backend's CFB default uses an 8-bit segment size.
            mode = legacy_modes.CFB8(iv)
        else:
            mode = modes.GCM(iv, tag)
        return Cipher(algorithms.AES(self.config.key), mode)

    def _get_aad(self, encryption_metadata: base.EncryptionMetadata) -> bytes:
        if not self.config.enable_aad:
            return b""
        aad = encryption_metadata.aad
        if aad is None:
            raise ValueError("AES AAD is required when AAD support is enabled")
        return aad

    @staticmethod
    def _pad_pkcs7(plaintext_bytes: bytes) -> bytes:
        padder = padding.PKCS7(AES_BLOCK_SIZE * 8).padder()
        return padder.update(plaintext_bytes) + padder.finalize()

    @staticmethod
    def _unpad_pkcs7(plaintext_bytes: bytes) -> bytes:
        unpadder = padding.PKCS7(AES_BLOCK_SIZE * 8).unpadder()
        try:
            return unpadder.update(plaintext_bytes) + unpadder.finalize()
        except ValueError as error:
            raise ValueError("Padding is incorrect.") from error

    def _encrypt(
        self, plaintext_bytes: bytes, encryption_metadata: base.EncryptionMetadata
    ) -> bytes:
        if self.config.mode == constants.SymmetricMode.GCM:
            cipher = self._create_cipher(self._get_iv(encryption_metadata))
            gcm_encryptor = typing.cast("AEADEncryptionContext", cipher.encryptor())
            gcm_encryptor.authenticate_additional_data(
                self._get_aad(encryption_metadata)
            )
            ciphertext_bytes: bytes = (
                gcm_encryptor.update(plaintext_bytes) + gcm_encryptor.finalize()
            )
            encryption_metadata.tag = gcm_encryptor.tag
            return ciphertext_bytes

        if (
            self.config.mode == constants.SymmetricMode.CBC
            and self.config.padding == constants.SymmetricPadding.PKCS7
        ):
            plaintext_bytes = self._pad_pkcs7(plaintext_bytes)

        cipher = self._create_cipher(self._get_iv(encryption_metadata))
        standard_encryptor = cipher.encryptor()
        return standard_encryptor.update(plaintext_bytes) + standard_encryptor.finalize()

    def _decrypt(
        self, ciphertext_bytes: bytes, encryption_metadata: base.EncryptionMetadata
    ) -> bytes:
        if self.config.mode == constants.SymmetricMode.CBC and (
            not ciphertext_bytes or len(ciphertext_bytes) % AES_BLOCK_SIZE
        ):
            raise ValueError("AES CBC ciphertext must be non-empty and block-aligned")

        if self.config.mode == constants.SymmetricMode.GCM:
            tag = encryption_metadata.tag
            if tag is None:
                raise ValueError("AES GCM authentication tag is required")
            cipher = self._create_cipher(self._get_iv(encryption_metadata), tag=tag)
            gcm_decryptor = typing.cast("AEADDecryptionContext", cipher.decryptor())
            gcm_decryptor.authenticate_additional_data(
                self._get_aad(encryption_metadata)
            )
            try:
                return gcm_decryptor.update(ciphertext_bytes) + gcm_decryptor.finalize()
            except exceptions.InvalidTag as error:
                raise ValueError("MAC check failed") from error

        cipher = self._create_cipher(self._get_iv(encryption_metadata))
        standard_decryptor = cipher.decryptor()
        decrypted_bytes: bytes = (
            standard_decryptor.update(ciphertext_bytes) + standard_decryptor.finalize()
        )
        if (
            self.config.mode == constants.SymmetricMode.CBC
            and self.config.padding == constants.SymmetricPadding.PKCS7
        ):
            return self._unpad_pkcs7(decrypted_bytes)
        return decrypted_bytes
