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

import abc
import copy
import os
import typing
from dataclasses import dataclass, field

from bkcrypto import constants, types
from Cryptodome.Util.Padding import pad, unpad
from dacite import from_dict
from typing_extensions import TypeAlias

from .. import configs
from ..options import SymmetricOptions

SymmetricConfigT = typing.TypeVar("SymmetricConfigT", bound="BaseSymmetricRuntimeConfig")


@dataclass
class EncryptionMetadata:
    """Store metadata required to decrypt a symmetric ciphertext."""

    iv: typing.Optional[types.SymmetricIv] = None
    tag: typing.Optional[types.SymmetricTag] = None
    aad: typing.Optional[types.SymmetricAad] = None


@dataclass
class BaseSymmetricRuntimeConfig(configs.BaseSymmetricConfig):
    """Store normalized runtime configuration for a symmetric cipher."""

    # 对称加密密钥
    key: types.SymmetricKey = field(init=False)

    def __post_init__(self) -> None:
        if self.iv and self.enable_iv:
            self.iv_size = len(self.iv)

        # 非 GCM 模式下 aad 默认关闭
        if self.mode not in {constants.SymmetricMode.GCM}:
            self.enable_aad = False

        if self.aad and self.enable_aad:
            self.aad_size = len(self.aad)


class BaseSymmetricCipher(abc.ABC, typing.Generic[SymmetricConfigT]):
    """Provide the shared lifecycle for symmetric cipher implementations."""

    CIPHER_TYPE: str

    # Raw subclasses historically inherit the base runtime config. Concrete
    # generic subclasses override this with the config matching their type arg.
    CONFIG_DATA_CLASS: type[SymmetricConfigT] = typing.cast(
        "type[SymmetricConfigT]", BaseSymmetricRuntimeConfig
    )

    OPTIONS_DATA_CLASS: type[SymmetricOptions] = SymmetricOptions

    config: SymmetricConfigT

    @staticmethod
    @abc.abstractmethod
    def get_block_size() -> int:
        raise NotImplementedError

    @abc.abstractmethod
    def _encrypt(
        self, plaintext_bytes: bytes, encryption_metadata: EncryptionMetadata
    ) -> bytes:
        raise NotImplementedError

    @abc.abstractmethod
    def _decrypt(
        self, ciphertext_bytes: bytes, encryption_metadata: EncryptionMetadata
    ) -> bytes:
        raise NotImplementedError

    def __init__(
        self,
        key: typing.Optional[typing.Union[bytes, str]] = None,
        **options: object,
    ) -> None:
        """Initialize a symmetric cipher.

        :param key: Raw key bytes or text; a random key is generated when omitted.
        :param options: Algorithm and metadata options used to build the runtime config.
        """
        normalized_options: dict[str, object] = copy.deepcopy(options)

        # init config
        self.config = from_dict(self.CONFIG_DATA_CLASS, normalized_options)

        if key is None:
            key = self.generate_key()

        if isinstance(key, str):
            key = key.encode(self.config.encoding)

        self.config.key = key[: self.config.key_size]

    def generate_key(self) -> types.SymmetricKey:
        """Generate a random key.

        :return: Random key containing ``config.key_size`` bytes.
        """
        return os.urandom(self.config.key_size)

    def generate_iv(self) -> types.SymmetricIv:
        """Generate a random initialization vector.

        :return: Random initialization vector containing ``config.iv_size`` bytes.
        """
        return os.urandom(self.config.iv_size)

    def generate_aad(self) -> types.SymmetricAad:
        """Generate random GCM associated data.

        :return: Random associated data containing ``config.aad_size`` bytes.
        """
        return os.urandom(self.config.aad_size)

    def combine_encryption_metadata(
        self, ciphertext_bytes: bytes, encryption_metadata: EncryptionMetadata
    ) -> str:
        combination_mode: str = self.config.encryption_metadata_combination_mode.value
        combine_encryption_metadata_handle: typing.Callable[
            [bytes, EncryptionMetadata], str
        ] = getattr(
            self,
            f"combine_encryption_metadata_with_{combination_mode}",
        )
        return combine_encryption_metadata_handle(ciphertext_bytes, encryption_metadata)

    def extract_encryption_metadata(
        self, ciphertext: str
    ) -> tuple[bytes, EncryptionMetadata]:
        combination_mode: str = self.config.encryption_metadata_combination_mode.value
        extract_encryption_metadata_handle: typing.Callable[
            [str], tuple[bytes, EncryptionMetadata]
        ] = getattr(
            self,
            f"extract_encryption_metadata_from_{combination_mode}",
        )
        return extract_encryption_metadata_handle(ciphertext)

    def combine_encryption_metadata_with_bytes(
        self, ciphertext_bytes: bytes, encryption_metadata: EncryptionMetadata
    ) -> str:
        """Combine ciphertext and encryption metadata as bytes.

        携带顺序：iv + tag + aad + 密文。
        :param ciphertext_bytes: Raw encrypted payload.
        :param encryption_metadata: IV, authentication tag, and associated data.
        :return: Encoded metadata and ciphertext in byte-combination order.
        """
        combination_bytes: bytes = b""
        if encryption_metadata.iv:
            combination_bytes += encryption_metadata.iv
        if encryption_metadata.tag:
            # padded_tag_size >= 2 * length(tag)，填充后长度固定为 padded_tag_size
            combination_bytes += pad(
                encryption_metadata.tag,
                block_size=self.config.padded_tag_size,
                style="iso7816",
            )
        if encryption_metadata.aad:
            combination_bytes += encryption_metadata.aad

        combination_bytes += ciphertext_bytes

        ciphertext: str = self.config.convertor.to_string(combination_bytes)
        return ciphertext

    def combine_encryption_metadata_with_string_sep(
        self, ciphertext_bytes: bytes, encryption_metadata: EncryptionMetadata
    ) -> str:
        """Join encoded ciphertext and metadata with a separator.

        携带顺序：iv + tag + aad + 密文。
        :param ciphertext_bytes: Raw encrypted payload.
        :param encryption_metadata: IV, authentication tag, and associated data.
        :return: Encoded metadata and ciphertext joined by the configured separator.
        """
        iv_str_or_none: typing.Optional[str] = None
        tag_str_or_none: typing.Optional[str] = None
        aad_str_or_none: typing.Optional[str] = None

        if encryption_metadata.iv is not None:
            iv_str_or_none = self.config.convertor.to_string(encryption_metadata.iv)
        if encryption_metadata.tag is not None:
            tag_str_or_none = self.config.convertor.to_string(encryption_metadata.tag)
        if encryption_metadata.aad is not None:
            aad_str_or_none = self.config.convertor.to_string(encryption_metadata.aad)

        encoded_ciphertext: str = self.config.convertor.to_string(ciphertext_bytes)
        combination: list[typing.Optional[str]] = [
            iv_str_or_none,
            tag_str_or_none,
            aad_str_or_none,
            encoded_ciphertext,
        ]
        # 仅过滤 None 值，密文可能是空串，也需要进行分隔
        combined_ciphertext: str = self.config.metadata_combination_separator.join(
            part for part in combination if part is not None
        )
        return combined_ciphertext

    def extract_encryption_metadata_from_bytes(
        self, ciphertext: str
    ) -> tuple[bytes, EncryptionMetadata]:
        """Extract ciphertext and encryption metadata from bytes.

        :param ciphertext: Encoded byte-combined metadata and encrypted payload.
        :return: Raw ciphertext and the extracted encryption metadata.
        """
        tag_or_none: typing.Optional[types.SymmetricTag] = None
        aad_or_none: typing.Optional[types.SymmetricAad] = None
        iv_or_none: typing.Optional[types.SymmetricIv] = None
        ciphertext_bytes: bytes = self.config.convertor.from_string(ciphertext)

        pointer: int = 0
        if self.config.enable_iv:
            iv_or_none = ciphertext_bytes[pointer : pointer + self.config.iv_size]
            pointer += self.config.iv_size

        # 只有 GCM 模式支持 tag
        if self.config.mode in {constants.SymmetricMode.GCM}:
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

    def extract_encryption_metadata_from_string_sep(
        self, ciphertext: str
    ) -> tuple[bytes, EncryptionMetadata]:
        """Extract ciphertext and encryption metadata from a string.

        :param ciphertext: Separator-joined metadata and encrypted payload.
        :return: Raw ciphertext and the extracted encryption metadata.
        """
        iv_or_none: typing.Optional[types.SymmetricIv] = None
        tag_or_none: typing.Optional[types.SymmetricTag] = None
        aad_or_none: typing.Optional[types.SymmetricAad] = None

        if self.config.enable_iv:
            iv_str, ciphertext = ciphertext.split(
                self.config.metadata_combination_separator, 1
            )
            iv_or_none = self.config.convertor.from_string(iv_str)
        # 只有 GCM 模式支持 tag
        if self.config.mode in {constants.SymmetricMode.GCM}:
            tag_str, ciphertext = ciphertext.split(
                self.config.metadata_combination_separator, 1
            )
            tag_or_none = self.config.convertor.from_string(tag_str)
        if self.config.enable_aad:
            aad_str, ciphertext = ciphertext.split(
                self.config.metadata_combination_separator, 1
            )
            aad_or_none = self.config.convertor.from_string(aad_str)

        ciphertext_bytes = self.config.convertor.from_string(ciphertext)

        return ciphertext_bytes, EncryptionMetadata(iv_or_none, tag_or_none, aad_or_none)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a string.

        :param plaintext: Text to encode and encrypt.
        :return: Encoded ciphertext with the metadata required for decryption.
        """
        plaintext = self.config.interceptor.before_encrypt(plaintext, cipher=self)
        plaintext_bytes: bytes = self.config.convertor.encode_plaintext(
            plaintext, encoding=self.config.encoding
        )

        ciphertext: str = self._encrypt_bytes(plaintext_bytes)
        return self.config.interceptor.after_encrypt(ciphertext, cipher=self)

    def encrypt_bytes(self, plaintext: bytes) -> str:
        """Encrypt binary data without text encoding."""
        return self._encrypt_bytes(plaintext)

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a string.

        :param ciphertext: Encoded ciphertext and encryption metadata.
        :return: Decoded plaintext.
        """
        ciphertext = self.config.interceptor.before_decrypt(ciphertext, cipher=self)
        plaintext_bytes: bytes = self.decrypt_bytes(ciphertext)
        plaintext: str = self.config.convertor.decode_plaintext(
            plaintext_bytes, encoding=self.config.encoding
        )
        return self.config.interceptor.after_decrypt(plaintext, cipher=self)

    def decrypt_bytes(self, ciphertext: str) -> bytes:
        """Decrypt binary data without text decoding."""
        ciphertext_bytes, encryption_metadata = self.extract_encryption_metadata(
            ciphertext
        )
        return self._decrypt(ciphertext_bytes, encryption_metadata)

    def _encrypt_bytes(self, plaintext_bytes: bytes) -> str:
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
        ciphertext_bytes: bytes = self._encrypt(plaintext_bytes, encryption_metadata)
        return self.combine_encryption_metadata(ciphertext_bytes, encryption_metadata)


SymmetricCipher: TypeAlias = BaseSymmetricCipher[typing.Any]
