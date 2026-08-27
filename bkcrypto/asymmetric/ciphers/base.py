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
import typing
from dataclasses import dataclass

from bkcrypto import constants, types
from dacite import from_dict
from typing_extensions import TypeAlias

from .. import configs
from ..options import AsymmetricOptions

AsymmetricConfigT = typing.TypeVar(
    "AsymmetricConfigT", bound="BaseAsymmetricRuntimeConfig"
)


@dataclass
class BaseAsymmetricRuntimeConfig(configs.BaseAsymmetricConfig):
    """Store normalized runtime configuration for an asymmetric cipher."""

    public_key: typing.Optional[object] = None
    private_key: typing.Optional[object] = None

    def __post_init__(self) -> None:
        pass


class BaseAsymmetricCipher(abc.ABC, typing.Generic[AsymmetricConfigT]):
    """Provide the shared lifecycle for asymmetric cipher implementations."""

    CIPHER_TYPE: str

    # Raw subclasses historically inherit the base runtime config. Concrete
    # generic subclasses override this with the config matching their type arg.
    CONFIG_DATA_CLASS: type[AsymmetricConfigT] = typing.cast(
        "type[AsymmetricConfigT]", BaseAsymmetricRuntimeConfig
    )

    OPTIONS_DATA_CLASS: type[AsymmetricOptions] = AsymmetricOptions

    config: AsymmetricConfigT

    @staticmethod
    @abc.abstractmethod
    def get_block_size(key_obj: object, is_encrypt: bool = True) -> typing.Optional[int]:
        """Return the maximum block size for encryption or decryption.

        The size is measured in bytes; ``None`` means segmentation is unnecessary.
        :param key_obj: Parsed key object whose capacity determines the block size.
        :param is_encrypt: Whether to calculate plaintext capacity for encryption.
        :return: Maximum block length in bytes, or ``None`` when splitting is unused.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def export_public_key(self) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def export_private_key(self) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def _load_public_key(self, public_key_string: types.PublicKeyString) -> object:
        raise NotImplementedError

    @abc.abstractmethod
    def _load_private_key(self, private_key_string: types.PrivateKeyString) -> object:
        raise NotImplementedError

    @staticmethod
    @abc.abstractmethod
    def load_public_key_from_pkey(private_key: object) -> object:
        """Load a public key from a private-key object.

        :param private_key: Parsed private key supplied by the crypto backend.
        :return: Public key derived from ``private_key``.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def generate_key_pair(
        self,
    ) -> tuple[types.PrivateKeyString, types.PublicKeyString]:
        """Generate a key pair.

        :return: Serialized private and public keys, in that order.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def _encrypt(self, plaintext_bytes: bytes) -> bytes:
        raise NotImplementedError

    @abc.abstractmethod
    def _decrypt(self, ciphertext_bytes: bytes) -> bytes:
        raise NotImplementedError

    @abc.abstractmethod
    def _sign(self, plaintext_bytes: bytes) -> bytes:
        raise NotImplementedError

    @abc.abstractmethod
    def _verify(self, plaintext_bytes: bytes, signature_types: bytes) -> bool:
        raise NotImplementedError

    def __init__(
        self,
        public_key_string: typing.Optional[types.PublicKeyString] = None,
        private_key_string: typing.Optional[types.PrivateKeyString] = None,
        public_key_file: typing.Optional[str] = None,
        private_key_file: typing.Optional[str] = None,
        **options: object,
    ) -> None:

        normalized_options: dict[str, object] = dict(options)

        # init config
        self.config = from_dict(self.CONFIG_DATA_CLASS, normalized_options)

        if not (
            public_key_string
            or private_key_string
            or public_key_file
            or private_key_file
        ):
            private_key_string, public_key_string = self.generate_key_pair()

        public_key: typing.Optional[object] = self.load_public_key(
            public_key_string, public_key_file
        )
        private_key: typing.Optional[object] = self.load_private_key(
            private_key_string, private_key_file
        )

        if not public_key and private_key:
            # load public_key_obj from private_key_file
            public_key = self.load_public_key_from_pkey(private_key)

        self.config.public_key = public_key
        self.config.private_key = private_key

    def load_key_base(
        self,
        handle: typing.Callable[[types.KeyString], object],
        key_str: typing.Optional[types.KeyString] = None,
        key_file: typing.Optional[str] = None,
    ) -> typing.Optional[object]:
        """Load a key from a string or file.

        :param handle: Backend parser that converts serialized key text to a key.
        :param key_str: Serialized key supplied directly by the caller.
        :param key_file: Path to a serialized key; its content takes precedence.
        :return: Parsed key object, or ``None`` when neither source is provided.
        """
        key_string_or_none: typing.Optional[str] = self.read_key(key_str, key_file)
        if not key_string_or_none:
            return None

        return handle(key_string_or_none)

    def load_private_key(
        self,
        key_str: typing.Optional[types.PrivateKeyString] = None,
        key_file: typing.Optional[str] = None,
    ) -> typing.Optional[object]:
        """Load a private key.

        :param key_str: Serialized private key supplied directly by the caller.
        :param key_file: Path to a serialized private key.
        :return: Parsed private key, or ``None`` when no key is provided.
        """
        # TODO(crayon,2023/06/15) 支持密码
        return self.load_key_base(self._load_private_key, key_str, key_file)

    def load_public_key(
        self,
        key_str: typing.Optional[types.PublicKeyString] = None,
        key_file: typing.Optional[str] = None,
    ) -> typing.Optional[object]:
        """Load a public key.

        :param key_str: Serialized public key supplied directly by the caller.
        :param key_file: Path to a serialized public key.
        :return: Parsed public key, or ``None`` when no key is provided.
        """
        return self.load_key_base(self._load_public_key, key_str, key_file)

    def _require_key(
        self, key_attribute: constants.AsymmetricKeyAttribute, operation: str
    ) -> None:
        """Ensure a key required by a public operation is configured."""
        key: object = getattr(self.config, key_attribute.value)
        if key is None:
            raise ValueError(
                f"{key_attribute} must be set if you want to call {operation}"
            )

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a string.

        :param plaintext: Text to encrypt with the configured public key.
        :return: Encoded ciphertext produced by the configured converter.
        """
        self._require_key(constants.AsymmetricKeyAttribute.PUBLIC_KEY, "encrypt")
        plaintext = self.config.interceptor.before_encrypt(plaintext)
        plaintext_bytes: bytes = self.config.convertor.encode_plaintext(
            plaintext, encoding=self.config.encoding
        )
        ciphertext_bytes: bytes = self._encrypt(plaintext_bytes)
        ciphertext: str = self.config.convertor.to_string(ciphertext_bytes)
        return self.config.interceptor.after_encrypt(ciphertext, cipher=self)

    def encrypt_bytes(self, plaintext: bytes) -> str:
        """Encrypt binary data without text encoding."""
        self._require_key(constants.AsymmetricKeyAttribute.PUBLIC_KEY, "encrypt_bytes")
        return self.config.convertor.to_string(self._encrypt_bytes(plaintext))

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a string.

        :param ciphertext: Encoded ciphertext to decrypt with the private key.
        :return: Decoded plaintext.
        """
        self._require_key(constants.AsymmetricKeyAttribute.PRIVATE_KEY, "decrypt")
        ciphertext = self.config.interceptor.before_decrypt(ciphertext, cipher=self)
        ciphertext_bytes: bytes = self.config.convertor.from_string(ciphertext)
        plaintext_bytes: bytes = self._decrypt(ciphertext_bytes)
        plaintext: str = self.config.convertor.decode_plaintext(
            plaintext_bytes, encoding=self.config.encoding
        )
        return self.config.interceptor.after_decrypt(plaintext)

    def decrypt_bytes(self, ciphertext: str) -> bytes:
        """Decrypt binary data without text decoding."""
        self._require_key(constants.AsymmetricKeyAttribute.PRIVATE_KEY, "decrypt_bytes")
        return self._decrypt_bytes(self.config.convertor.from_string(ciphertext))

    def _encrypt_bytes(self, plaintext_bytes: bytes) -> bytes:
        return self._encrypt(plaintext_bytes)

    def _decrypt_bytes(self, ciphertext_bytes: bytes) -> bytes:
        return self._decrypt(ciphertext_bytes)

    def sign(self, plaintext: str) -> str:
        """Sign a string with the private key.

        :param plaintext: Text whose encoded bytes will be signed.
        :return: Encoded signature produced by the configured converter.
        """
        self._require_key(constants.AsymmetricKeyAttribute.PRIVATE_KEY, "sign")
        plaintext = self.config.interceptor.before_sign(plaintext)
        plaintext_types: bytes = self.config.convertor.encode_plaintext(
            plaintext, encoding=self.config.encoding
        )
        signature_types: bytes = self._sign(plaintext_types)
        signature: str = self.config.convertor.to_string(signature_types)
        return self.config.interceptor.after_sign(signature)

    def verify(self, plaintext: str, signature: str) -> bool:
        """Verify a signature with the public key.

        :param plaintext: Original text whose signature should be verified.
        :param signature: Encoded signature received from the signer.
        :return: ``True`` when the signature is valid; otherwise ``False``.
        """
        self._require_key(constants.AsymmetricKeyAttribute.PUBLIC_KEY, "verify")
        plaintext, signature = self.config.interceptor.before_verify(
            plaintext, signature
        )
        plaintext_bytes: bytes = self.config.convertor.encode_plaintext(
            plaintext, encoding=self.config.encoding
        )
        signature_bytes: bytes = self.config.convertor.from_string(signature)
        return self._verify(plaintext_bytes, signature_bytes)

    @staticmethod
    def read_key(
        key_string: typing.Optional[types.KeyString] = None,
        key_file: typing.Optional[str] = None,
    ) -> typing.Optional[str]:
        """Read a key from inline content or a file.

        :param key_string: Serialized key supplied directly by the caller.
        :param key_file: Path to a serialized key; its content takes precedence.
        :return: Serialized key content, or ``None`` when no source is provided.
        """
        if not (key_string or key_file):
            return None

        if key_file:
            try:
                with open(encoding="utf-8", file=key_file) as extern_key_fs:
                    key_string = extern_key_fs.read()
            except OSError as e:
                raise OSError(
                    f"can't not read / open extern_key_file -> {key_file}"
                ) from e

        return key_string


AsymmetricCipher: TypeAlias = BaseAsymmetricCipher[typing.Any]
