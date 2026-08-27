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

from bkcrypto import constants, types
from cryptography import exceptions
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric import rsa

from .. import configs
from ..options import RSAAsymmetricOptions
from . import base


@dataclass
class RSAAsymmetricRuntimeConfig(
    configs.BaseRSAAsymmetricConfig, base.BaseAsymmetricRuntimeConfig
):
    """Store normalized RSA runtime configuration."""

    public_key: typing.Optional[rsa.RSAPublicKey] = None
    private_key: typing.Optional[rsa.RSAPrivateKey] = None


class RSAAsymmetricCipher(base.BaseAsymmetricCipher[RSAAsymmetricRuntimeConfig]):
    """Encrypt, decrypt, sign, and verify data with RSA."""

    CIPHER_TYPE: str = constants.AsymmetricCipherType.RSA.value

    CONFIG_DATA_CLASS = RSAAsymmetricRuntimeConfig

    OPTIONS_DATA_CLASS = RSAAsymmetricOptions

    def _public_key(self) -> rsa.RSAPublicKey:
        public_key: typing.Optional[rsa.RSAPublicKey] = self.config.public_key
        if public_key is None:
            raise ValueError("RSA public key is not configured")
        return public_key

    def _private_key(self) -> rsa.RSAPrivateKey:
        private_key: typing.Optional[rsa.RSAPrivateKey] = self.config.private_key
        if private_key is None:
            raise ValueError("RSA private key is not configured")
        return private_key

    def export_public_key(self) -> str:
        public_key: bytes = self._public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return public_key.decode(encoding=self.config.encoding)

    def export_private_key(self) -> str:
        private_key: bytes = self._private_key().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return private_key.decode(encoding=self.config.encoding)

    def _load_public_key(
        self, public_key_string: types.PublicKeyString
    ) -> rsa.RSAPublicKey:
        key_bytes: bytes = public_key_string.encode(self.config.encoding)
        key_loaders: tuple[typing.Callable[[], object], ...] = (
            lambda: serialization.load_pem_public_key(key_bytes),
            lambda: serialization.load_ssh_public_key(key_bytes),
            lambda: serialization.load_pem_private_key(key_bytes, password=None),
        )
        last_error: typing.Optional[Exception] = None

        for load_key in key_loaders:
            try:
                loaded_key: object = load_key()
            except (TypeError, ValueError, exceptions.UnsupportedAlgorithm) as error:
                last_error = error
                continue

            if isinstance(loaded_key, rsa.RSAPrivateKey):
                return loaded_key.public_key()
            if isinstance(loaded_key, rsa.RSAPublicKey):
                return loaded_key
            raise ValueError("Invalid RSA public key")  # noqa: TRY004

        raise ValueError("Invalid RSA public key") from last_error

    def _load_private_key(
        self, private_key_string: types.PrivateKeyString
    ) -> rsa.RSAPrivateKey:
        try:
            loaded_key: object = serialization.load_pem_private_key(
                private_key_string.encode(self.config.encoding), password=None
            )
        except (TypeError, ValueError, exceptions.UnsupportedAlgorithm) as error:
            raise ValueError("Invalid RSA private key") from error
        if not isinstance(loaded_key, rsa.RSAPrivateKey):
            raise ValueError("Expected an RSA private key")  # noqa: TRY004
        return loaded_key

    def generate_key_pair(
        self,
    ) -> tuple[types.PrivateKeyString, types.PublicKeyString]:
        private_key_obj: rsa.RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537, key_size=self.config.pkey_bits
        )
        private_key: bytes = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_key: bytes = private_key_obj.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_key.decode(encoding=self.config.encoding), public_key.decode(
            encoding=self.config.encoding
        )

    def _encryption_padding(self) -> asymmetric_padding.AsymmetricPadding:
        if self.config.padding == constants.RSACipherPadding.PKCS1_OAEP:
            return asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(self.config.mgf1_hash),
                algorithm=self.config.oaep_hash,
                label=self.config.oaep_label,
            )
        return asymmetric_padding.PKCS1v15()

    def _signature_padding(self) -> asymmetric_padding.AsymmetricPadding:
        if self.config.sig_scheme == constants.RSASigScheme.PKCS1_PSS:
            digest_size: int = hashes.SHA1().digest_size
            return asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA1()),
                salt_length=digest_size,
            )
        return asymmetric_padding.PKCS1v15()

    def _encrypt(self, plaintext_bytes: bytes) -> bytes:
        block_size: int = self._get_encrypt_block_size()
        if not self.config.enable_segmented_encryption:
            return self._encrypt_bytes(plaintext_bytes)
        return b"".join(
            self._encrypt_block(block)
            for block in self.block_list(plaintext_bytes, block_size)
        )

    def _decrypt(self, ciphertext_bytes: bytes) -> bytes:
        if not self.config.enable_segmented_encryption:
            return self._decrypt_bytes(ciphertext_bytes)

        block_size: int = self.get_block_size(self._private_key(), is_encrypt=False)
        if len(ciphertext_bytes) % block_size:
            raise ValueError("Invalid RSA ciphertext length")
        return b"".join(
            self._decrypt_block(block)
            for block in self.block_list(ciphertext_bytes, block_size)
        )

    def _encrypt_bytes(self, plaintext_bytes: bytes) -> bytes:
        if len(plaintext_bytes) > self._get_encrypt_block_size():
            raise ValueError("RSA plaintext is too long")
        return self._encrypt_block(plaintext_bytes)

    def _decrypt_bytes(self, ciphertext_bytes: bytes) -> bytes:
        block_size: int = self.get_block_size(self._private_key(), is_encrypt=False)
        if len(ciphertext_bytes) != block_size:
            raise ValueError("Invalid RSA ciphertext length")
        return self._decrypt_block(ciphertext_bytes)

    def _encrypt_block(self, plaintext_bytes: bytes) -> bytes:
        return self._public_key().encrypt(plaintext_bytes, self._encryption_padding())

    def _decrypt_block(self, ciphertext_bytes: bytes) -> bytes:
        try:
            return self._private_key().decrypt(
                ciphertext_bytes, self._encryption_padding()
            )
        except ValueError as error:
            if self.config.padding == constants.RSACipherPadding.PKCS1_OAEP:
                raise ValueError("Incorrect decryption.") from error
            raise ValueError("Invalid RSA ciphertext") from error

    def _get_encrypt_block_size(self) -> int:
        return self.get_block_size(
            self._public_key(),
            padding=self.config.padding,
            oaep_hash=self.config.oaep_hash,
        )

    def _sign(self, plaintext_bytes: bytes) -> bytes:
        return self._private_key().sign(
            plaintext_bytes, self._signature_padding(), hashes.SHA1()
        )

    def _verify(self, plaintext_bytes: bytes, signature_types: bytes) -> bool:
        try:
            self._public_key().verify(
                signature_types,
                plaintext_bytes,
                self._signature_padding(),
                hashes.SHA1(),
            )
        except (exceptions.InvalidSignature, TypeError, ValueError):
            return False
        return True

    @staticmethod
    def load_public_key_from_pkey(private_key: object) -> rsa.RSAPublicKey:
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TypeError("Expected an RSA private key")
        return private_key.public_key()

    @staticmethod
    def block_list(lst: bytes, block_size: int) -> typing.Iterator[bytes]:
        """Yield fixed-size blocks from a byte sequence.

        :param lst: Byte sequence to divide into consecutive blocks.
        :param block_size: Maximum number of bytes yielded per block.
        :return: Iterator over the blocks, including a shorter final block if needed.
        """
        for idx in range(0, len(lst), block_size):
            yield lst[idx : idx + block_size]

    @staticmethod
    def get_block_size(
        key_obj: object,
        is_encrypt: bool = True,
        padding: constants.RSACipherPadding = constants.RSACipherPadding.PKCS1_v1_5,
        oaep_hash: hashes.HashAlgorithm = configs.DEFAULT_RSA_HASH,
    ) -> int:
        """Return the maximum RSA block size in bytes.

        :param key_obj: Parsed RSA key whose modulus determines the block size.
        :param is_encrypt: Whether to calculate plaintext rather than ciphertext size.
        :param padding: Padding scheme whose overhead limits plaintext capacity.
        :param oaep_hash: Hash algorithm used to calculate OAEP padding overhead.
        :return: Maximum plaintext size or ciphertext block size, in bytes.
        """
        if not isinstance(key_obj, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
            raise TypeError("Expected an RSA key")
        block_size: int = (key_obj.key_size + 7) // 8
        if not is_encrypt:
            return block_size
        if padding == constants.RSACipherPadding.PKCS1_OAEP:
            return block_size - 2 * oaep_hash.digest_size - 2
        return block_size - 11
