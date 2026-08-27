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
from dataclasses import dataclass, field

from bkcrypto import constants, types
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Cryptodome.Cipher.PKCS1_v1_5 import PKCS115_Cipher
from Cryptodome.Hash import SHA1
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature.pss import MGF1

from .. import configs
from ..options import RSAAsymmetricOptions
from . import base


@dataclass
class RSAAsymmetricRuntimeConfig(
    configs.BaseRSAAsymmetricConfig, base.BaseAsymmetricRuntimeConfig
):
    """Store normalized RSA runtime configuration."""

    public_key: typing.Optional[RSA.RsaKey] = None
    private_key: typing.Optional[RSA.RsaKey] = None

    cipher_maker: types.RSACipherMaker = field(init=False)
    sig_scheme_maker: types.RSASigSchemeMaker = field(init=False)

    def __post_init__(self) -> None:
        if self.padding == constants.RSACipherPadding.PKCS1_OAEP:
            self.cipher_maker = self._make_oaep_cipher
        else:
            self.cipher_maker = constants.RSACipherPadding.get_cipher_maker_by_member(
                self.padding
            )
        self.sig_scheme_maker = constants.RSASigScheme.get_sig_scheme_maker_by_member(
            self.sig_scheme
        )

        super().__post_init__()

    def _make_oaep_cipher(self, key: RSA.RsaKey) -> types.RSACipher:
        return PKCS1_OAEP.new(
            key,
            hashAlgo=self.oaep_hash,
            mgfunc=self._mgf1,
            label=self.oaep_label or b"",
        )

    def _mgf1(self, seed: bytes, length: int) -> bytes:
        # PyCryptodome's MGF1 stub does not accept an equivalent external hash
        # protocol, so narrow that mismatch at the dependency boundary.
        mgf1 = typing.cast("types.MaskFunction", MGF1)
        return mgf1(seed, length, self.mgf1_hash)


class RSAAsymmetricCipher(base.BaseAsymmetricCipher[RSAAsymmetricRuntimeConfig]):
    """Encrypt, decrypt, sign, and verify data with RSA."""

    CIPHER_TYPE: str = constants.AsymmetricCipherType.RSA.value

    CONFIG_DATA_CLASS = RSAAsymmetricRuntimeConfig

    OPTIONS_DATA_CLASS = RSAAsymmetricOptions

    def _public_key(self) -> RSA.RsaKey:
        public_key: typing.Optional[RSA.RsaKey] = self.config.public_key
        if public_key is None:
            raise ValueError("RSA public key is not configured")
        return public_key

    def _private_key(self) -> RSA.RsaKey:
        private_key: typing.Optional[RSA.RsaKey] = self.config.private_key
        if private_key is None:
            raise ValueError("RSA private key is not configured")
        return private_key

    def export_public_key(self) -> str:
        return self._public_key().exportKey().decode(encoding=self.config.encoding)

    def export_private_key(self) -> str:
        return self._private_key().exportKey().decode(encoding=self.config.encoding)

    def _load_public_key(self, public_key_string: types.PublicKeyString) -> RSA.RsaKey:
        try:
            public_key: RSA.RsaKey = RSA.import_key(
                public_key_string.encode(self.config.encoding)
            )
        except (IndexError, TypeError, ValueError) as error:
            raise ValueError("Invalid RSA public key") from error
        if public_key.has_private():
            return public_key.publickey()
        return public_key

    def _load_private_key(
        self, private_key_string: types.PrivateKeyString
    ) -> RSA.RsaKey:
        try:
            private_key: RSA.RsaKey = RSA.import_key(
                private_key_string.encode(self.config.encoding)
            )
        except (IndexError, TypeError, ValueError) as error:
            raise ValueError("Invalid RSA private key") from error
        if not private_key.has_private():
            raise ValueError("Expected an RSA private key")
        return private_key

    def generate_key_pair(
        self,
    ) -> tuple[types.PrivateKeyString, types.PublicKeyString]:
        private_key_obj: RSA.RsaKey = RSA.generate(self.config.pkey_bits)
        private_key: bytes = private_key_obj.export_key(format="PEM", pkcs=1)
        public_key: bytes = private_key_obj.publickey().export_key(format="PEM")
        return private_key.decode(encoding=self.config.encoding), public_key.decode(
            encoding=self.config.encoding
        )

    def _encrypt(self, plaintext_bytes: bytes) -> bytes:
        block_size: int = self._get_encrypt_block_size()
        if not self.config.enable_segmented_encryption:
            return self._encrypt_bytes(plaintext_bytes)
        cipher: types.RSACipher = self.config.cipher_maker(self._public_key())
        return b"".join(
            cipher.encrypt(block)
            for block in self.block_list(plaintext_bytes, block_size)
        )

    def _decrypt(self, ciphertext_bytes: bytes) -> bytes:
        if not self.config.enable_segmented_encryption:
            return self._decrypt_bytes(ciphertext_bytes)

        block_size: int = self.get_block_size(self._private_key(), is_encrypt=False)
        if len(ciphertext_bytes) % block_size:
            raise ValueError("Invalid RSA ciphertext length")
        cipher: types.RSACipher = self.config.cipher_maker(self._private_key())
        return b"".join(
            self._decrypt_block(cipher, block)
            for block in self.block_list(ciphertext_bytes, block_size)
        )

    def _encrypt_bytes(self, plaintext_bytes: bytes) -> bytes:
        if len(plaintext_bytes) > self._get_encrypt_block_size():
            raise ValueError("RSA plaintext is too long")
        cipher: types.RSACipher = self.config.cipher_maker(self._public_key())
        return cipher.encrypt(plaintext_bytes)

    def _decrypt_bytes(self, ciphertext_bytes: bytes) -> bytes:
        block_size: int = self.get_block_size(self._private_key(), is_encrypt=False)
        if len(ciphertext_bytes) != block_size:
            raise ValueError("Invalid RSA ciphertext length")
        cipher: types.RSACipher = self.config.cipher_maker(self._private_key())
        return self._decrypt_block(cipher, ciphertext_bytes)

    def _decrypt_block(self, cipher: types.RSACipher, ciphertext_bytes: bytes) -> bytes:
        if self.config.padding == constants.RSACipherPadding.PKCS1_OAEP:
            if not isinstance(cipher, PKCS1OAEP_Cipher):
                raise TypeError("RSA OAEP factory returned an invalid cipher")
            return cipher.decrypt(ciphertext_bytes)

        if not isinstance(cipher, PKCS115_Cipher):
            raise TypeError("RSA PKCS#1 v1.5 factory returned an invalid cipher")
        plaintext_bytes: typing.Optional[bytes] = cipher.decrypt(ciphertext_bytes, None)
        if plaintext_bytes is None:
            raise ValueError("Invalid RSA ciphertext")
        return plaintext_bytes

    def _get_encrypt_block_size(self) -> int:
        return self.get_block_size(
            self._public_key(),
            padding=self.config.padding,
            oaep_hash=self.config.oaep_hash,
        )

    def _sign(self, plaintext_bytes: bytes) -> bytes:
        sig_scheme: types.RSASigScheme = self.config.sig_scheme_maker(
            self._private_key()
        )
        # PyCryptodome's PSS stub names update()'s parameter differently from
        # its SHA1 stub, making the documented companion types incompatible.
        sha: typing.Any = SHA1.new(plaintext_bytes)
        return sig_scheme.sign(sha)

    def _verify(self, plaintext_bytes: bytes, signature_types: bytes) -> bool:
        sig_scheme: types.RSASigScheme = self.config.sig_scheme_maker(self._public_key())
        sha: typing.Any = SHA1.new(plaintext_bytes)
        try:
            sig_scheme.verify(sha, signature_types)
        except (TypeError, ValueError):
            return False
        return True

    @staticmethod
    def load_public_key_from_pkey(private_key: object) -> RSA.RsaKey:
        if not isinstance(private_key, RSA.RsaKey):
            raise TypeError("Expected an RSA private key")
        return private_key.publickey()

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
        oaep_hash: types.HashModule = configs.DEFAULT_RSA_HASH,
    ) -> int:
        """Return the maximum RSA block size in bytes.

        :param key_obj: Parsed RSA key whose modulus determines the block size.
        :param is_encrypt: Whether to calculate plaintext rather than ciphertext size.
        :param padding: Padding scheme whose overhead limits plaintext capacity.
        :param oaep_hash: Hash module used to calculate OAEP padding overhead.
        :return: Maximum plaintext size or ciphertext block size, in bytes.
        """
        if not isinstance(key_obj, RSA.RsaKey):
            raise TypeError("Expected an RSA key")
        if not is_encrypt:
            return key_obj.size_in_bytes()
        if padding == constants.RSACipherPadding.PKCS1_OAEP:
            return key_obj.size_in_bytes() - 2 * oaep_hash.digest_size - 2
        return key_obj.size_in_bytes() - 11
