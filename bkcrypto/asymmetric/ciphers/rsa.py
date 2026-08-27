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

from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA1
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature.pss import MGF1

from bkcrypto import constants, types

from .. import configs
from ..options import RSAAsymmetricOptions
from . import base


@dataclass
class RSAAsymmetricRuntimeConfig(configs.BaseRSAAsymmetricConfig, base.BaseAsymmetricRuntimeConfig):
    public_key: typing.Optional[RSA.RsaKey] = None
    private_key: typing.Optional[RSA.RsaKey] = None

    cipher_maker: types.RSACipherMaker = None
    sig_scheme_maker: types.RSASigSchemeMaker = None

    def __post_init__(self):
        if self.padding == constants.RSACipherPadding.PKCS1_OAEP:
            self.cipher_maker = self._make_oaep_cipher
        else:
            self.cipher_maker = constants.RSACipherPadding.get_cipher_maker_by_member(self.padding)
        self.sig_scheme_maker = constants.RSASigScheme.get_sig_scheme_maker_by_member(self.sig_scheme)

        super().__post_init__()

    def _make_oaep_cipher(self, key: RSA.RsaKey) -> types.RSACipher:
        return PKCS1_OAEP.new(
            key,
            hashAlgo=self.oaep_hash,
            mgfunc=lambda seed, length: MGF1(seed, length, self.mgf1_hash),
            label=self.oaep_label or b"",
        )


class RSAAsymmetricCipher(base.BaseAsymmetricCipher):

    CIPHER_TYPE: str = constants.AsymmetricCipherType.RSA.value

    CONFIG_DATA_CLASS: typing.Type[RSAAsymmetricRuntimeConfig] = RSAAsymmetricRuntimeConfig

    OPTIONS_DATA_CLASS: typing.Type[RSAAsymmetricOptions] = RSAAsymmetricOptions

    config: RSAAsymmetricRuntimeConfig = None

    def export_public_key(self) -> str:
        return self.config.public_key.exportKey().decode(encoding=self.config.encoding)

    def export_private_key(self) -> str:
        return self.config.private_key.exportKey().decode(encoding=self.config.encoding)

    def _load_public_key(self, public_key_string: types.PublicKeyString) -> RSA.RsaKey:
        try:
            public_key: RSA.RsaKey = RSA.import_key(public_key_string)
        except (IndexError, TypeError, ValueError) as error:
            raise ValueError("Invalid RSA public key") from error
        if public_key.has_private():
            return public_key.publickey()
        return public_key

    def _load_private_key(self, private_key_string: types.PrivateKeyString) -> RSA.RsaKey:
        try:
            private_key: RSA.RsaKey = RSA.import_key(private_key_string)
        except (IndexError, TypeError, ValueError) as error:
            raise ValueError("Invalid RSA private key") from error
        if not private_key.has_private():
            raise ValueError("Expected an RSA private key")
        return private_key

    def generate_key_pair(self) -> typing.Tuple[types.PrivateKeyString, types.PublicKeyString]:
        private_key_obj: RSA.RsaKey = RSA.generate(self.config.pkey_bits)
        private_key: bytes = private_key_obj.export_key(format="PEM", pkcs=1)
        public_key: bytes = private_key_obj.publickey().export_key(format="PEM")
        return private_key.decode(encoding=self.config.encoding), public_key.decode(encoding=self.config.encoding)

    def _encrypt(self, plaintext_bytes: bytes) -> bytes:
        block_size: int = self._get_encrypt_block_size()
        if not self.config.enable_segmented_encryption:
            return self._encrypt_bytes(plaintext_bytes)
        cipher: types.RSACipher = self.config.cipher_maker(self.config.public_key)
        return b"".join(cipher.encrypt(block) for block in self.block_list(plaintext_bytes, block_size))

    def _decrypt(self, ciphertext_bytes: bytes) -> bytes:
        if not self.config.enable_segmented_encryption:
            return self._decrypt_bytes(ciphertext_bytes)

        block_size: int = self.get_block_size(self.config.private_key, is_encrypt=False)
        if len(ciphertext_bytes) % block_size:
            raise ValueError("Invalid RSA ciphertext length")
        cipher: types.RSACipher = self.config.cipher_maker(self.config.private_key)
        return b"".join(self._decrypt_block(cipher, block) for block in self.block_list(ciphertext_bytes, block_size))

    def _encrypt_bytes(self, plaintext_bytes: bytes) -> bytes:
        if len(plaintext_bytes) > self._get_encrypt_block_size():
            raise ValueError("RSA plaintext is too long")
        cipher: types.RSACipher = self.config.cipher_maker(self.config.public_key)
        return cipher.encrypt(plaintext_bytes)

    def _decrypt_bytes(self, ciphertext_bytes: bytes) -> bytes:
        block_size: int = self.get_block_size(self.config.private_key, is_encrypt=False)
        if len(ciphertext_bytes) != block_size:
            raise ValueError("Invalid RSA ciphertext length")
        cipher: types.RSACipher = self.config.cipher_maker(self.config.private_key)
        return self._decrypt_block(cipher, ciphertext_bytes)

    def _decrypt_block(self, cipher: types.RSACipher, ciphertext_bytes: bytes) -> bytes:
        if self.config.padding == constants.RSACipherPadding.PKCS1_OAEP:
            return cipher.decrypt(ciphertext_bytes)

        plaintext_bytes: typing.Optional[bytes] = cipher.decrypt(ciphertext_bytes, None)
        if plaintext_bytes is None:
            raise ValueError("Invalid RSA ciphertext")
        return plaintext_bytes

    def _get_encrypt_block_size(self) -> int:
        return self.get_block_size(
            self.config.public_key,
            padding=self.config.padding,
            oaep_hash=self.config.oaep_hash,
        )

    def _sign(self, plaintext_bytes: bytes) -> bytes:
        sig_scheme: types.RSASigScheme = self.config.sig_scheme_maker(self.config.private_key)
        sha: SHA1.SHA1Hash = SHA1.new(plaintext_bytes)
        return sig_scheme.sign(sha)

    def _verify(self, plaintext_bytes: bytes, signature_types: bytes) -> bool:
        sig_scheme: types.RSASigScheme = self.config.sig_scheme_maker(self.config.public_key)
        sha: SHA1.SHA1Hash = SHA1.new(plaintext_bytes)
        return sig_scheme.verify(sha, signature_types)

    @staticmethod
    def load_public_key_from_pkey(private_key: RSA.RsaKey) -> RSA.RsaKey:
        return private_key.publickey()

    @staticmethod
    def block_list(
        lst: typing.Union[str, bytes, typing.List[typing.Any]], block_size
    ) -> typing.Union[str, bytes, typing.List[typing.Any]]:
        """
        序列切片
        :param lst:
        :param block_size:
        :return:
        """
        for idx in range(0, len(lst), block_size):
            yield lst[idx : idx + block_size]

    @staticmethod
    def get_block_size(
        key_obj: RSA.RsaKey,
        is_encrypt: bool = True,
        padding: constants.RSACipherPadding = constants.RSACipherPadding.PKCS1_v1_5,
        oaep_hash: typing.Any = SHA1,
    ) -> int:
        """
        获取加解密最大片长度，用于分割过长的文本，单位：bytes
        :param key_obj:
        :param is_encrypt:
        :return:
        """
        if not is_encrypt:
            return key_obj.size_in_bytes()
        if padding == constants.RSACipherPadding.PKCS1_OAEP:
            return key_obj.size_in_bytes() - 2 * oaep_hash.digest_size - 2
        return key_obj.size_in_bytes() - 11
