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

from Cryptodome import Util
from Cryptodome.Hash import SHA1
from Cryptodome.PublicKey import RSA

from bkcrypto import constants, types

from . import base


@dataclass
class RSAAsymmetricConfig(base.BaseAsymmetricConfig):
    public_key: typing.Optional[RSA.RsaKey] = None
    private_key: typing.Optional[RSA.RsaKey] = None

    # 加解密填充方案，默认为 `PKCS1_v1_5`
    rsa_padding: constants.RSACipherPadding = constants.RSACipherPadding.PKCS1_v1_5
    # 签名方案，默认为 `PKCS1_v1_5`
    rsa_sig_scheme: constants.RSASigScheme = constants.RSASigScheme.PKCS1_v1_5
    # 密钥长度（bit）
    # In 2017, a sufficient length is deemed to be 2048 bits.
    # 具体参考 -> https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html
    rsa_pkey_bits: int = 2048

    cipher_maker: types.RSACipherMaker = None
    sig_scheme_maker: types.RSASigSchemeMaker = None

    def __post_init__(self):
        # TODO(crayon) hashAlgo 哈希算法注入
        self.cipher_maker = constants.RSACipherPadding.get_cipher_maker_by_member(self.rsa_padding)
        self.sig_scheme_maker = constants.RSASigScheme.get_sig_scheme_maker_by_member(self.rsa_sig_scheme)

        super().__post_init__()


class RSAAsymmetricCipher(base.BaseAsymmetricCipher):

    CONFIG_DATA_CLASS: typing.Type[base.BaseAsymmetricConfig] = RSAAsymmetricConfig

    config: RSAAsymmetricConfig = None

    def _load_public_key(self, public_key_string: types.PublicKeyString) -> RSA.RsaKey:
        return RSA.importKey(public_key_string)

    def _load_private_key(self, private_key_string: types.PrivateKeyString) -> RSA.RsaKey:
        return RSA.importKey(private_key_string)

    def generate_key_pair(self) -> typing.Tuple[types.PrivateKeyString, types.PublicKeyString]:
        private_key_obj: RSA.RsaKey = RSA.generate(self.config.rsa_pkey_bits)
        private_key: bytes = private_key_obj.exportKey()
        public_key: bytes = private_key_obj.publickey().exportKey()
        return private_key.decode(encoding=self.config.encoding), public_key.decode(encoding=self.config.encoding)

    def _encrypt(self, plaintext_bytes: bytes) -> bytes:
        ciphertext_bytes: bytes = b""
        block_size: int = self.get_block_size(self.config.public_key)
        cipher: types.RSACipher = self.config.cipher_maker(self.config.public_key)
        for block in self.block_list(plaintext_bytes, block_size):
            ciphertext_bytes += cipher.encrypt(block)
        return ciphertext_bytes

    def _decrypt(self, ciphertext_bytes: bytes) -> bytes:
        plaintext_bytes: bytes = b""
        cipher: types.RSACipher = self.config.cipher_maker(self.config.private_key)
        block_size: int = self.get_block_size(self.config.private_key, is_encrypt=False)
        for block in self.block_list(ciphertext_bytes, block_size):
            plaintext_bytes += cipher.decrypt(block, "")
        return plaintext_bytes

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
    def get_block_size(key_obj: RSA.RsaKey, is_encrypt: bool = True) -> int:
        """
        获取加解密最大片长度，用于分割过长的文本，单位：bytes
        :param key_obj:
        :param is_encrypt:
        :return:
        """
        # TODO(crayon) 区分不同 Cipher 的最大明文长度
        # PKCS1_v1_5: RSA key length(bytes) - 11
        # PKCS1_OAEP: RSA密钥长度（字节） - 2 * 哈希（hashAlgo）输出长度（字节） - 2
        block_size = Util.number.size(key_obj.n) / 8
        reserve_size = 11
        if not is_encrypt:
            reserve_size = 0
        return int(block_size - reserve_size)
