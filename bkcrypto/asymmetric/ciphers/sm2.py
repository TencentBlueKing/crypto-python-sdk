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

from tongsuopy.crypto import exceptions, hashes, serialization
from tongsuopy.crypto.asymciphers import ec
from tongsuopy.crypto.asymciphers import types as tongsuopy_types

from bkcrypto import types

from . import base


@dataclass
class SM2AsymmetricConfig(base.BaseAsymmetricConfig):
    public_key: typing.Optional[tongsuopy_types.PUBLIC_KEY_TYPES] = None
    private_key: typing.Optional[tongsuopy_types.PRIVATE_KEY_TYPES] = None


class SM2AsymmetricCipher(base.BaseAsymmetricCipher):

    CONFIG_DATA_CLASS: typing.Type[base.BaseAsymmetricConfig] = SM2AsymmetricConfig

    config: SM2AsymmetricConfig = None

    @staticmethod
    def load_public_key_from_pkey(private_key: tongsuopy_types.PRIVATE_KEY_TYPES) -> tongsuopy_types.PUBLIC_KEY_TYPES:
        return private_key.public_key()

    def _load_public_key(self, public_key_string: types.PublicKeyString) -> tongsuopy_types.PUBLIC_KEY_TYPES:
        return serialization.load_pem_public_key(public_key_string.encode(self.config.encoding))

    def _load_private_key(self, private_key_string: types.PrivateKeyString) -> tongsuopy_types.PRIVATE_KEY_TYPES:
        return serialization.load_pem_private_key(private_key_string.encode(self.config.encoding), None)

    def generate_key_pair(self) -> typing.Tuple[types.PrivateKeyString, types.PublicKeyString]:
        private_key_obj: tongsuopy_types.PRIVATE_KEY_TYPES = (
            ec.generate_private_key(ec.SM2()).private_numbers().private_key()
        )

        private_key_string: str = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode(encoding=self.config.encoding)

        public_key_string: str = (
            private_key_obj.public_key()
            .public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode(encoding=self.config.encoding)
        )

        return private_key_string, public_key_string

    def _encrypt(self, plaintext: str) -> bytes:
        return self.config.public_key.encrypt(plaintext.encode(encoding=self.config.encoding))

    def _decrypt(self, ciphertext_bytes: bytes) -> str:
        return self.config.private_key.decrypt(ciphertext_bytes).decode(encoding=self.config.encoding)

    def _sign(self, plaintext: str) -> str:
        return self.config.private_key.sign(
            plaintext.encode(encoding=self.config.encoding), ec.ECDSA(hashes.SM3())
        ).decode(encoding=self.config.encoding)

    def _verify(self, plaintext: str, signature_types: bytes) -> bool:
        try:
            self.config.public_key.verify(
                signature_types, plaintext.encode(encoding=self.config.encoding), ec.ECDSA(hashes.SM3())
            )
            return True
        except exceptions.InvalidSignature:
            return False
