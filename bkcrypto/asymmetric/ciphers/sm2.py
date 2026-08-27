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
from tongsuopy.crypto import exceptions, hashes, serialization
from tongsuopy.crypto.asymciphers import ec

from .. import configs
from ..options import SM2AsymmetricOptions
from . import base


@dataclass
class SM2AsymmetricRuntimeConfig(
    configs.BaseSM2AsymmetricConfig, base.BaseAsymmetricRuntimeConfig
):
    """Store normalized SM2 runtime configuration."""

    public_key: typing.Optional[ec.EllipticCurvePublicKey] = None
    private_key: typing.Optional[ec.EllipticCurvePrivateKey] = None


class SM2AsymmetricCipher(base.BaseAsymmetricCipher[SM2AsymmetricRuntimeConfig]):
    """Encrypt, decrypt, sign, and verify data with SM2."""

    CIPHER_TYPE: str = constants.AsymmetricCipherType.SM2.value

    CONFIG_DATA_CLASS = SM2AsymmetricRuntimeConfig

    OPTIONS_DATA_CLASS = SM2AsymmetricOptions

    def _public_key(self) -> ec.EllipticCurvePublicKey:
        public_key = self.config.public_key
        if public_key is None:
            raise ValueError("SM2 public key is not configured")
        return public_key

    def _private_key(self) -> ec.EllipticCurvePrivateKey:
        private_key = self.config.private_key
        if private_key is None:
            raise ValueError("SM2 private key is not configured")
        return private_key

    def export_public_key(self) -> str:
        public_key_bytes: bytes = self._public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return public_key_bytes.decode(encoding=self.config.encoding)

    def export_private_key(self) -> str:
        private_key_bytes: bytes = self._private_key().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return private_key_bytes.decode(encoding=self.config.encoding)

    @staticmethod
    def load_public_key_from_pkey(
        private_key: object,
    ) -> ec.EllipticCurvePublicKey:
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise TypeError("Expected an SM2 private key")
        return private_key.public_key()

    def _load_public_key(
        self, public_key_string: types.PublicKeyString
    ) -> ec.EllipticCurvePublicKey:
        public_key: ec.EllipticCurvePublicKey = serialization.load_pem_public_key(
            public_key_string.encode(self.config.encoding)
        )
        return public_key

    def _load_private_key(
        self, private_key_string: types.PrivateKeyString
    ) -> ec.EllipticCurvePrivateKey:
        private_key: ec.EllipticCurvePrivateKey = serialization.load_pem_private_key(
            private_key_string.encode(self.config.encoding), None
        )
        return private_key

    def generate_key_pair(
        self,
    ) -> tuple[types.PrivateKeyString, types.PublicKeyString]:
        private_key_obj: ec.EllipticCurvePrivateKey = (
            ec.generate_private_key(ec.SM2()).private_numbers().private_key()
        )

        private_key_string: str = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode(encoding=self.config.encoding)

        public_key_string: str = (
            private_key_obj.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode(encoding=self.config.encoding)
        )

        return private_key_string, public_key_string

    def _encrypt(self, plaintext_bytes: bytes) -> bytes:
        ciphertext: bytes = self._public_key().encrypt(plaintext_bytes)
        return ciphertext

    def _decrypt(self, ciphertext_bytes: bytes) -> bytes:
        plaintext: bytes = self._private_key().decrypt(ciphertext_bytes)
        return plaintext

    def _sign(self, plaintext_bytes: bytes) -> bytes:
        signature: bytes = self._private_key().sign(
            plaintext_bytes, ec.ECDSA(hashes.SM3())
        )
        return signature

    def _verify(self, plaintext_bytes: bytes, signature_types: bytes) -> bool:
        try:
            self._public_key().verify(
                signature_types, plaintext_bytes, ec.ECDSA(hashes.SM3())
            )
        except exceptions.InvalidSignature:
            return False
        else:
            return True

    @staticmethod
    def get_block_size(key_obj: object, is_encrypt: bool = True) -> typing.Optional[int]:
        return None
