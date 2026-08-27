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

from bkcrypto import constants
from bkcrypto.asymmetric.ciphers.base import BaseAsymmetricCipher
from bkcrypto.asymmetric.options import AsymmetricOptions
from bkcrypto.symmetric.ciphers.base import BaseSymmetricCipher
from bkcrypto.symmetric.options import SymmetricOptions
from bkcrypto.utils import module_loding

SYMMETRIC_CIPHER_CLASSES: typing.Dict[str, str] = {
    constants.SymmetricCipherType.AES.value: "bkcrypto.symmetric.ciphers.aes.AESSymmetricCipher",
    constants.SymmetricCipherType.SM4.value: "bkcrypto.symmetric.ciphers.sm4.SM4SymmetricCipher",
}


ASYMMETRIC_CIPHER_CLASSES: typing.Dict[str, str] = {
    constants.AsymmetricCipherType.RSA.value: "bkcrypto.asymmetric.ciphers.rsa.RSAAsymmetricCipher",
    constants.AsymmetricCipherType.SM2.value: "bkcrypto.asymmetric.ciphers.sm2.SM2AsymmetricCipher",
}


def _load_cipher_class(cipher_type: str, cipher_classes: typing.Dict[str, typing.Any]) -> typing.Type:
    cipher_class_or_path: typing.Any = cipher_classes[cipher_type]
    if isinstance(cipher_class_or_path, str):
        return module_loding.import_string(cipher_class_or_path)
    return cipher_class_or_path


def get_asymmetric_cipher(
    cipher_type: typing.Optional[str] = None,
    common: typing.Optional[typing.Dict[str, typing.Any]] = None,
    cipher_options: typing.Optional[typing.Dict[str, typing.Optional[AsymmetricOptions]]] = None,
    asymmetric__cipher_classes: typing.Optional[typing.Dict[str, typing.Any]] = None,
) -> BaseAsymmetricCipher:
    cipher_type: str = cipher_type or constants.AsymmetricCipherType.RSA.value
    asymmetric__cipher_classes = asymmetric__cipher_classes or ASYMMETRIC_CIPHER_CLASSES
    asymmetric_cipher_class: typing.Type[BaseAsymmetricCipher] = _load_cipher_class(
        cipher_type, asymmetric__cipher_classes
    )

    common = common or {}
    cipher_options: typing.Dict[str, typing.Optional[AsymmetricOptions]] = cipher_options or {}
    options: AsymmetricOptions = cipher_options.get(cipher_type) or asymmetric_cipher_class.OPTIONS_DATA_CLASS()

    # 同参数优先级：common > options
    return asymmetric_cipher_class(**{**vars(options), **common})


def get_symmetric_cipher(
    cipher_type: typing.Optional[str] = None,
    common: typing.Optional[typing.Dict[str, typing.Any]] = None,
    cipher_options: typing.Optional[typing.Dict[str, typing.Optional[SymmetricOptions]]] = None,
    symmetric_cipher_classes: typing.Optional[typing.Dict[str, typing.Any]] = None,
) -> BaseSymmetricCipher:
    cipher_type: str = cipher_type or constants.SymmetricCipherType.AES.value
    symmetric_cipher_classes = symmetric_cipher_classes or SYMMETRIC_CIPHER_CLASSES
    symmetric_cipher_class: typing.Type[BaseSymmetricCipher] = _load_cipher_class(cipher_type, symmetric_cipher_classes)

    common = common or {}
    cipher_options: typing.Dict[str, typing.Optional[SymmetricOptions]] = cipher_options or {}
    options: SymmetricOptions = cipher_options.get(cipher_type) or symmetric_cipher_class.OPTIONS_DATA_CLASS()

    # 同参数优先级：common > options
    return symmetric_cipher_class(**{**vars(options), **common})
