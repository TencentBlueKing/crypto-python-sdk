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
from dataclasses import asdict

from bkcrypto import constants
from bkcrypto.asymmetric.ciphers import BaseAsymmetricCipher, RSAAsymmetricCipher, SM2AsymmetricCipher
from bkcrypto.asymmetric.options import AsymmetricOptions
from bkcrypto.symmetric.ciphers import AESSymmetricCipher, BaseSymmetricCipher, SM4SymmetricCipher
from bkcrypto.symmetric.options import SymmetricOptions

SYMMETRIC_CIPHER_CLASSES: typing.Dict[str, typing.Type[BaseSymmetricCipher]] = {
    constants.SymmetricCipherType.AES.value: AESSymmetricCipher,
    constants.SymmetricCipherType.SM4.value: SM4SymmetricCipher,
}


ASYMMETRIC_CIPHER_CLASSES: typing.Dict[str, typing.Type[BaseAsymmetricCipher]] = {
    constants.AsymmetricCipherType.RSA.value: RSAAsymmetricCipher,
    constants.AsymmetricCipherType.SM2.value: SM2AsymmetricCipher,
}


def get_asymmetric_cipher(
    cipher_type: typing.Optional[str] = None,
    common: typing.Optional[typing.Dict[str, typing.Any]] = None,
    cipher_options: typing.Optional[typing.Dict[str, typing.Optional[AsymmetricOptions]]] = None,
    asymmetric__cipher_classes: typing.Optional[typing.Dict[str, BaseAsymmetricCipher]] = None,
) -> BaseAsymmetricCipher:
    cipher_type: str = cipher_type or constants.AsymmetricCipherType.RSA.value
    asymmetric__cipher_classes: typing.Optional[typing.Dict[str, typing.Type[BaseAsymmetricCipher]]] = (
        asymmetric__cipher_classes or ASYMMETRIC_CIPHER_CLASSES
    )
    asymmetric_cipher_class: typing.Type[BaseAsymmetricCipher] = asymmetric__cipher_classes[cipher_type]

    common = common or {}
    cipher_options: typing.Dict[str, typing.Optional[AsymmetricOptions]] = cipher_options or {}
    options: AsymmetricOptions = cipher_options.get(cipher_type) or asymmetric_cipher_class.OPTIONS_DATA_CLASS()

    # 同参数优先级：common > options
    return asymmetric_cipher_class(**{**asdict(options), **common})


def get_symmetric_cipher(
    cipher_type: typing.Optional[str] = None,
    common: typing.Optional[typing.Dict[str, typing.Any]] = None,
    cipher_options: typing.Optional[typing.Dict[str, typing.Optional[SymmetricOptions]]] = None,
    symmetric_cipher_classes: typing.Optional[typing.Dict[str, BaseSymmetricCipher]] = None,
) -> BaseSymmetricCipher:
    cipher_type: str = cipher_type or constants.SymmetricCipherType.AES.value
    symmetric_cipher_classes: typing.Optional[typing.Dict[str, typing.Type[BaseSymmetricCipher]]] = (
        symmetric_cipher_classes or SYMMETRIC_CIPHER_CLASSES
    )
    symmetric_cipher_class: typing.Type[BaseSymmetricCipher] = symmetric_cipher_classes[cipher_type]

    common = common or {}
    cipher_options: typing.Dict[str, typing.Optional[SymmetricOptions]] = cipher_options or {}
    options: SymmetricOptions = cipher_options.get(cipher_type) or symmetric_cipher_class.OPTIONS_DATA_CLASS()

    # 同参数优先级：common > options
    return symmetric_cipher_class(**{**asdict(options), **common})
