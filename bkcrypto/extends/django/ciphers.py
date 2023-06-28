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

from django.conf import settings

from bkcrypto import constants
from bkcrypto.asymmetric.ciphers import BaseAsymmetricCipher, RSAAsymmetricCipher, SM2AsymmetricCipher
from bkcrypto.asymmetric.options import AsymmetricOptions
from bkcrypto.symmetric.ciphers import AESSymmetricCipher, BaseSymmetricCipher, SM4SymmetricCipher
from bkcrypto.symmetric.options import SymmetricOptions
from bkcrypto.utils import module_loding

BKCRYPTO_ASYMMETRIC_CIPHER_TYPE: str = constants.AsymmetricCipherType.RSA.value

BKCRYPTO_SYMMETRIC_CIPHER_TYPE: str = constants.SymmetricCipherType.AES.value

BKCRYPTO_SYMMETRIC_CIPHER_IMPORT_PATHS: typing.Dict[str, str] = {
    constants.SymmetricCipherType.AES.value: module_loding.get_import_path(AESSymmetricCipher),
    constants.SymmetricCipherType.SM4.value: module_loding.get_import_path(SM4SymmetricCipher),
}

BKCRYPTO_ASYMMETRIC_CIPHER_IMPORT_PATHS: typing.Dict[str, str] = {
    constants.AsymmetricCipherType.RSA.value: module_loding.get_import_path(RSAAsymmetricCipher),
    constants.AsymmetricCipherType.SM2.value: module_loding.get_import_path(SM2AsymmetricCipher),
}


def get_asymmetric_cipher_class(asymmetric_cipher_type: str) -> typing.Type[BaseAsymmetricCipher]:
    try:
        asymmetric_cipher_import_paths: typing.Dict[str, str] = settings.BKCRYPTO_ASYMMETRIC_CIPHER_IMPORT_PATHS
    except AttributeError:
        asymmetric_cipher_import_paths: typing.Dict[str, str] = BKCRYPTO_ASYMMETRIC_CIPHER_IMPORT_PATHS

    try:
        cipher_import_path: str = asymmetric_cipher_import_paths[asymmetric_cipher_type]
    except KeyError:
        raise ValueError(f"Unsupported asymmetric_cipher_type: {asymmetric_cipher_type}")

    return module_loding.import_string(cipher_import_path)


def get_symmetric_cipher_class(symmetric_cipher_type: str) -> typing.Type[BaseSymmetricCipher]:
    try:
        symmetric_cipher_import_paths: typing.Dict[str, str] = settings.BKCRYPTO_SYMMETRIC_CIPHER_IMPORT_PATHS
    except AttributeError:
        symmetric_cipher_import_paths: typing.Dict[str, str] = BKCRYPTO_SYMMETRIC_CIPHER_IMPORT_PATHS

    try:
        cipher_import_path: str = symmetric_cipher_import_paths[symmetric_cipher_type]
    except KeyError:
        raise ValueError(f"Unsupported symmetric_cipher_type: {symmetric_cipher_type}")

    return module_loding.import_string(cipher_import_path)


def get_asymmetric_cipher(
    common: typing.Optional[typing.Dict[str, typing.Any]] = None,
    cipher_options: typing.Optional[typing.Dict[str, typing.Optional[AsymmetricOptions]]] = None,
) -> BaseAsymmetricCipher:
    try:
        asymmetric_cipher_type: str = settings.BKCRYPTO_ASYMMETRIC_CIPHER_TYPE
    except AttributeError:
        asymmetric_cipher_type: str = BKCRYPTO_ASYMMETRIC_CIPHER_TYPE

    asymmetric_cipher_class: typing.Type[BaseAsymmetricCipher] = get_asymmetric_cipher_class(asymmetric_cipher_type)

    cipher_options: typing.Dict[str, typing.Optional[AsymmetricOptions]] = cipher_options or {}

    options: AsymmetricOptions = (
        cipher_options.get(asymmetric_cipher_type) or asymmetric_cipher_class.OPTIONS_DATA_CLASS()
    )

    # 同参数优先级：common > options
    return asymmetric_cipher_class(**{**asdict(options), **common})


def get_symmetric_cipher(
    common: typing.Optional[typing.Dict[str, typing.Any]] = None,
    cipher_options: typing.Optional[typing.Dict[str, typing.Optional[SymmetricOptions]]] = None,
) -> BaseSymmetricCipher:
    try:
        symmetric_cipher_type: str = settings.BKCRYPTO_SYMMETRIC_CIPHER_TYPE
    except AttributeError:
        symmetric_cipher_type: str = BKCRYPTO_SYMMETRIC_CIPHER_TYPE

    symmetric_cipher_class: typing.Type[BaseSymmetricCipher] = get_symmetric_cipher_class(symmetric_cipher_type)

    cipher_options: typing.Dict[str, typing.Optional[SymmetricOptions]] = cipher_options or {}

    options: SymmetricOptions = cipher_options.get(symmetric_cipher_type) or symmetric_cipher_class.OPTIONS_DATA_CLASS()

    # 同参数优先级：common > options
    return symmetric_cipher_class(**{**asdict(options), **common})
