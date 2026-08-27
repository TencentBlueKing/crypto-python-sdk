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
from collections.abc import Mapping

from bkcrypto import constants
from bkcrypto.asymmetric.ciphers.base import AsymmetricCipher, BaseAsymmetricCipher
from bkcrypto.asymmetric.options import AsymmetricOptions
from bkcrypto.symmetric.ciphers.base import BaseSymmetricCipher, SymmetricCipher
from bkcrypto.symmetric.options import SymmetricOptions
from bkcrypto.utils import module_loding
from typing_extensions import TypeAlias

AsymmetricCipherClass: TypeAlias = typing.Union[str, type[AsymmetricCipher]]
SymmetricCipherClass: TypeAlias = typing.Union[str, type[SymmetricCipher]]

SYMMETRIC_CIPHER_CLASSES: dict[str, SymmetricCipherClass] = {
    constants.SymmetricCipherType.AES.value: (
        "bkcrypto.symmetric.ciphers.aes.AESSymmetricCipher"
    ),
    constants.SymmetricCipherType.SM4.value: (
        "bkcrypto.symmetric.ciphers.sm4.SM4SymmetricCipher"
    ),
}


ASYMMETRIC_CIPHER_CLASSES: dict[str, AsymmetricCipherClass] = {
    constants.AsymmetricCipherType.RSA.value: (
        "bkcrypto.asymmetric.ciphers.rsa.RSAAsymmetricCipher"
    ),
    constants.AsymmetricCipherType.SM2.value: (
        "bkcrypto.asymmetric.ciphers.sm2.SM2AsymmetricCipher"
    ),
}


def _load_configured_class(
    cipher_type: str,
    cipher_classes: Mapping[str, typing.Union[str, type[object]]],
) -> type[object]:
    configured_class = cipher_classes[cipher_type]
    loaded_class: object = (
        module_loding.import_string(configured_class)
        if isinstance(configured_class, str)
        else configured_class
    )
    if not isinstance(loaded_class, type):
        raise TypeError(f"Configured cipher {cipher_type!r} must be a class")
    return loaded_class


def _load_asymmetric_cipher_class(
    cipher_type: str, cipher_classes: Mapping[str, AsymmetricCipherClass]
) -> type[AsymmetricCipher]:
    cipher_class = _load_configured_class(cipher_type, cipher_classes)
    if not issubclass(cipher_class, BaseAsymmetricCipher):
        raise TypeError(
            f"Configured cipher {cipher_type!r} must inherit "
            f"{BaseAsymmetricCipher.__name__}"
        )
    return cipher_class


def _load_symmetric_cipher_class(
    cipher_type: str, cipher_classes: Mapping[str, SymmetricCipherClass]
) -> type[SymmetricCipher]:
    cipher_class = _load_configured_class(cipher_type, cipher_classes)
    if not issubclass(cipher_class, BaseSymmetricCipher):
        raise TypeError(
            f"Configured cipher {cipher_type!r} must inherit "
            f"{BaseSymmetricCipher.__name__}"
        )
    return cipher_class


def get_asymmetric_cipher(
    cipher_type: typing.Optional[str] = None,
    common: typing.Optional[dict[str, typing.Any]] = None,
    cipher_options: typing.Optional[
        dict[str, typing.Optional[AsymmetricOptions]]
    ] = None,
    asymmetric__cipher_classes: typing.Optional[dict[str, AsymmetricCipherClass]] = None,
) -> AsymmetricCipher:
    """Build an asymmetric cipher from common and algorithm-specific options."""
    selected_cipher_type: str = cipher_type or constants.AsymmetricCipherType.RSA.value
    selected_cipher_classes: dict[str, AsymmetricCipherClass] = (
        asymmetric__cipher_classes or ASYMMETRIC_CIPHER_CLASSES
    )
    asymmetric_cipher_class = _load_asymmetric_cipher_class(
        selected_cipher_type, selected_cipher_classes
    )

    common_options: dict[str, typing.Any] = common or {}
    selected_cipher_options: dict[str, typing.Optional[AsymmetricOptions]] = (
        cipher_options or {}
    )
    options: AsymmetricOptions = (
        selected_cipher_options.get(selected_cipher_type)
        or asymmetric_cipher_class.OPTIONS_DATA_CLASS()
    )

    # 同参数优先级：common > options
    return asymmetric_cipher_class(**{**vars(options), **common_options})


def get_symmetric_cipher(
    cipher_type: typing.Optional[str] = None,
    common: typing.Optional[dict[str, typing.Any]] = None,
    cipher_options: typing.Optional[dict[str, typing.Optional[SymmetricOptions]]] = None,
    symmetric_cipher_classes: typing.Optional[dict[str, SymmetricCipherClass]] = None,
) -> SymmetricCipher:
    """Build a symmetric cipher from common and algorithm-specific options."""
    selected_cipher_type: str = cipher_type or constants.SymmetricCipherType.AES.value
    selected_cipher_classes: dict[str, SymmetricCipherClass] = (
        symmetric_cipher_classes or SYMMETRIC_CIPHER_CLASSES
    )
    symmetric_cipher_class = _load_symmetric_cipher_class(
        selected_cipher_type, selected_cipher_classes
    )

    common_options: dict[str, typing.Any] = common or {}
    selected_cipher_options: dict[str, typing.Optional[SymmetricOptions]] = (
        cipher_options or {}
    )
    options: SymmetricOptions = (
        selected_cipher_options.get(selected_cipher_type)
        or symmetric_cipher_class.OPTIONS_DATA_CLASS()
    )

    # 同参数优先级：common > options
    return symmetric_cipher_class(**{**vars(options), **common_options})
