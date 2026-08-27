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

from Cryptodome.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Cryptodome.Cipher.PKCS1_v1_5 import PKCS115_Cipher
from Cryptodome.PublicKey.RSA import RsaKey
from Cryptodome.Signature.pkcs1_15 import PKCS115_SigScheme
from Cryptodome.Signature.pss import PSS_SigScheme
from typing_extensions import TypeAlias


class HashObject(typing.Protocol):
    """Describe a hash object consumed by PyCryptodome RSA helpers."""

    def digest(self) -> bytes: ...

    def update(self, data: bytes) -> None: ...


@typing.runtime_checkable
class HashModule(typing.Protocol):
    """Describe a PyCryptodome hash module used by RSA operations."""

    digest_size: int

    def new(self, data: typing.Optional[bytes] = None) -> HashObject: ...


KeyString: TypeAlias = str

HashSource: TypeAlias = typing.Union[HashObject, HashModule]

# from pss.MaskFunction
MaskFunction: TypeAlias = typing.Callable[[bytes, int, HashSource], bytes]

PrivateKeyString: TypeAlias = KeyString

PublicKeyString: TypeAlias = KeyString

RSACipher: TypeAlias = typing.Union[PKCS1OAEP_Cipher, PKCS115_Cipher]

RSASigScheme: TypeAlias = typing.Union[PSS_SigScheme, PKCS115_SigScheme]

RSACipherMaker: TypeAlias = typing.Callable[[RsaKey], RSACipher]

RSASigSchemeMaker: TypeAlias = typing.Callable[[RsaKey], RSASigScheme]

SymmetricKey: TypeAlias = bytes

SymmetricIv: TypeAlias = bytes

SymmetricTag: TypeAlias = bytes

SymmetricAad: TypeAlias = bytes
