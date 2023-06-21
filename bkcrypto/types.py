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

from Cryptodome.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Cryptodome.Cipher.PKCS1_v1_5 import PKCS115_Cipher
from Cryptodome.PublicKey.RSA import RsaKey
from Cryptodome.Signature import pkcs1_15, pss
from tongsuopy.crypto.ciphers import modes

T = typing.TypeVar("T")


KeyString = str

# from pss.MaskFunction
MaskFunction = typing.Callable[[bytes, int, typing.Any], bytes]

# from pss.RndFunction
RndFunction = typing.Callable[[int], bytes]

PrivateKeyString = KeyString

PublicKeyString = KeyString

RSACipher = typing.Union[PKCS1OAEP_Cipher, PKCS115_Cipher]

RSASigScheme = typing.Union[pss.PSS_SigScheme, pkcs1_15.PKCS115_SigScheme]

RSACipherMaker = typing.Callable[[RsaKey], RSACipher]

RSASigSchemeMaker = typing.Callable[
    [RsaKey, typing.Optional[MaskFunction], typing.Optional[int], typing.Optional[RndFunction]], RSASigScheme
]


SymmetricKey = bytes

SymmetricIv = bytes

SymmetricTag = bytes

SymmetricAad = bytes

SM4ModeClass = typing.Union[
    typing.Type[modes.CBC], typing.Type[modes.CTR], typing.Type[modes.CFB], typing.Type[modes.GCM]
]

AESModeClass = typing.Any
