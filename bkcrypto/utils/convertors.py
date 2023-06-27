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


import abc
import base64


class BaseConvertor(abc.ABC):
    @classmethod
    @abc.abstractmethod
    def to_string(cls, data: bytes, encoding: str = "utf-8", **kwargs) -> str:
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def from_string(cls, string: str, **kwargs) -> bytes:
        raise NotImplementedError

    @classmethod
    def encode_plaintext(cls, plaintext: str, encoding: str = "utf-8", **kwargs) -> bytes:
        return plaintext.encode(encoding=encoding)

    @classmethod
    def decode_plaintext(cls, plaintext_bytes: bytes, encoding: str = "utf-8", **kwargs) -> str:
        return plaintext_bytes.decode(encoding=encoding)


class Base64Convertor(BaseConvertor):
    @classmethod
    def to_string(cls, data: bytes, encoding: str = "utf-8", **kwargs) -> str:
        return base64.b64encode(data).decode(encoding=encoding)

    @classmethod
    def from_string(cls, string: str, **kwargs) -> bytes:
        return base64.b64decode(string)


class HexConvertor(BaseConvertor):
    @classmethod
    def to_string(cls, data: bytes, encoding: str = "utf-8", **kwargs) -> str:
        return data.hex()

    @classmethod
    def from_string(cls, string: str, **kwargs) -> bytes:
        return bytes.fromhex(string)
