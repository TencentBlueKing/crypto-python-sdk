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

import abc
import base64


class BaseConvertor(abc.ABC):
    """Define conversions between byte payloads and serialized strings."""

    @classmethod
    @abc.abstractmethod
    def to_string(cls, data: bytes, encoding: str = "utf-8", **kwargs: object) -> str:
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def from_string(cls, string: str, **kwargs: object) -> bytes:
        raise NotImplementedError

    @classmethod
    def encode_plaintext(
        cls, plaintext: str, encoding: str = "utf-8", **kwargs: object
    ) -> bytes:
        return plaintext.encode(encoding=encoding)

    @classmethod
    def decode_plaintext(
        cls, plaintext_bytes: bytes, encoding: str = "utf-8", **kwargs: object
    ) -> str:
        return plaintext_bytes.decode(encoding=encoding)


class Base64Convertor(BaseConvertor):
    """Serialize byte payloads with Base64 encoding."""

    @classmethod
    def to_string(cls, data: bytes, encoding: str = "utf-8", **kwargs: object) -> str:
        return base64.b64encode(data).decode(encoding=encoding)

    @classmethod
    def from_string(cls, string: str, **kwargs: object) -> bytes:
        return base64.b64decode(string)


class HexConvertor(BaseConvertor):
    """Serialize byte payloads with hexadecimal encoding."""

    @classmethod
    def to_string(cls, data: bytes, encoding: str = "utf-8", **kwargs: object) -> str:
        return data.hex()

    @classmethod
    def from_string(cls, string: str, **kwargs: object) -> bytes:
        return bytes.fromhex(string)
