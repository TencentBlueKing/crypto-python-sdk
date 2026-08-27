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
from dataclasses import asdict, dataclass, field

from bkcrypto.asymmetric.configs import KeyConfig as AsymmetricKeyConfig
from bkcrypto.asymmetric.options import AsymmetricOptions
from bkcrypto.symmetric.configs import KeyConfig as SymmetricKeyConfig
from bkcrypto.symmetric.options import SymmetricOptions
from bkcrypto.utils.module_loding import import_string
from typing_extensions import TypedDict

KeyConfigFactory = typing.Callable[
    [str], typing.Union[AsymmetricKeyConfig, SymmetricKeyConfig]
]
CipherOptionT = typing.TypeVar(
    "CipherOptionT", bound=typing.Union[AsymmetricOptions, SymmetricOptions]
)


class CipherParams(TypedDict, typing.Generic[CipherOptionT]):
    """Describe keyword arguments accepted by the basic cipher factories."""

    cipher_type: str
    common: dict[str, typing.Any]
    cipher_options: typing.Optional[dict[str, typing.Optional[CipherOptionT]]]


@dataclass
class CipherInitConfig(typing.Generic[CipherOptionT]):
    """Describe how a configured cipher instance should be initialized."""

    # 默认取值 f"{cipher_type}_str:::"
    db_prefix_map: dict[str, str] = field(default_factory=dict)
    prefix_cipher_type_map: dict[str, str] = field(default_factory=dict)
    get_key_config: typing.Optional[str] = None
    get_key_config_func: typing.Optional[KeyConfigFactory] = None
    common: typing.Optional[dict[str, typing.Any]] = None
    cipher_options: typing.Optional[dict[str, typing.Optional[CipherOptionT]]] = None

    def __post_init__(self) -> None:
        if self.get_key_config:
            configured_factory = import_string(self.get_key_config)
            if not callable(configured_factory):
                raise TypeError("Configured key factory must be callable")

            def key_config_factory(
                cipher_type: str,
            ) -> typing.Union[AsymmetricKeyConfig, SymmetricKeyConfig]:
                key_config = configured_factory(cipher_type)
                if not isinstance(key_config, (AsymmetricKeyConfig, SymmetricKeyConfig)):
                    raise TypeError("Configured key factory returned an invalid config")
                return key_config

            self.get_key_config_func = key_config_factory

    def as_get_cipher_params(self, cipher_type: str) -> CipherParams[CipherOptionT]:
        # get key hook 不为空，优先从此处取 key
        if self.get_key_config_func:
            key_config = self.get_key_config_func(cipher_type)
            key_dict: dict[str, typing.Any] = asdict(key_config)
        else:
            key_dict = {}

        common: dict[str, typing.Any] = dict(self.common or {})
        common.update(key_dict)
        return {
            "cipher_type": cipher_type,
            "common": common,
            "cipher_options": self.cipher_options,
        }


@dataclass
class SymmetricCipherInitConfig(CipherInitConfig[SymmetricOptions]):
    """Configure initialization of a symmetric cipher."""


@dataclass
class AsymmetricCipherInitConfig(CipherInitConfig[AsymmetricOptions]):
    """Configure initialization of an asymmetric cipher."""
