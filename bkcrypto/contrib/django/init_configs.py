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
from dataclasses import asdict, dataclass

from bkcrypto.asymmetric.configs import KeyConfig as AsymmetricKeyConfig
from bkcrypto.asymmetric.options import AsymmetricOptions
from bkcrypto.symmetric.configs import KeyConfig as SymmetricKeyConfig
from bkcrypto.symmetric.options import SymmetricOptions
from bkcrypto.utils.module_loding import import_string


@dataclass
class CipherInitConfig:
    # 默认取值 f"{cipher_type}_str:::"
    db_prefix_map: typing.Dict[str, str] = None
    prefix_cipher_type_map: typing.Dict[str, str] = None
    get_key_config: typing.Optional[str] = None
    get_key_config_func: typing.Optional[
        typing.Callable[[str], typing.Union[AsymmetricKeyConfig, SymmetricKeyConfig]]
    ] = None
    common: typing.Optional[typing.Dict[str, typing.Any]] = None
    cipher_options: typing.Optional[typing.Dict[str, typing.Union[SymmetricOptions, AsymmetricOptions, None]]] = None

    def __post_init__(self):
        if self.get_key_config:
            self.get_key_config_func = import_string(self.get_key_config)
        self.db_prefix_map = self.db_prefix_map or {}

    def as_get_cipher_params(self, cipher_type: str):
        # get key hook 不为空，优先从此处取 key
        if self.get_key_config_func:
            key_config = self.get_key_config_func(cipher_type)
            key_dict: typing.Dict = asdict(key_config)
        else:
            key_dict: typing.Dict = {}

        common = self.common or {}
        common.update(key_dict)
        return {"cipher_type": cipher_type, "common": common, "cipher_options": self.cipher_options}


@dataclass
class SymmetricCipherInitConfig(CipherInitConfig):
    get_key_config_func: typing.Optional[typing.Callable[[str], SymmetricKeyConfig]] = None


@dataclass
class AsymmetricCipherInitConfig(CipherInitConfig):
    get_key_config_func: typing.Optional[typing.Callable[[str], AsymmetricKeyConfig]] = None
