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

from dataclasses import dataclass

from . import configs


@dataclass
class SymmetricOptions(configs.BaseSymmetricConfig, configs.KeyConfig):
    """Configure shared symmetric cipher behavior and key material."""


@dataclass
class AESSymmetricOptions(configs.BaseAESSymmetricConfig, SymmetricOptions):
    """Configure an AES symmetric cipher."""


@dataclass
class SM4SymmetricOptions(configs.BaseSM4SymmetricConfig, SymmetricOptions):
    """Configure an SM4 symmetric cipher."""
