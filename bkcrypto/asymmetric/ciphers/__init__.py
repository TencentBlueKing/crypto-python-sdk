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

__all__ = ["BaseAsymmetricCipher", "RSAAsymmetricCipher", "SM2AsymmetricCipher"]

from .base import BaseAsymmetricCipher
from .rsa import RSAAsymmetricCipher


def __getattr__(name):
    if name == "SM2AsymmetricCipher":
        from .sm2 import SM2AsymmetricCipher

        return SM2AsymmetricCipher
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
