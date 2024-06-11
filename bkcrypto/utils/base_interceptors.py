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


class BaseInterceptor:
    @classmethod
    def before_encrypt(cls, plaintext: str, **kwargs) -> str:
        return plaintext

    @classmethod
    def after_encrypt(cls, ciphertext: str, **kwargs) -> str:
        return ciphertext

    @classmethod
    def before_decrypt(cls, ciphertext: str, **kwargs) -> str:
        return ciphertext

    @classmethod
    def after_decrypt(cls, plaintext: str, **kwargs) -> str:
        return plaintext

    @classmethod
    def before_encrypt_b(cls, plaintext_bytes: bytes, **kwargs) -> bytes:
        return plaintext_bytes

    @classmethod
    def after_encrypt_b(cls, plaintext_bytes: bytes, **kwargs) -> bytes:
        return plaintext_bytes

    @classmethod
    def before_decrypt_b(cls, ciphertext_bytes: bytes, **kwargs) -> bytes:
        return ciphertext_bytes

    @classmethod
    def after_decrypt_b(cls, ciphertext_bytes: bytes, **kwargs) -> bytes:
        return ciphertext_bytes
