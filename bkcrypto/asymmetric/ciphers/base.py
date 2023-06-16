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
import copy
import typing
from dataclasses import dataclass

import wrapt
from dacite import from_dict

from bkcrypto import constants, types
from bkcrypto.utils import convertors, module_loding


@dataclass
class BaseAsymmetricConfig:
    public_key: typing.Any = None
    private_key: typing.Any = None
    encoding: str = "utf-8"

    convertor_import_path: str = module_loding.get_import_path(convertors.Base64Convertor)

    # 非可配置属性
    convertor: typing.Type[convertors.BaseConvertor] = None

    def __post_init__(self):
        self.convertor = module_loding.import_string(self.convertor_import_path)


def key_obj_checker(key_attribute: constants.AsymmetricKeyAttribute):
    """
    密钥对象检查器
    :param key_attribute: 密钥属性
    :return:
    """

    @wrapt.decorator
    def handle(
        wrapped: typing.Callable,
        instance: "BaseAsymmetricCipher",
        args: typing.Tuple[typing.Any],
        kwargs: typing.Dict[str, typing.Any],
    ):
        if not getattr(instance.config, key_attribute.value):
            raise ValueError(f"{key_attribute} must be set if you want to call {wrapped.__name__}")
        return wrapped(*args, **kwargs)

    return handle


class BaseAsymmetricCipher:

    CONFIG_DATA_CLASS: typing.Type[BaseAsymmetricConfig] = BaseAsymmetricConfig

    config: BaseAsymmetricConfig = None

    @abc.abstractmethod
    def _load_public_key(self, public_key_string: types.PublicKeyString):
        raise NotImplementedError

    @abc.abstractmethod
    def _load_private_key(self, private_key_string: types.PrivateKeyString):
        raise NotImplementedError

    @staticmethod
    @abc.abstractmethod
    def load_public_key_from_pkey(private_key: typing.Any):
        """
        通过 private_key 加载公钥
        :return:
        """
        raise NotImplementedError

    @abc.abstractmethod
    def generate_key_pair(self) -> typing.Tuple[types.PrivateKeyString, types.PublicKeyString]:
        """
        生成密钥对
        :return: private_key_string, public_key_string
        """
        raise NotImplementedError

    @abc.abstractmethod
    def _encrypt(self, plaintext: str) -> bytes:
        raise NotImplementedError

    @abc.abstractmethod
    def _decrypt(self, ciphertext_bytes: bytes) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def _sign(self, plaintext: str) -> bytes:
        raise NotImplementedError

    @abc.abstractmethod
    def _verify(self, plaintext: str, signature_types: bytes) -> bool:
        raise NotImplementedError

    def __init__(
        self,
        public_key_string: typing.Optional[types.PublicKeyString] = None,
        private_key_string: typing.Optional[types.PrivateKeyString] = None,
        public_key_file: typing.Optional[str] = None,
        private_key_file: typing.Optional[str] = None,
        **options,
    ):
        options: typing.Dict[str, typing.Any] = copy.deepcopy(options)

        # init config
        self.config = from_dict(self.CONFIG_DATA_CLASS, options)

        public_key: typing.Optional[typing.Any] = self.load_public_key(public_key_string, public_key_file)
        private_key: typing.Optional[typing.Any] = self.load_private_key(private_key_string, private_key_file)

        if not public_key and private_key:
            # load public_key_obj from private_key_file
            public_key = self.load_public_key_from_pkey(private_key)

        self.config.public_key = public_key
        self.config.private_key = private_key

    def load_key_base(
        self,
        handle: typing.Callable[[types.KeyString], typing.Any],
        key_str: typing.Optional[types.KeyString] = None,
        key_file: typing.Optional[str] = None,
    ) -> typing.Optional:
        """
        载入密钥
        :param handle: 处理方法
        :param key_str: 密钥文本
        :param key_file: 密钥文件
        :return:
        """

        key_string_or_none: typing.Optional[str] = self.read_key(key_str, key_file)
        if not key_string_or_none:
            return None

        return handle(key_string_or_none)

    def load_private_key(
        self, key_str: typing.Optional[types.PrivateKeyString] = None, key_file: typing.Optional[str] = None
    ) -> typing.Optional:
        """
        载入私钥
        :param key_str:
        :param key_file:
        :return:
        """
        # TODO(crayon,2023/06/15) 支持密码
        return self.load_key_base(self._load_private_key, key_str, key_file)

    def load_public_key(
        self, key_str: typing.Optional[types.PublicKeyString] = None, key_file: typing.Optional[str] = None
    ) -> typing.Optional:
        """
        载入公钥
        :param key_str:
        :param key_file:
        :return:
        """
        return self.load_key_base(self._load_public_key, key_str, key_file)

    @key_obj_checker(constants.AsymmetricKeyAttribute.PUBLIC_KEY)
    def encrypt(self, plaintext: str) -> str:
        """
        加密
        :param plaintext: 待加密的字符串
        :return: 密文
        """
        ciphertext_bytes: bytes = self._encrypt(plaintext)
        return self.config.convertor.to_string(ciphertext_bytes)

    @key_obj_checker(constants.AsymmetricKeyAttribute.PRIVATE_KEY)
    def decrypt(self, ciphertext: str) -> str:
        """
        解密
        :param ciphertext: 密文
        :return: 解密后的信息
        """
        ciphertext_bytes: bytes = self.config.convertor.from_string(ciphertext)
        return self._decrypt(ciphertext_bytes)

    @key_obj_checker(constants.AsymmetricKeyAttribute.PRIVATE_KEY)
    def sign(self, plaintext: str) -> str:
        """
        根据私钥和需要发送的信息生成签名
        :param plaintext: 需要发送给客户端的信息
        :return:
        """
        signature_types: bytes = self._sign(plaintext)
        return self.config.convertor.to_string(signature_types)

    @key_obj_checker(constants.AsymmetricKeyAttribute.PUBLIC_KEY)
    def verify(self, plaintext: str, signature: str) -> bool:
        """
        使用公钥验证签名
        :param plaintext: 客户端接受的信息
        :param signature: 签名
        :return:
        """
        signature_bytes: bytes = self.config.convertor.from_string(signature)
        return self._verify(plaintext, signature_bytes)

    @staticmethod
    def read_key(
        key_string: typing.Optional[types.KeyString] = None, key_file: typing.Optional[str] = None
    ) -> typing.Optional[str]:
        """
        读取密钥
        :param key_string: 内容
        :param key_file: 文件
        :return:
        """
        if not (key_string or key_file):
            return None

        if key_file:
            try:
                with open(file=key_file, mode="r") as extern_key_fs:
                    key_string = extern_key_fs.read()
            except OSError as e:
                raise OSError(f"can't not read / open extern_key_file -> {key_file}") from e

        return key_string