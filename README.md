# BlueKing crypto-python-sdk

️🔧 BlueKing crypto-python-sdk 是一个基于 pyCryptodome / tongsuopy 等加密库的轻量级密码学工具包，为 Python 应用统一的加解密实现，
便于项目在不同的加密方式之间进行无侵入切换

![Python](https://badgen.net/badge/python/%3E=3.6.12,%3C3.11/green?icon=github)
![Django](https://badgen.net/badge/django/%3E=3.1.5,%3C=4.2.1/yellow?icon=github)

[![License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](LICENSE)


---

## 功能特点

* [Basic] 基于 Cryptodome / tongsuopy 等加密库进行封装，提供统一的加解密实现
* [Basic] 支持国际主流密码学算法：AES、RSA
* [Basic] 支持中国商用密码学算法：SM2、SM4
* [Basic] 非对称加密支持模式：CBC、CTR、GCM、CFB

## 开始使用

### 安装

使用 `pip` 安装 bk-crypto-python-sdk

```shell
pip install bk-crypto-python-sdk
```

## 结合 Django 使用

在项目中配置

```python
from bkcrypto.constants import SymmetricCipherType, AsymmetricCipherType

# 非对称加密类型
BKCRYPTO_ASYMMETRIC_CIPHER_TYPE: str = AsymmetricCipherType.RSA.value
# BKCRYPTO_ASYMMETRIC_CIPHER_TYPE: str = AsymmetricCipherType.SM2.value
# 对称加密类型
BKCRYPTO_SYMMETRIC_CIPHER_TYPE: str = SymmetricCipherType.AES.value
# BKCRYPTO_SYMMETRIC_CIPHER_TYPE: str = SymmetricCipherType.SM4.value
```

### 非对称加密

```python
from bkcrypto.extends.django.ciphers import get_asymmetric_cipher
from bkcrypto.asymmetric.ciphers.base import BaseAsymmetricCipher

asymmetric_cipher: BaseAsymmetricCipher = get_asymmetric_cipher()

# 加解密
assert "123" == asymmetric_cipher.decrypt(asymmetric_cipher.encrypt("123"))
# 验签
assert asymmetric_cipher.verify(plaintext="123", signature=asymmetric_cipher.sign("123"))
```

### 对称加密

```python
import os
import typing
from bkcrypto import constants
from bkcrypto.extends.django.ciphers import get_symmetric_cipher
from bkcrypto.symmetric.ciphers.base import BaseSymmetricCipher

# 公共参数
common_options: typing.Dict[str, typing.Any] = {"key": os.urandom(30)}

symmetric_cipher: BaseSymmetricCipher = get_symmetric_cipher(
    # 兼容不同加密类型在不同场景下可能存在的差异
    {
        constants.SymmetricCipherType.AES.value: {
            **common_options,
            "key_size": 24,
            "mode": constants.SymmetricMode.CFB,
            # 固定 iv
            "iv": os.urandom(16),
            # 指定按字符串拼接密文
            "encryption_metadata_combination_mode": constants.EncryptionMetadataCombinationMode.STRING_SEP,
        },
        constants.SymmetricCipherType.SM4.value: {**common_options, "key_size": 16, "mode": constants.SymmetricMode.CBC}
    }
)

assert "123" == symmetric_cipher.decrypt(symmetric_cipher.encrypt("123"))
```

### ModelField

```python
import os
import typing
from django.db import models
from bkcrypto import constants
from bkcrypto.extends.django.fields import SymmetricTextField
from bkcrypto.extends.django.ciphers import get_symmetric_cipher
from bkcrypto.symmetric.ciphers.base import BaseSymmetricCipher

# 公共参数
common_options: typing.Dict[str, typing.Any] = {"key": os.urandom(30), "mode": constants.SymmetricMode.CBC}

symmetric_cipher: BaseSymmetricCipher = get_symmetric_cipher(
    # 兼容不同加密类型在不同场景下可能存在的差异
    {
        constants.SymmetricCipherType.AES.value: common_options,
        constants.SymmetricCipherType.SM4.value: common_options
    }
)


class IdentityData(models.Model):
    password = SymmetricTextField("密码", cipher=symmetric_cipher, prefix="aes_str:::", blank=True, null=True)
```

## 扩展开发

### convertor

> 编码转换器

* to_string
* from_string
* encode_plaintext
* decode_plaintext

### interceptors

> 拦截器（hooks）

* before_encrypt
* after_encrypt
* before_decrypt
* after_decrypt
* before_sign
* after_sign
* before_verify

## 版本

...

## 问题

### Mac M1 报错：symbol not found in flat namespace '_ffi_prep_closure'

```shell
# refer: https://stackoverflow.com/questions/66035003/
pip uninstall cffi
LDFLAGS=-L$(brew --prefix libffi)/lib CFLAGS=-I$(brew --prefix libffi)/include pip install cffi
```

## 贡献

欢迎您对 bk-crypto 项目作出贡献！请随时提交 issue 和 pull request。

## 许可证

[MIT](LICENSE)
