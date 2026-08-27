# BlueKing crypto-python-sdk

---

![Python](https://badgen.net/badge/python/%3E=3.9,%3C3.15/green?icon=github)
![Django](https://badgen.net/badge/django/%3E=3.1.5,%3C=4.2.1/yellow?icon=github)
[![License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](LICENSE.txt)

![Release](https://badgen.net/github/release/TencentBlueKing/crypto-python-sdk)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/TencentBlueKing/crypto-python-sdk/pulls)

[![Publish to Pypi](https://github.com/TencentBlueKing/crypto-python-sdk/actions/workflows/release.yml/badge.svg)](https://github.com/TencentBlueKing/crypto-python-sdk/actions/workflows/release.yml)

[(English Documents Available)](https://github.com/TencentBlueKing/crypto-python-sdk/blob/main/readme_en.md)

## Overview

️🔧 BlueKing crypto-python-sdk 是一个基于 pyCryptodome / tongsuopy 等加密库的轻量级密码学工具包，为 Python 应用统一的加解密实现，
便于项目在不同的加密方式之间进行无侵入切换

## Features

* [Basic] 提供加密统一抽象层，对接 Cryptodome / tongsuopy 等加密库，提供统一的加解密实现
* [Basic] 支持国际主流密码学算法：AES、RSA
* [Basic] 支持中国商用密码学算法：SM2、SM4
* [Basic] 非对称加密支持 CBC、CTR、GCM、CFB 作为块密码模式
* [Contrib] Django Support，集成 Django settings、ModelField

## Getting started

### Installation

```bash
$ pip install bk-crypto-python-sdk
```

仅使用 AES、RSA 时无需安装国密依赖。需要 SM2、SM4 时安装 `gm` extra：

```bash
$ pip install "bk-crypto-python-sdk[gm]"
```

### Usage

> 更多用法参考：[使用文档](https://github.com/TencentBlueKing/crypto-python-sdk/blob/main/docs/usage.md)

#### 1. 基础用法

**非对称加密**

````python
from bkcrypto import constants
from bkcrypto.asymmetric import options
from bkcrypto.asymmetric.ciphers import BaseAsymmetricCipher
from bkcrypto.contrib.basic.ciphers import get_asymmetric_cipher

asymmetric_cipher: BaseAsymmetricCipher = get_asymmetric_cipher(
    cipher_type=constants.AsymmetricCipherType.SM2.value,
    # 传入 None 将随机生成密钥，业务可以根据场景选择传入密钥或随机生成
    cipher_options={
        constants.AsymmetricCipherType.SM2.value: options.SM2AsymmetricOptions(
            private_key_string=None
        ),
        constants.AsymmetricCipherType.RSA.value: options.SM2AsymmetricOptions(
            private_key_string=None
        ),
    },
)

# 加解密
assert "123" == asymmetric_cipher.decrypt(asymmetric_cipher.encrypt("123"))
# 验签
assert asymmetric_cipher.verify(plaintext="123", signature=asymmetric_cipher.sign("123"))
````

**对称加密**

```python
import os

from bkcrypto import constants
from bkcrypto.symmetric.ciphers import BaseSymmetricCipher
from bkcrypto.contrib.basic.ciphers import get_symmetric_cipher

symmetric_cipher: BaseSymmetricCipher = get_symmetric_cipher(
    cipher_type=constants.SymmetricCipherType.SM4.value,
    common={"key": os.urandom(16)},
)
assert "123" == symmetric_cipher.decrypt(symmetric_cipher.encrypt("123"))
```

#### 2. 结合 Django 使用

在 Django Settings 中配置加密算法类型

```python
from bkcrypto import constants

BKCRYPTO = {
    # 声明项目所使用的非对称加密算法
    "ASYMMETRIC_CIPHER_TYPE": constants.AsymmetricCipherType.SM2.value,
    # 声明项目所使用的对称加密算法
    "SYMMETRIC_CIPHER_TYPE": constants.SymmetricCipherType.SM4.value,
}
```

**非对称加密**

```python
from bkcrypto.asymmetric.ciphers import BaseAsymmetricCipher
from bkcrypto.contrib.django.ciphers import get_asymmetric_cipher

asymmetric_cipher: BaseAsymmetricCipher = get_asymmetric_cipher()

# 加解密
assert "123" == asymmetric_cipher.decrypt(asymmetric_cipher.encrypt("123"))
# 验签
assert asymmetric_cipher.verify(plaintext="123", signature=asymmetric_cipher.sign("123"))
```

**对称加密**

```python
from bkcrypto.symmetric.ciphers import BaseSymmetricCipher
from bkcrypto.contrib.django.ciphers import get_symmetric_cipher

symmetric_cipher: BaseSymmetricCipher = get_symmetric_cipher()
assert "123" == symmetric_cipher.decrypt(symmetric_cipher.encrypt("123"))
```

#### 3. 使用 Django CipherManager

在 Django Settings 中配置加密算法类型

```python
from bkcrypto import constants
from bkcrypto.symmetric.options import AESSymmetricOptions, SM4SymmetricOptions
from bkcrypto.asymmetric.options import RSAAsymmetricOptions, SM2AsymmetricOptions

BKCRYPTO = {
    # 声明项目所使用的非对称加密算法
    "ASYMMETRIC_CIPHER_TYPE": constants.AsymmetricCipherType.SM2.value,
    # 声明项目所使用的对称加密算法
    "SYMMETRIC_CIPHER_TYPE": constants.SymmetricCipherType.SM4.value,
    "SYMMETRIC_CIPHERS": {
        # default - 所配置的对称加密实例，根据项目需要可以配置多个
        "default": {
            # 可选，用于在 settings 没法直接获取 key 的情况
            # "get_key_config": "apps.utils.encrypt.key.get_key_config",
            # 可选，用于 ModelField，加密时携带该前缀入库，解密时分析该前缀并选择相应的解密算法
            # ⚠️ 前缀和 cipher type 必须一一对应，且不能有前缀匹配关系
            # "db_prefix_map": {
            #     SymmetricCipherType.AES.value: "aes_str:::",
            #     SymmetricCipherType.SM4.value: "sm4_str:::"
            # },
            # 公共参数配置，不同 cipher 初始化时共用这部分参数
            "common": {"key": "your key"},
            "cipher_options": {
                constants.SymmetricCipherType.AES.value: AESSymmetricOptions(
                    key_size=16
                ),
                # 蓝鲸推荐配置
                constants.SymmetricCipherType.SM4.value: SM4SymmetricOptions(
                    mode=constants.SymmetricMode.CTR
                ),
            },
        },
    },
    "ASYMMETRIC_CIPHERS": {
        # 配置同 SYMMETRIC_CIPHERS
        "default": {
            "common": {"public_key_string": "your key"},
            "cipher_options": {
                constants.AsymmetricCipherType.RSA.value: RSAAsymmetricOptions(
                    padding=constants.RSACipherPadding.PKCS1_v1_5
                ),
                constants.AsymmetricCipherType.SM2.value: SM2AsymmetricOptions(),
            },
        },
    },
}
```

**非对称加密**

使用 `asymmetric_cipher_manager` 获取 `BKCRYPTO.ASYMMETRIC_CIPHERS` 配置的 `cipher`

```python
from bkcrypto.asymmetric.ciphers import BaseAsymmetricCipher
from bkcrypto.contrib.django.ciphers import asymmetric_cipher_manager

asymmetric_cipher: BaseAsymmetricCipher = asymmetric_cipher_manager.cipher(
    using="default"
)

# 加解密
assert "123" == asymmetric_cipher.decrypt(asymmetric_cipher.encrypt("123"))
# 验签
assert asymmetric_cipher.verify(plaintext="123", signature=asymmetric_cipher.sign("123"))
```

**对称加密**

使用 `symmetric_cipher_manager` 获取 `BKCRYPTO.SYMMETRIC_CIPHERS` 配置的 `cipher`

```python
from bkcrypto.symmetric.ciphers import BaseSymmetricCipher
from bkcrypto.contrib.django.ciphers import symmetric_cipher_manager

# using - 指定对称加密实例，默认使用 `default`
symmetric_cipher: BaseSymmetricCipher = symmetric_cipher_manager.cipher(using="default")
assert "123" == symmetric_cipher.decrypt(symmetric_cipher.encrypt("123"))
```

**Django ModelField**

```python
from django.db import models
from bkcrypto.contrib.django.fields import SymmetricTextField


class IdentityData(models.Model):
    password = SymmetricTextField("密码", blank=True, null=True)
```


## Roadmap

- [版本日志](https://github.com/TencentBlueKing/crypto-python-sdk/blob/main/release.md)

## Support

- [蓝鲸论坛](https://bk.tencent.com/s-mart/community)
- [蓝鲸 DevOps 在线视频教程](https://bk.tencent.com/s-mart/video/)
- [蓝鲸社区版交流群](https://jq.qq.com/?_wv=1027&k=5zk8F7G)

## BlueKing Community

- [BK-CMDB](https://github.com/Tencent/bk-cmdb)：蓝鲸配置平台（蓝鲸 CMDB）是一个面向资产及应用的企业级配置管理平台。
- [BK-CI](https://github.com/Tencent/bk-ci)：蓝鲸持续集成平台是一个开源的持续集成和持续交付系统，可以轻松将你的研发流程呈现到你面前。
- [BK-BCS](https://github.com/Tencent/bk-bcs)：蓝鲸容器管理平台是以容器技术为基础，为微服务业务提供编排管理的基础服务平台。
- [BK-PaaS](https://github.com/Tencent/bk-paas)：蓝鲸 PaaS 平台是一个开放式的开发平台，让开发者可以方便快捷地创建、开发、部署和管理
  SaaS 应用。
- [BK-SOPS](https://github.com/Tencent/bk-sops)：标准运维（SOPS）是通过可视化的图形界面进行任务流程编排和执行的系统，是蓝鲸体系中一款轻量级的调度编排类
  SaaS 产品。
- [BK-JOB](https://github.com/Tencent/bk-job) 蓝鲸作业平台(Job)是一套运维脚本管理系统，具备海量任务并发处理能力。

## Contributing

如果你有好的意见或建议，欢迎给我们提 Issues 或 Pull Requests，为蓝鲸开源社区贡献力量。   
[腾讯开源激励计划](https://opensource.tencent.com/contribution) 鼓励开发者的参与和贡献，期待你的加入。

## License

基于 MIT 协议， 详细请参考 [LICENSE](https://github.com/TencentBlueKing/crypto-python-sdk/blob/main/LICENSE.txt)
