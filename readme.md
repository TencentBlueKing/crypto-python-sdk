# BlueKing crypto-python-sdk

---

![Python](https://badgen.net/badge/python/%3E=3.6.12,%3C3.11/green?icon=github)
![Django](https://badgen.net/badge/django/%3E=3.1.5,%3C=4.2.1/yellow?icon=github)
[![License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](LICENSE.txt)

[(English Documents Available)](readme_en.md)

## Overview

️🔧 BlueKing crypto-python-sdk 是一个基于 pyCryptodome / tongsuopy 等加密库的轻量级密码学工具包，为 Python 应用统一的加解密实现，
便于项目在不同的加密方式之间进行无侵入切换

## Features

* 基于 Cryptodome / tongsuopy 等加密库进行封装，提供统一的加解密实现
* 支持国际主流密码学算法：AES、RSA
* 支持中国商用密码学算法：SM2、SM4
* 非对称加密支持模式：CBC、CTR、GCM、CFB
* Django Support，集成 Model Field

## Getting started

### Installation

```bash
$ pip install bk-crypto-python-sdk
```

### Usage

> 更多用法参考：[使用文档](docs/usage.md)

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

#### 非对称加密

```python
from bkcrypto.asymmetric.ciphers import BaseAsymmetricCipher
from bkcrypto.extends.django.ciphers import get_asymmetric_cipher

asymmetric_cipher: BaseAsymmetricCipher = get_asymmetric_cipher()

# 加解密
assert "123" == asymmetric_cipher.decrypt(asymmetric_cipher.encrypt("123"))
# 验签
assert asymmetric_cipher.verify(plaintext="123", signature=asymmetric_cipher.sign("123"))
```

#### 对称加密

```python
import os
from bkcrypto import constants
from bkcrypto.symmetric.ciphers import BaseSymmetricCipher
from bkcrypto.extends.django.ciphers import get_symmetric_cipher
from bkcrypto.symmetric.options import SM4SymmetricOptions, AESSymmetricOptions

symmetric_cipher: BaseSymmetricCipher = get_symmetric_cipher(
    common={"key": os.urandom(16)},
    # 不同加密后端使用不同的配置
    cipher_options={
        constants.SymmetricCipherType.AES.value: AESSymmetricOptions(
            # 不足位时补 0
            key_size=24,
            mode=constants.SymmetricMode.CFB,
            # 指定按字符串拼接密文
            encryption_metadata_combination_mode=constants.EncryptionMetadataCombinationMode.STRING_SEP
        ),
        constants.SymmetricCipherType.SM4.value: SM4SymmetricOptions(mode=constants.SymmetricMode.CTR)
    }
)

assert "123" == symmetric_cipher.decrypt(symmetric_cipher.encrypt("123"))
```

#### ModelField

```python
from django.db import models
from django.conf import settings
from bkcrypto.symmetric.ciphers import BaseSymmetricCipher
from bkcrypto.extends.django.fields import SymmetricTextField
from bkcrypto.extends.django.ciphers import get_symmetric_cipher


def get_cipher() -> BaseSymmetricCipher:
    return get_symmetric_cipher(common={"key": settings.BKCRYPTO_SYMMETRIC_KEY})


class IdentityData(models.Model):
    password = SymmetricTextField("密码", get_cipher=get_cipher, prefix="aes_str:::", blank=True, null=True)
```

## Roadmap

- [版本日志](release.md)

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

基于 MIT 协议， 详细请参考 [LICENSE](LICENSE.txt)
