# BlueKing crypto-python-sdk

---

![Python](https://badgen.net/badge/python/%3E=3.6.2,%3C3.11/green?icon=github)
![Django](https://badgen.net/badge/django/%3E=3.1.5,%3C=4.2.1/yellow?icon=github)
[![License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](LICENSE.txt)

![Release](https://badgen.net/github/release/TencentBlueKing/crypto-python-sdk)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/TencentBlueKing/crypto-python-sdk/pulls)

[![Publish to Pypi](https://github.com/TencentBlueKing/crypto-python-sdk/actions/workflows/release.yml/badge.svg)](https://github.com/TencentBlueKing/crypto-python-sdk/actions/workflows/release.yml)

[(English Documents Available)](https://github.com/TencentBlueKing/crypto-python-sdk/blob/main/readme_en.md)

## Overview

️🔧 BlueKing crypto-python-sdk is a lightweight cryptography toolkit based on encryption libraries such as pyCryptodome
and tongsuopy, providing a unified encryption and decryption implementation for Python applications, making it easy for
projects to switch between different encryption methods without intrusion.

## Features

* [Basic] Provides a unified encryption abstraction layer, docking with Cryptodome / tongsuopy and other encryption
  libraries, providing a unified encryption and decryption implementation
* [Basic] Supports mainstream international cryptography algorithms: AES, RSA
* [Basic] Supports Chinese commercial cryptography algorithms: SM2, SM4
* [Basic] Asymmetric encryption supports CBC, CTR, GCM, CFB as block cipher modes
* [Contrib] Django Support, integrating Django settings, ModelField

## Getting started

### Installation

```bash
$ pip install bk-crypto-python-sdk
```

### Usage

> For more usage guidelines, please refer
> to: [Usage Documentation](https://github.com/TencentBlueKing/crypto-python-sdk/blob/main/docs/usage.md)


#### 1. Basic Usage

**Asymmetric Encryption**

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

**Symmetric Encryption**

````python
from bkcrypto import constants
from bkcrypto.asymmetric import options
from bkcrypto.asymmetric.ciphers import BaseAsymmetricCipher
from bkcrypto.contrib.basic.ciphers import get_asymmetric_cipher

asymmetric_cipher: BaseAsymmetricCipher = get_asymmetric_cipher(
    cipher_type=constants.AsymmetricCipherType.SM2.value,
    # Passing in None will randomly generate a key, the business can choose to pass in a key or randomly generate it according to the scenario.
    cipher_options={
        constants.AsymmetricCipherType.SM2.value: options.SM2AsymmetricOptions(
            private_key_string=None
        ),
        constants.AsymmetricCipherType.RSA.value: options.SM2AsymmetricOptions(
            private_key_string=None
        ),
    }
)

# Encrypt and Decrypt
assert "123" == asymmetric_cipher.decrypt(asymmetric_cipher.encrypt("123"))
# Signature verification
assert asymmetric_cipher.verify(plaintext="123", signature=asymmetric_cipher.sign("123"))
````

#### 2. Using with Django

Configure the encryption algorithm type in Django Settings

```python
from bkcrypto import constants

BKCRYPTO = {
    # Declare the asymmetric encryption algorithm used by the project
    "ASYMMETRIC_CIPHER_TYPE": constants.AsymmetricCipherType.SM2.value,
    # Declare the symmetric encryption algorithm used by the project
    "SYMMETRIC_CIPHER_TYPE": constants.SymmetricCipherType.SM4.value,
}
```

**Asymmetric Encryption**

```python
from bkcrypto.asymmetric.ciphers import BaseAsymmetricCipher
from bkcrypto.contrib.django.ciphers import get_asymmetric_cipher

asymmetric_cipher: BaseAsymmetricCipher = get_asymmetric_cipher()

# Encrypt and Decrypt
assert "123" == asymmetric_cipher.decrypt(asymmetric_cipher.encrypt("123"))
# Signature verification
assert asymmetric_cipher.verify(plaintext="123", signature=asymmetric_cipher.sign("123"))
```

**Symmetric Encryption**

```python
from bkcrypto.symmetric.ciphers import BaseSymmetricCipher
from bkcrypto.contrib.django.ciphers import get_symmetric_cipher

symmetric_cipher: BaseSymmetricCipher = get_symmetric_cipher()
assert "123" == symmetric_cipher.decrypt(symmetric_cipher.encrypt("123"))
```



## Roadmap

- [Version Log](https://github.com/TencentBlueKing/crypto-python-sdk/blob/main/release.md)

## Support

- [BK Forum](https://bk.tencent.com/s-mart/community)
- [BK DevOps Online Video Tutorial (In Chinese)](https://bk.tencent.com/s-mart/video/)
- [Technical Exchange QQ Group](https://jq.qq.com/?_wv=1027&k=5zk8F7G)

## BlueKing Community

- [BK-CMDB](https://github.com/Tencent/bk-cmdb): BlueKing CMDB is an enterprise-level management platform designed for
  assets and applications.
- [BK-CI](https://github.com/Tencent/bk-ci): BlueKing Continuous Integration platform is a free, open source CI service,
  which allows developers to automatically create - test - release workflow, and continuously, efficiently deliver their
  high-quality products.
- [BK-BCS](https://github.com/Tencent/bk-bcs): BlueKing Container Service is a container-based basic service platform
  that provides management service to microservice businesses.
- [BK-PaaS](https://github.com/Tencent/bk-paas): BlueKing PaaS is an open development platform that allows developers to
  efficiently create, develop, set up, and manage SaaS apps.
- [BK-SOPS](https://github.com/Tencent/bk-sops): BlueKing SOPS is a system that features workflow arrangement and
  execution using a graphical interface. It's a lightweight task scheduling and arrangement SaaS product of the Blueking
  system.
- [BK-JOB](https://github.com/Tencent/bk-job):BlueKing JOB is a set of operation and maintenance script management
  platform with the ability to handle a large number of tasks concurrently.

## Contributing

If you have good ideas or suggestions, please let us know by Issues or Pull Requests and contribute to the Blue Whale
Open Source Community.      
[Tencent Open Source Incentive Program](https://opensource.tencent.com/contribution) welcome developers from all over
the globe to contribute to Tencent Open Source projects.

## License

Based on the MIT protocol. Please refer to [LICENSE](LICENSE.txt)
