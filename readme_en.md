# BlueKing crypto-python-sdk

---

![Python](https://badgen.net/badge/python/%3E=3.6.12,%3C3.11/green?icon=github)
![Django](https://badgen.net/badge/django/%3E=3.1.5,%3C=4.2.1/yellow?icon=github)
[![License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](LICENSE.txt)

[(English Documents Available)](readme_en.md)

## Overview

️🔧 BlueKing crypto-python-sdk is a lightweight cryptography toolkit based on encryption libraries such as pyCryptodome
and tongsuopy, providing a unified encryption and decryption implementation for Python applications, facilitating
non-intrusive switching between different encryption methods in projects.

## Features

* [Basic] Provides a unified encryption abstraction layer, docks with Cryptodome / tongsuopy and other encryption
  libraries, and provides a unified encryption and decryption implementation.
* [Basic] Supports mainstream international cryptography algorithms: AES, RSA.
* [Basic] Supports Chinese commercial cryptography algorithms: SM2, SM4.
* [Basic] Asymmetric encryption supports CBC, CTR, GCM, CFB as block cipher modes.
* [Contrib] Django Support, integrated Django settings, ModelField.

## Getting started

### Installation

```bash
$ pip install bk-crypto-python-sdk
```

### Usage

> For more usage, please refer to: [Usage Documentation](docs/usage.md)

Configure in the project

```python
import os
from bkcrypto import constants
from bkcrypto.symmetric.options import AESSymmetricOptions, SM4SymmetricOptions

BKCRYPTO = {
    # Declare the asymmetric encryption algorithm used in the project
    "ASYMMETRIC_CIPHER_TYPE": constants.AsymmetricCipherType.SM2.value,
    # Declare the symmetric encryption algorithm used in the project
    "SYMMETRIC_CIPHER_TYPE": constants.SymmetricCipherType.SM4.value,
    "SYMMETRIC_CIPHERS": {
        # default - The configured symmetric encryption instance, multiple instances can be configured according to project needs
        "default": {
            # Optional, used when the key cannot be obtained directly in settings
            # "get_key_config": "apps.utils.encrypt.key.get_key_config",
            # Optional, used for ModelField, when encrypting, it carries this prefix into the database, when decrypting, it analyzes this prefix and selects the corresponding decryption algorithm
            # ⚠️ Prefix and cipher type must correspond one-to-one, and there can be no prefix matching relationship
            # "db_prefix_map": {
            #     SymmetricCipherType.AES.value: "aes_str:::",
            #     SymmetricCipherType.SM4.value: "sm4_str:::"
            # },
            "common": {"key": os.urandom(24)},
            "cipher_options": {
                constants.SymmetricCipherType.AES.value: AESSymmetricOptions(
                    key_size=24,
                    iv=os.urandom(16),
                    mode=constants.SymmetricMode.CFB,
                    encryption_metadata_combination_mode=constants.EncryptionMetadataCombinationMode.STRING_SEP
                ),
                constants.SymmetricCipherType.SM4.value: SM4SymmetricOptions(mode=constants.SymmetricMode.CTR)
            }
        },
    }
}
```

#### Asymmetric encryption

```python
from bkcrypto.asymmetric.ciphers import BaseAsymmetricCipher
from bkcrypto.contrib.django.ciphers import get_asymmetric_cipher

asymmetric_cipher: BaseAsymmetricCipher = get_asymmetric_cipher()

# Encrypt and decrypt
assert "123" == asymmetric_cipher.decrypt(asymmetric_cipher.encrypt("123"))
# Verify signature
assert asymmetric_cipher.verify(plaintext="123", signature=asymmetric_cipher.sign("123"))
```

#### Symmetric encryption

```python
from bkcrypto.symmetric.ciphers import BaseSymmetricCipher
from bkcrypto.contrib.django.ciphers import symmetric_cipher_manager

# using - Specifies the symmetric encryption instance, the default is `default`
symmetric_cipher: BaseSymmetricCipher = symmetric_cipher_manager.cipher(using="default")
assert "123" == symmetric_cipher.decrypt(symmetric_cipher.encrypt("123"))
```

#### SymmetricTextField

```python
from django.db import models
from bkcrypto.contrib.django.fields import SymmetricTextField


class IdentityData(models.Model):
    password = SymmetricTextField("Password", blank=True, null=True)
```

## Roadmap

- [Version Log](release.md)

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
