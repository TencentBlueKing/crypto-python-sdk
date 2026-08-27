# BlueKing crypto-python-sdk

---

以下为 crypto-python-sdk 使用说明文档，所有代码均有完整注释，可以在源码中查看。

## 参数说明

### 非对称加密

#### KeyConfig

| 参数                 | 类型                                      | 描述                                |
|--------------------|-----------------------------------------|-----------------------------------|
| public_key_string  | typing.Optional[types.PublicKeyString]  | 公钥（字符串），优先使用                      |
| private_key_string | typing.Optional[types.PrivateKeyString] | 私钥（字符串），优先使用                      |
| public_key_file    | typing.Optional[str]                    | 公钥文件路径，如果公钥字符串没有提供                |
| private_key_file   | typing.Optional[str]                    | 私钥文件路径，如果私钥字符串没有提供，公钥可以不传，会基于私钥生成 |

注：若公钥和私钥都不传时将随机生成密钥对。

#### BaseAsymmetricConfig

| 参数          | 类型                                                  | 描述                                   |
|-------------|-----------------------------------------------------|--------------------------------------|
| encoding    | str                                                 | 编码，默认为 `utf-8`                       |
| convertor   | typing.Type[convertors.BaseConvertor]               | 字节序列转换器，默认使用 `Base64Convertor`       |
| interceptor | typing.Type[interceptors.BaseAsymmetricInterceptor] | 拦截器，默认使用 `BaseAsymmetricInterceptor` |

#### BaseRSAAsymmetricConfig

| 参数                          | 类型                         | 描述                                      |
|-----------------------------|----------------------------|-----------------------------------------|
| padding                     | constants.RSACipherPadding | 加解密填充方案，默认为 `PKCS1_v1_5`                |
| oaep_hash                   | Hash 模块                    | OAEP 哈希算法，默认为 `SHA1`                    |
| mgf1_hash                   | Hash 模块                    | MGF1 哈希算法，默认为 `SHA1`                    |
| oaep_label                  | typing.Optional[bytes]     | OAEP label，默认为空                         |
| enable_segmented_encryption | bool                       | 文本接口是否按 RSA 最大明文长度分段，默认为 `True`       |
| sig_scheme                  | constants.RSASigScheme     | 签名方案，默认为 `PKCS1_v1_5`                   |
| pkey_bits                   | int                        | 密钥长度（bit），默认为 2048                      |

### 对称加密

#### KeyConfig

| 参数  | 类型                                        | 描述             |
|-----|-------------------------------------------|----------------|
| key | typing.Optional[typing.Union[bytes, str]] | 密钥。如果为空，则随机生成。 |

#### BaseSymmetricConfig

| 参数                                   | 类型                                                 | 描述                                                                      |
|--------------------------------------|----------------------------------------------------|-------------------------------------------------------------------------|
| mode                                 | constants.SymmetricMode                            | 块密码模式，默认为 `CTR`                                                         |
| key_size                             | int                                                | 密钥长度，默认为 16                                                             |
| enable_iv                            | bool                                               | 是否启用初始向量 (IV)，默认为 `True`                                                |
| iv_size                              | int                                                | 初始向量长度，默认为 16 字节                                                        |
| iv                                   | typing.Optional[types.SymmetricIv]                 | 固定初始向量。如果为空，每次执行加密操作时都会随机生成                                             |
| aad_size                             | int                                                | 仅用于 GCM 模式，为关联数据 (AAD) 的长度，默认为 20                                       |
| enable_aad                           | bool                                               | 是否启用关联数据 (AAD)，默认为 `True`（仅适用于 GCM 模式）                                  |
| aad                                  | typing.Optional[types.SymmetricAad]                | 仅用于 GCM 模式，关联数据 (AAD)。如果为空，则每次执行加密操作时都会随机生成                             |
| padded_tag_size                      | int                                                | 用于 Tag 的固定填充长度，默认为 32                                                   |
| encryption_metadata_combination_mode | constants.EncryptionMetadataCombinationMode        | 加密元数据携带模式，默认为 `bytes`                                                   |
| metadata_combination_separator       | str                                                | 当 `encryption_metadata_combination_mode` 为 `bytes` 时使用的分隔符，`$bkcrypto$` |
| encoding                             | str                                                | 编码，默认为 `utf-8`                                                          |
| convertor                            | typing.Type[convertors.BaseConvertor]              | 字节序列转换器，默认使用 `Base64Convertor`                                          |
| interceptor                          | typing.Type[interceptors.BaseSymmetricInterceptor] | 拦截器，默认使用 `BaseSymmetricInterceptor`                                     |

#### BaseAESSymmetricConfig

_BaseAESSymmetricConfig_ 类继承自 _BaseSymmetricConfig_ 类，并增加以下参数：

| 参数      | 类型                         | 描述                          |
|---------|----------------------------|-----------------------------|
| padding | constants.SymmetricPadding | 填充方案，默认为 `NONE`，可选 `PKCS7` |

#### BaseSM4SymmetricConfig

_baseSM4SymmetricConfig_ 类继承自 _BaseSymmetricConfig_ 类，不包含额外参数，继承了父类的所有参数。

## 类型说明

### convertor

> 编码转换器，用于 `bytes` <-> `string` 转换，目前提供 `hex` `base64`

* to_string
* from_string
* encode_plaintext
* decode_plaintext

### interceptors

> 拦截器（hooks），用于明文/密文的预处理、后置处理和填充

* before_encrypt
* after_encrypt
* before_decrypt
* after_decrypt
* before_sign
* after_sign
* before_verify

## 二进制数据与 BK-KMS 互通

`encrypt_bytes()` 和 `decrypt_bytes()` 直接处理二进制明文，不执行字符串编码，也不调用文本拦截器。RSA 的二进制接口始终处理单个 RSA 分组；明文超过当前密钥和填充方案允许的长度时会抛出 `ValueError`。原有 `encrypt()` 和 `decrypt()` 文本接口仍默认启用分段，可通过 `enable_segmented_encryption=False` 关闭。

与 BK-KMS SDK 的 RSA-OAEP 配置保持一致时，需要同时为 OAEP 和 MGF1 指定 SHA-256，并使用空 label：

```python
from Cryptodome.Hash import SHA256

from bkcrypto import constants
from bkcrypto.asymmetric.ciphers import RSAAsymmetricCipher

rsa_cipher = RSAAsymmetricCipher(
    padding=constants.RSACipherPadding.PKCS1_OAEP,
    oaep_hash=SHA256,
    mgf1_hash=SHA256,
    oaep_label=None,
    enable_segmented_encryption=False,
)

plaintext = b"\x00\xffbinary data"
ciphertext = rsa_cipher.encrypt_bytes(plaintext)
assert rsa_cipher.decrypt_bytes(ciphertext) == plaintext
```

示例会临时生成 RSA 密钥对。实际互通时，加密方传入 BK-KMS 导出的 PEM 公钥，解密方传入对应的 PKCS#1 或 PKCS#8 PEM 私钥。

AES-CBC 使用 PKCS#7 填充，AES-CTR 不填充。两种模式的 IV 都必须是 16 字节；未传入固定 IV 时，加密结果会携带随机 IV：

```python
from bkcrypto import constants
from bkcrypto.symmetric.ciphers import AESSymmetricCipher

aes_cipher = AESSymmetricCipher(
    key=b"0123456789abcdef",
    mode=constants.SymmetricMode.CBC,
    padding=constants.SymmetricPadding.PKCS7,
)

plaintext = b"\x00\xffbinary data"
ciphertext = aes_cipher.encrypt_bytes(plaintext)
assert aes_cipher.decrypt_bytes(ciphertext) == plaintext
```

仅使用 AES、RSA 时安装基础包即可。使用 SM2、SM4 时需要安装国密 extra：

```bash
pip install "bk-crypto-python-sdk[gm]"
```

## 扩展开发

### 自定义 Cipher

```python
import typing
from bkcrypto import types
from bkcrypto.asymmetric.ciphers import BaseAsymmetricCipher


class MyAsymmetricCipher(BaseAsymmetricCipher):
    @staticmethod
    def get_block_size(key_obj: object, is_encrypt: bool = True) -> typing.Optional[int]:
        pass

    def export_public_key(self) -> str:
        pass

    def export_private_key(self) -> str:
        pass

    def _load_public_key(self, public_key_string: types.PublicKeyString) -> object:
        pass

    def _load_private_key(self, private_key_string: types.PrivateKeyString) -> object:
        pass

    @staticmethod
    def load_public_key_from_pkey(private_key: object) -> object:
        pass

    def generate_key_pair(
        self,
    ) -> tuple[types.PrivateKeyString, types.PublicKeyString]:
        pass

    def _encrypt(self, plaintext_bytes: bytes) -> bytes:
        pass

    def _decrypt(self, ciphertext_bytes: bytes) -> bytes:
        pass

    def _sign(self, plaintext_bytes: bytes) -> bytes:
        pass

    def _verify(self, plaintext_bytes: bytes, signature_types: bytes) -> bool:
        pass
```

### 自定义 convertor

```python
import binascii
from bkcrypto.constants import SymmetricMode
from bkcrypto.utils.convertors import HexConvertor
from bkcrypto.symmetric.ciphers import SM4SymmetricCipher


class MyHexConvertor(HexConvertor):
    @staticmethod
    def encode_plaintext(
        plaintext: str, encoding: str = "utf-8", **kwargs: object
    ) -> bytes:
        return bytes.fromhex(plaintext)

    @staticmethod
    def decode_plaintext(
        plaintext_bytes: bytes, encoding: str = "utf-8", **kwargs: object
    ) -> str:
        return plaintext_bytes.hex()


key = b"0123456789ABCDEFFEDCBA9876543210"
iv = b"0123456789ABCDEFFEDCBA9876543210"
plaintext = b"0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210"
ciphertext = b"2677F46B09C122CC975533105BD4A22AF6125F7275CE552C3A2BBCF533DE8A3B"

cipher = SM4SymmetricCipher(
    key=binascii.unhexlify(key),
    iv=binascii.unhexlify(iv),
    mode=SymmetricMode.CBC,
    convertor=MyHexConvertor,
)

assert plaintext.decode().lower() == cipher.decrypt(
    MyHexConvertor.to_string(binascii.unhexlify(iv) + binascii.unhexlify(ciphertext))
)

assert plaintext.decode().lower() == cipher.decrypt(
    cipher.encrypt(MyHexConvertor.to_string(binascii.unhexlify(plaintext)))
)
```

### 自定义 interceptors

```python
import random

from bkcrypto.asymmetric.ciphers import SM2AsymmetricCipher
from bkcrypto.asymmetric.interceptors import BaseAsymmetricInterceptor


class PrefixAsymmetricInterceptor(BaseAsymmetricInterceptor):
    @classmethod
    def after_encrypt(cls, ciphertext: str, **kwargs: object) -> str:
        return f"bkcrypto${ciphertext}"

    @classmethod
    def before_decrypt(cls, ciphertext: str, **kwargs: object) -> str:
        return ciphertext[len("bkcrypto$") :]


sm2_cipher = SM2AsymmetricCipher(interceptor=PrefixAsymmetricInterceptor)

plaintext = "emoji😄😄& 中文 & English" * random.randint(2, 10)
ciphertext = sm2_cipher.encrypt(plaintext)
assert plaintext == sm2_cipher.decrypt(ciphertext)
```


### SymmetricTextField

- `using`：指定对称加密实例，默认使用 `default`。

- `prefix`：指定固定前缀；值不为 `None` 时，密文统一使用该前缀。

## 问题

### Mac M1 报错：symbol not found in flat namespace '_ffi_prep_closure'

处理方式参考 [macOS 上的 cffi 链接错误排查](https://stackoverflow.com/questions/66035003/)：

```shell
pip uninstall cffi
LDFLAGS=-L$(brew --prefix libffi)/lib CFLAGS=-I$(brew --prefix libffi)/include pip install cffi
```
