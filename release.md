# 版本日志

## 1.0.0 - 2023-07-03

### Feature

* [ Feature ] Provides a unified encryption abstraction layer, docks with Cryptodome / tongsuopy and other encryption
  libraries, and provides a unified encryption and decryption implementation
* [ Feature ] Supports mainstream international cryptography algorithms: AES, RSA
* [ Feature ] Supports Chinese commercial cryptography algorithms: SM2, SM4
* [ Feature ] Asymmetric encryption supports CBC, CTR, GCM, CFB as block cipher modes
* [ Feature ] Django Support, integrated Django settings, ModelField

## 1.0.1 - 2023-07-07

### Improved

* [ Improved ] The Django CipherManager.cipher "using" parameter provides "default" as the default
  value ([#10](https://github.com/TencentBlueKing/crypto-python-sdk/issues/10))
