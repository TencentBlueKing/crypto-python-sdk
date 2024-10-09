**# 版本日志

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

  
## 1.0.2 - 2023-07-11

### Feature

* [ Feature ] Add support for backward compatibility to Python v3.6.2 ([#12](https://github.com/TencentBlueKing/crypto-python-sdk/issues/12))


## 1.0.3 - 2023-07-19

### Feature

* [ Feature ] Support configuring AsymmetricCipherManager through Django settings ([#14](https://github.com/TencentBlueKing/crypto-python-sdk/issues/14))


## 1.0.4 - 2023-07-20

### Fixed

* [ Fixed ] Fix the issue of "Too many arguments for this mode" in AES CTR mode ([#16](https://github.com/TencentBlueKing/crypto-python-sdk/issues/16))


## 1.1.0 - 2023-08-07

### Feature

* [ Feature ] Add support for non-Django projects ([#19](https://github.com/TencentBlueKing/crypto-python-sdk/issues/19))
* [ Feature ] Add support for prefix ciphertext decryption ([#20](https://github.com/TencentBlueKing/crypto-python-sdk/issues/20))


## 1.1.1 - 2023-08-16

### Fixed

* [ Fixed ] Fix the issue of get_symmetric_cipher has wrong default value ([#25](https://github.com/TencentBlueKing/crypto-python-sdk/issues/25))


## 2.0.0 - 2024-10-09

### Feature

* [ Feature ] Add support for python 3.11
* [ Feature ] Drop support for python 3.6, 3.7