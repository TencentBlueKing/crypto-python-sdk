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

## 开始使用

### 安装

使用 `pip` 安装 bk-crypto

```shell
pip install bk-crypto
```

### 示例

...

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
