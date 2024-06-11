from bkcrypto import constants
from bkcrypto.asymmetric import options
from bkcrypto.asymmetric.ciphers import BaseAsymmetricCipher
from bkcrypto.contrib.basic.ciphers import get_asymmetric_cipher


def test_asymmetric_cipher():
    asymmetric_cipher: BaseAsymmetricCipher = get_asymmetric_cipher(
        cipher_type=constants.AsymmetricCipherType.SM2.value,
        # 传入 None 将随机生成密钥，业务可以根据场景选择传入密钥或随机生成
        cipher_options={
            constants.AsymmetricCipherType.SM2.value: options.SM2AsymmetricOptions(private_key_string=None),
            constants.AsymmetricCipherType.RSA.value: options.SM2AsymmetricOptions(private_key_string=None),
        },
    )
    # 加解密
    assert b"123" == asymmetric_cipher.decrypt_b(asymmetric_cipher.encrypt_b(b"123"))
    # 验签
    assert asymmetric_cipher.verify_b(plaintext_bytes=b"123", signature_bytes=asymmetric_cipher.sign_b(b"123"))
