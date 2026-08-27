import subprocess
import sys
import textwrap


class TestOptionalGMDependency:
    @classmethod
    def test_import__rsa_and_aes_do_not_load_tongsuopy(cls) -> None:
        script = textwrap.dedent(
            """
            import builtins

            real_import = builtins.__import__

            def import_without_gm(name, *args, **kwargs):
                if name.startswith("tongsuopy"):
                    raise ModuleNotFoundError(name)
                return real_import(name, *args, **kwargs)

            builtins.__import__ = import_without_gm

            import bkcrypto.asymmetric.ciphers
            import bkcrypto.symmetric.ciphers
            from bkcrypto.contrib.basic.ciphers import (
                get_asymmetric_cipher,
                get_symmetric_cipher,
            )

            assert get_asymmetric_cipher().__class__.__name__ == "RSAAsymmetricCipher"
            assert get_symmetric_cipher().__class__.__name__ == "AESSymmetricCipher"
            """
        )

        subprocess.run([sys.executable, "-c", script], check=True)
