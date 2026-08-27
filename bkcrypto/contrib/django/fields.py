"""TencentBlueKing is pleased to support the open source community.

蓝鲸智云 - crypto-python-sdk (BlueKing - crypto-python-sdk) is made available by
TencentBlueKing.

Copyright (C) 2017-2023 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at
https://opensource.org/licenses/MIT.
Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""

import typing

from bkcrypto.contrib.django.selectors import SymmetricCipherSelectorMixin
from django.db import models

if typing.TYPE_CHECKING:

    class _TextFieldBase(models.TextField[str, str]):
        """Provide precise descriptor types during static analysis."""

else:

    class _TextFieldBase(models.TextField):
        """Use Django's unsubscripted field class at runtime."""


class _DjangoFieldMethods(typing.Protocol):
    """Describe Django field methods used through the mixin MRO."""

    def deconstruct(
        self,
    ) -> tuple[str, str, typing.Sequence[typing.Any], dict[str, typing.Any]]: ...

    def to_python(self, value: object) -> typing.Optional[str]: ...

    def get_prep_value(self, value: typing.Optional[str]) -> typing.Optional[str]: ...


class SymmetricFieldMixin(SymmetricCipherSelectorMixin):
    """Encrypt values before storage and decrypt values loaded by Django."""

    def _field_super(self) -> _DjangoFieldMethods:
        """Expose the Django field API supplied later in the concrete MRO."""
        return typing.cast("_DjangoFieldMethods", super())

    def deconstruct(
        self,
    ) -> tuple[str, str, typing.Sequence[typing.Any], dict[str, typing.Any]]:
        name, path, args, kwargs = self._field_super().deconstruct()
        if self.prefix is not None:
            kwargs["prefix"] = self.prefix
        kwargs["using"] = self.using
        return name, path, args, kwargs

    def get_decrypted_value(self, value: typing.Optional[str]) -> typing.Optional[str]:
        """Return a decrypted value while preserving ``None``.

        :param value: Stored ciphertext, or ``None`` for a nullable field value.
        :return: Decrypted plaintext while preserving ``None``.
        """
        if value is None:
            return value

        return self.decrypt(value)

    def from_db_value(
        self,
        value: typing.Optional[str],
        expression: object,
        connection: object,
        context: typing.Optional[object] = None,
    ) -> typing.Optional[str]:
        """出库后解密数据."""
        value = self.get_decrypted_value(value)

        field_super = self._field_super()
        from_db_value: typing.Optional[
            typing.Callable[
                [typing.Optional[str], object, object, typing.Optional[object]],
                typing.Optional[str],
            ]
        ] = getattr(field_super, "from_db_value", None)
        if from_db_value is not None:
            value = from_db_value(value, expression, connection, context)
        return value

    def to_python(self, value: object) -> typing.Optional[str]:
        """反序列化和 Form clean() 时调用，解密数据."""
        python_value = self._field_super().to_python(value)
        return self.get_decrypted_value(python_value)

    def get_prep_value(self, value: typing.Optional[str]) -> typing.Optional[str]:
        """入库前加密数据."""
        if value is None:
            return value

        value = self._field_super().get_prep_value(value)
        if value is None:
            return None

        return self.encrypt(value)


class SymmetricTextField(SymmetricFieldMixin, _TextFieldBase):
    """Store text encrypted by a configured symmetric cipher."""

    def __init__(
        self,
        *args: object,
        using: typing.Optional[str] = None,
        prefix: typing.Optional[str] = None,
        **kwargs: object,
    ) -> None:
        """Initialize an encrypted Django text field.

        基于 BKCRYPTO.SYMMETRIC_CIPHERS 的配置提供敏感信息加解密的能力。
        :param using: Configured symmetric cipher alias; defaults to ``default``.
        :param prefix: Fixed ciphertext prefix, or ``None`` to use configured mappings.
        :param args: Positional arguments forwarded to Django's ``TextField``.
        :param kwargs: Keyword arguments forwarded to Django's ``TextField``.
        """
        self.prefix = prefix
        self.using = using or "default"

        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
