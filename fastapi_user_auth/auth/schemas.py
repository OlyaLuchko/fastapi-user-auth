from enum import Enum
from typing import Type, Set, Iterable, Dict, Any

from fastapi.utils import create_cloned_field
from fastapi_amis_admin.crud import BaseApiSchema
from fastapi_amis_admin.utils.translation import i18n as _
from pydantic import BaseModel, SecretStr, validator, BaseConfig, Extra
from pydantic.fields import ModelField
from pydantic.main import ModelMetaclass
from sqlmodel import Field

from .models import BaseUser, EmailMixin, PasswordMixin, UsernameMixin


class BaseTokenData(BaseModel):
    id: int
    username: str


class UserLoginOut(BaseUser):
    """用户登录返回信息"""

    token_type: str = "bearer"
    access_token: str = None
    password: SecretStr = None


class UserRegIn(UsernameMixin, PasswordMixin, EmailMixin):
    """用户注册"""

    password2: str = Field(title=_("Confirm Password"), max_length=128)

    @validator("password2")
    def passwords_match(cls, v, values, **kwargs):
        if "password" in values and v != values["password"]:
            raise ValueError("passwords do not match!")
        return v


def validator_skip_blank(cls, v, config: BaseConfig, field: ModelField, *args, **kwargs):
    if isinstance(v, str):
        if not v:
            if not issubclass(field.type_, str):
                return None
            if issubclass(field.type_, Enum) and "" not in field.type_.__members__:
                return None
            return ""
        if issubclass(field.type_, int):
            v = int(v)
    return v


def schema_create_by_schema(
    schema_cls: Type[BaseModel],
    schema_name: str,
    *,
    include: Set[str] = None,
    exclude: Set[str] = None,
    set_none: bool = False,
    **kwargs,
) -> Type[BaseModel]:
    keys = set(schema_cls.__fields__.keys())
    if include:
        keys &= include
    if exclude:
        keys -= exclude
    fields = {name: create_cloned_field(field) for name, field in schema_cls.__fields__.items() if name in keys}
    return schema_create_by_modelfield(schema_name, fields.values(), set_none=set_none, **kwargs)


def schema_create_by_modelfield(
    schema_name: str,
    modelfields: Iterable[ModelField],
    *,
    set_none: bool = False,
    namespaces: Dict[str, Any] = None,
    extra: Extra = Extra.ignore,
    **kwargs,
) -> Type[BaseModel]:
    namespaces = namespaces or {}
    namespaces["Config"] = type("Config", (BaseApiSchema.Config,), {"extra": extra, **kwargs})
    namespaces.update({"__fields__": {}, "__annotations__": {}})
    for modelfield in modelfields:
        if set_none:
            modelfield.required = False
            modelfield.allow_none = True
            if not modelfield.pre_validators:
                modelfield.pre_validators = [validator_skip_blank]
            else:
                modelfield.pre_validators.insert(0, validator_skip_blank)
        namespaces["__fields__"][modelfield.name] = modelfield
        namespaces["__annotations__"][modelfield.name] = modelfield.type_
    return ModelMetaclass(schema_name, (BaseApiSchema,), namespaces)