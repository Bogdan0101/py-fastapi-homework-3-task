from pydantic import BaseModel, EmailStr, field_validator, Field, ConfigDict

from src.database.validators.accounts import validate_password_strength, validate_email


# Write your code here

class BaseEmail(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(BaseEmail):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return validate_password_strength(v)


class UserRegistrationResponseSchema(BaseEmail):
    id: int
    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(BaseEmail):
    token: str


class PasswordResetRequestSchema(BaseEmail):
    pass


class PasswordResetCompleteRequestSchema(BaseEmail):
    token: str
    password: str


class UserLoginRequestSchema(UserRegistrationRequestSchema):
    pass


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
