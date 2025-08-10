from pydantic import BaseModel, EmailStr, field_validator, Field

from database import accounts_validators


class BaseUserSchema(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(BaseUserSchema):
    password: str = Field(..., min_length=8)

    @field_validator("password", mode="before")
    @classmethod
    def validate_password(cls, value):
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(BaseUserSchema):
    id: int

    model_config = {
        "from_attributes": True
    }


class UserActivationRequestSchema(BaseUserSchema):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetResponseSchema(BaseModel):
    message: str


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str = Field(..., min_length=8)

    @field_validator("password", mode="before")
    @classmethod
    def validate_password(cls, value):
        return accounts_validators.validate_password_strength(value)


class PasswordResetCompleteResponseSchema(BaseModel):
    message: str


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
