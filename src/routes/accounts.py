from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete, and_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,

)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface

from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetCompleteResponseSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)

from security.passwords import hash_password, verify_password

from security.utils import generate_secure_token

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    try:
        # Check for existing user
        result = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
        existing_user = result.scalar_one_or_none()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists."
            )

        # Get default group for users
        stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        result = await db.execute(stmt)
        group = result.scalar_one()

        # Create new user
        new_user = UserModel(
            email=user_data.email,
            password=hash_password(user_data.password),
            group=group,
            is_active=False,
            activation_token=ActivationTokenModel(
                token=generate_secure_token(),
                expires_at=datetime.now(timezone.utc) + timedelta(days=2),
            )
        )

        db.add(new_user)
        await db.commit()
        await db.flush()
        return new_user

    # Raising 409 error in case new user already exists in db
    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(
        activation_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    # Fetch user
    result = await db.execute(select(UserModel).where(UserModel.email == activation_data.email))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    # Fetch activation token
    token_query = await db.execute(
        select(ActivationTokenModel).where(
            and_(
                ActivationTokenModel.user_id == user.id,
                ActivationTokenModel.token == activation_data.token
            )
        )
    )
    token_record = token_query.scalar_one_or_none()

    if not token_record or cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc) < datetime.now(
            timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    # Activate user & delete token
    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/", response_model=PasswordResetResponseSchema)
async def request_password_reset(
        reset_data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    # Always return success message
    success_msg = PasswordResetResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )

    # Find active user with provided email
    result = await db.execute(
        select(UserModel).where(
            and_(
                UserModel.email == reset_data.email,
                UserModel.is_active == True
            )
        )
    )
    user = result.scalar_one_or_none()

    if not user:
        # Do not indicate user existence
        return success_msg

    # Invalidate existing reset tokens
    await db.execute(
        delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    )

    # Create new reset token
    token = generate_secure_token()
    reset_token_record = PasswordResetTokenModel(
        user_id=cast(int, user.id),
        token=token,
        expires_at=datetime.now(timezone.utc) + timedelta(days=2)
    )
    db.add(reset_token_record)
    await db.commit()

    return success_msg


@router.post("/reset-password/complete/", response_model=PasswordResetCompleteResponseSchema)
async def complete_password_reset(
        reset_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    try:
        # Find user
        result = await db.execute(select(UserModel).where(UserModel.email == reset_data.email))
        user = result.scalar_one_or_none()

        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        # Find reset token
        token_query = await db.execute(
            select(PasswordResetTokenModel).where(
                and_(
                    PasswordResetTokenModel.user_id == user.id,
                    PasswordResetTokenModel.token == reset_data.token
                )
            )
        )
        token_record = token_query.scalar_one_or_none()

        # Validate token existence & expiration
        if not token_record or cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc) < datetime.now(
                timezone.utc):
            await db.execute(
                delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        # Update password
        user.password = reset_data.password

        # Delete used token
        await db.delete(token_record)
        await db.commit()

        return PasswordResetCompleteResponseSchema(message="Password reset successfully.")

    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
async def login_user(
        login_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        # Find user
        result = await db.execute(select(UserModel).where(UserModel.email == login_data.email))
        user = result.scalar_one_or_none()

        if not user or not verify_password(login_data.password, user._hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password."
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated."
            )

        # Generate tokens
        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

        # Store refresh token
        refresh_token_record = RefreshTokenModel(
            user_id=cast(int, user.id),
            token=refresh_token,
            expires_at=datetime.now(timezone.utc) + timedelta(days=2)
        )
        db.add(refresh_token_record)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token
        )

    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
        refresh_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        # Decode refresh token
        try:
            payload = jwt_manager.decode_refresh_token(refresh_data.refresh_token)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e) or "Invalid or expired refresh token."
            )

        user_id = int(payload.get("user_id"))

        # Check token exists in DB
        token_query = await db.execute(
            select(RefreshTokenModel).where(RefreshTokenModel.token == refresh_data.refresh_token)
        )
        token_record = token_query.scalar_one_or_none()

        if not token_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found."
            )

        # Check user exists
        user_query = await db.execute(select(UserModel).where(UserModel.id == user_id))
        user = user_query.scalar_one_or_none()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found."
            )

        # Generate new access token
        new_access_token = jwt_manager.create_access_token({"user_id": user.id})

        return TokenRefreshResponseSchema(access_token=new_access_token)

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while refreshing the token."
        )
