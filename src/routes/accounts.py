from datetime import datetime, timezone
from typing import cast, Any

from fastapi import APIRouter, Depends, status, HTTPException
from pydantic import EmailStr
from sqlalchemy import select, delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload
from fastapi.security import OAuth2PasswordBearer

from src.exceptions.security import TokenExpiredError, InvalidTokenError

from src.config.dependencies import get_jwt_auth_manager, get_settings

from src.config.settings import BaseAppSettings
from src.database.models.accounts import (
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from src.schemas.accounts import (UserRegistrationResponseSchema,
                                  UserRegistrationRequestSchema,
                                  UserLoginResponseSchema,
                                  UserLoginRequestSchema,
                                  UserActivationRequestSchema, PasswordResetRequestSchema,
                                  PasswordResetCompleteRequestSchema, TokenRefreshRequestSchema,
                                  TokenRefreshResponseSchema, )
from src.database import get_db
from src.security.token_manager import JWTAuthManager
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


async def create_user(db: AsyncSession, data: UserRegistrationRequestSchema):
    db_user = await get_user_by_email(db, data.email)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {data.email} already exists."
        )

    result_group = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    group = result_group.scalar_one_or_none()
    if group is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )

    new_user = UserModel.create(
        email=data.email,
        raw_password=data.password,
        group_id=group.id
    )
    try:
        db.add(new_user)
        await db.flush()

        activate_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activate_token)

        await db.commit()
        await db.refresh(new_user)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {data.email} already exists."
        )
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="An error occurred during user creation.")
    return new_user


async def get_user_by_email(db: AsyncSession, email: EmailStr):
    db_user = await db.execute(select(UserModel).where(UserModel.email == email))
    return db_user.scalar_one_or_none()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register(data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    return await create_user(db, data)


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate(
        data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(ActivationTokenModel)
        .join(UserModel)
        .where(UserModel.email == data.email)
        .where(ActivationTokenModel.token == data.token)
        .options(joinedload(ActivationTokenModel.user))
    )
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )
    if token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        await db.delete(token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )
    db_user = token.user
    if db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    try:
        db_user.is_active = True
        await db.delete(token)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user activation."
        )
    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def password_reset(
        data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    try:
        db_user = await get_user_by_email(db, data.email)
        if not db_user or not db_user.is_active:
            return {"message": "If you are registered, you will receive an email with instructions."}
        await db.execute(
            delete(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user_id == db_user.id)
        )
        user_id_val = cast(int, cast(Any, db_user.id))
        new_token = PasswordResetTokenModel(user_id=user_id_val)
        db.add(new_token)
        await db.commit()
    except Exception as e:
        await db.rollback()
        logger.error(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during password reset request."
        )
    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def password_reset_complete(
        data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    invalid_error = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid email or token."
    )
    result = await db.execute(
        select(PasswordResetTokenModel)
        .join(UserModel)
        .where(UserModel.email == data.email)
        .options(joinedload(PasswordResetTokenModel.user))
    )
    token = result.scalar_one_or_none()

    if not token:
        raise invalid_error

    if token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc) or token.token != data.token:
        await db.delete(token)
        await db.commit()
        raise invalid_error

    db_user = token.user
    if not db_user or not db_user.is_active:
        raise invalid_error

    try:
        db_user.password = data.password
        await db.delete(token)
        await db.commit()
    except ValueError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        await db.rollback()
        logger.error(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )

    return {"message": "Password reset successfully."}


@router.post("/login/", status_code=status.HTTP_201_CREATED, response_model=UserLoginResponseSchema)
async def login(
        user_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings),
):
    db_user = await get_user_by_email(db, user_data.email)
    if not db_user or not db_user.verify_password(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )
    if not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    try:
        user_id = cast(int, cast(Any, db_user.id))
        token_data = {"user_id": user_id, "email": db_user.email}
        access_token = jwt_manager.create_access_token(data=token_data)
        refresh_token = jwt_manager.create_refresh_token(data=token_data)
        new_refresh_token = RefreshTokenModel.create(
            user_id=int(user_id),
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )
        db.add(new_refresh_token)
        await db.commit()
    except Exception as e:
        await db.rollback()
        logger.error(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/refresh/", status_code=status.HTTP_200_OK, response_model=TokenRefreshResponseSchema)
async def refresh(
        data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager),
):
    try:
        check_refresh = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = check_refresh.get("user_id")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token payload."
            )
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    result = await db.execute(
        select(RefreshTokenModel)
        .where(RefreshTokenModel.token == data.refresh_token)
        .options(joinedload(RefreshTokenModel.user))
    )
    db_token = result.scalar_one_or_none()
    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )
    db_user = db_token.user
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    new_access_token = jwt_manager.create_access_token(
        data={"user_id": user_id, "email": db_user.email},
    )

    return {"access_token": new_access_token}
