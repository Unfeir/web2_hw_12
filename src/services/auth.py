from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import JWTError, jwt

from src.database.db import get_db
from src.repository import user as repository_user


class AuthPassword:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def get_hash_password(self, password: str):
        return self.pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password):
        return self.pwd_context.verify(plain_password, hashed_password)


class AuthToken:
    # openssl rand -hex 32
    SECRET_KEY = "7c349acae221e4cd05b4e92c0b542b89839ae7246ecbf50db1f77198d6a79938"
    ALGORITHM = "HS256"
    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

    async def create_access_token(self, data: dict, expires_delta: Optional[float] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + timedelta(expires_delta)
        else:
            expire = datetime.utcnow() + timedelta(minutes=30)

        to_encode.update({'iat': datetime.utcnow(), 'exp': expire, "scope": "access_token"})
        access_token = jwt.encode(to_encode, self.SECRET_KEY, self.ALGORITHM)
        return access_token

    async def create_refresh_token(self, data: dict, expires_delta: Optional[float] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + timedelta(expires_delta)
        else:
            expire = datetime.utcnow() + timedelta(days=1)

        to_encode.update({'iat': datetime.utcnow(), 'exp': expire, "scope": "refresh_token"})
        refresh_token = jwt.encode(to_encode, self.SECRET_KEY, self.ALGORITHM)
        return refresh_token

    async def get_current_user(self, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            payload = jwt.decode(token, self.SECRET_KEY, self.ALGORITHM)
            if payload['scope'] == 'access_token':
                email = payload['sub']
                if email is None:
                    raise credentials_exception
            else:
                raise credentials_exception
        except JWTError:
            raise credentials_exception

        user = await repository_user.get_user_by_email(email, db)
        if user is None:
            raise credentials_exception
        return user

    async def decode_refresh_token(self, refresh_token: str):
        try:
            payload = jwt.decode(refresh_token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            if payload['scope'] == 'refresh_token':
                email = payload['sub']
                return email
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid scope for token')
        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate credentials')
