from fastapi import Depends, HTTPException, status, APIRouter, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from src.database.db import get_db
from src.schemas import UserModel, UserResponse, Token
from src.repository import user as repository_user
from src.services.auth import AuthPassword, AuthToken

router = APIRouter(prefix="/auth", tags=['auth'])
security = HTTPBearer()
authpassword = AuthPassword()
authtoken = AuthToken()


@router.post("/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED, description='Create new user')
async def sign_up(body: UserModel, db: Session = Depends(get_db)):
    check_user = await repository_user.get_user_by_email(body.email, db)
    if check_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='This email is already in use')
    body.password = authpassword.get_hash_password(body.password)
    new_user = await repository_user.add_user(body, db)
    return new_user


@router.post("/login", response_model=Token)
async def login(body: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = await repository_user.get_user_by_email(body.username, db)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email")
    if not authpassword.verify_password(body.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")

    access_token = await authtoken.create_access_token(data={"sub": user.email})
    refresh_token = await authtoken.create_refresh_token(data={"sub": user.email})
    await repository_user.update_token(user, refresh_token, db)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.post("/refresh_token", response_model=Token)
async def refresh_token(credentials: HTTPAuthorizationCredentials = Security(security), db: Session = Depends(get_db)):
    token = credentials.credentials
    email = await authtoken.decode_refresh_token(token)
    user = await repository_user.get_user_by_email(email, db)
    if user.refresh_token != token:
        await repository_user.update_token(user, None, db)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    access_token = await authtoken.create_access_token(data={"sub": email})
    refresh_token = await authtoken.create_refresh_token(data={"sub": email})
    await repository_user.update_token(user, refresh_token, db)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}






