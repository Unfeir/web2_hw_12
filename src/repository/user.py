from libgravatar import Gravatar
from sqlalchemy.orm import Session

from src.database.models import User
from src.schemas import UserModel


async def get_user_by_email(email, db):
    user = db.query(User).filter(User.email == email).first()
    return user


async def add_user(body: UserModel, db):
    user = User(
        username=body.username,
        email=body.email,
        password=body.password,
        avatar=Gravatar(body.email).get_image()
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


async def update_token(user: User, refresh_token, db: Session):
    user.refresh_token = refresh_token
    db.commit()
