from datetime import datetime, timedelta

from flask_login import UserMixin
from flask_jwt_extended import create_access_token

from database.models.base import Base
from sqlalchemy import *



class RatingUsers(Base, UserMixin):
    __tablename__ = 'rating_users'

    id = Column(Integer, primary_key=True)
    name = Column(String(100))
    login = Column(String(30), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    date_create = Column(DateTime, default=datetime.utcnow)
    token = Column(String(512), nullable=False)

    def get_token(self, expire_time=24):
        expire_delta = timedelta(expire_time)
        token = create_access_token(
            identity=self.id, expires_delta=expire_delta)
        return token

    def __repr__(self):
        return "<{}:{}>".format(id, self.name)
