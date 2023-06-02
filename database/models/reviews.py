from datetime import datetime

from sqlalchemy import *

from database.models.base import Base


class Reviews(Base):
    __tablename__ = 'reviews'

    id = Column(Integer, primary_key=True)
    id_area = Column(Integer, nullable=False)
    id_1C = Column(Text(300), nullable=False)
    mail = Column(String(30), nullable=False)
    review = Column(Text(300), nullable=False)
    date = Column(DateTime, default=datetime.utcnow)

    user_id = Column(Integer(), ForeignKey('rating_users.id'), nullable=False)

    def __repr__(self):
        return "<{}:{}>".format(id, self.name)
