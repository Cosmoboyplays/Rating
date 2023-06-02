from database.models.base import Base
from sqlalchemy import *


class Areas(Base):
    __tablename__ = "areas"

    id_area = Column(Integer, primary_key=True)
    area = Column(Text(250), nullable=False)
    id_rating_user = Column(Integer(), ForeignKey('rating_users.id'), nullable=False)

    def __repr__(self):
        return "<{}:{}>".format(id, self.name)
