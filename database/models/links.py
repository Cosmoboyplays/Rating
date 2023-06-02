from sqlalchemy import *

from database.models import Base


class Links(Base):
    __tablename__ = 'links'

    id = Column(Integer, primary_key=True)
    link = Column(Text(300), nullable=False)
    name = Column(Text(30), nullable=False)
    checkbox = Column(Text(30), nullable=False)

    id_area = Column(Integer(), ForeignKey('areas.id_area'), nullable=False)
    

    def __repr__(self):
        return "<{}:{}>".format(id, self.name)