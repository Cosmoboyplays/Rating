from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .models.base import Base

engine = create_engine(
    'mysql+pymysql://root:.Cosmos534534@localhost/Rating'
)

session_maker = sessionmaker(
    bind=engine, autoflush=False,
    autocommit=False, expire_on_commit=False
)

Base.metadata.create_all(engine)
