from datetime import datetime

from sqlalchemy import MetaData, Integer, String, TIMESTAMP, ForeignKey, Column, JSON
from pydantic import BaseModel
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
import passlib.hash as _hash
from sqlalchemy.orm import relationship

metadata = MetaData()

# Базовый класс моделей
Base = declarative_base()


class Role(Base):
    __tablename__ = "roles"

    metadata = metadata
    id = Column("id", Integer, primary_key=True, index=True)
    name = Column("name", String)
    permissions = Column("permissions", JSON)

    users = relationship("User", back_populates="roles")


class User(Base):
    __tablename__ = "users"

    metadata = metadata
    id = Column("id", Integer, primary_key=True, index=True)
    email = Column("email", String)
    username = Column("username", String)
    hashed_password = Column("password", String)
    registered_at = Column("registered_at", TIMESTAMP, default=datetime.utcnow)
    permissions = Column("permissions", JSON)
    role_id = Column(Integer, ForeignKey("roles.id"))

    roles = relationship("Role", back_populates="users")

    def verify_password(self, password: str):
        return _hash.bcrypt.verify(password, self.hashed_password)
