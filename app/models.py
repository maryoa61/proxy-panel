from sqlalchemy import Column, Integer, String, Boolean, DateTime
from datetime import datetime
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    uuid = Column(String, unique=True, nullable=False)
    traffic_limit = Column(Integer, default=0)  # بر حسب بایت یا مگابایت
    used_traffic = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    expire_date = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
