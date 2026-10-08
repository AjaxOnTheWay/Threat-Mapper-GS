from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, UniqueConstraint, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    siem_configs = relationship("SiemConfigRecord", back_populates="organization", cascade="all, delete-orphan")
    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="analyst")
    org_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    organization = relationship("Organization", back_populates="users")

class SiemConfigRecord(Base):
    __tablename__ = "siem_configs"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    siem_type = Column(String(50), nullable=False)
    endpoint_url = Column(String(255), nullable=True)
    auth_token = Column(String(255), nullable=False)
    sync_mode = Column(String(20), default="push")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    organization = relationship("Organization", back_populates="siem_configs")

    __table_args__ = (
        UniqueConstraint("org_id", "siem_type", name="uq_org_siem_type"),
    )

class IOCRecord(Base):
    __tablename__ = "ioc_records"
    
    id = Column(Integer, primary_key=True, index=True)
    ioc_value = Column(String(255), unique=True, index=True, nullable=False)
    ioc_type = Column(String(50), nullable=False)
    verdict = Column(String(50), nullable=False)
    confidence_score = Column(Float, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow)


class WatchlistRecord(Base):
    __tablename__ = "watchlist_records"
    
    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    ioc_value = Column(String, index=True, nullable=False)
    ioc_type = Column(String, nullable=False)
    added_at = Column(DateTime, default=datetime.utcnow)
    last_checked = Column(DateTime, nullable=True)
    alert_on_change = Column(Boolean, default=True)