from sqlalchemy import Column, Integer, String, Boolean, DateTime, BigInteger, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class Admin(Base):
    __tablename__ = "admins"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    totp_secret = Column(String, nullable=True)
    is_2fa_enabled = Column(Boolean, default=False)
    last_login_at = Column(DateTime, nullable=True)
    last_login_ip = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    audit_logs = relationship("AuditLog", back_populates="admin")

class Node(Base):
    __tablename__ = "nodes"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    api_address = Column(String, nullable=False)
    api_token = Column(String, nullable=False)
    status = Column(String, default="offline") # online / offline

    inbounds = relationship("Inbound", back_populates="node")

class Inbound(Base):
    __tablename__ = "inbounds"

    id = Column(Integer, primary_key=True, index=True)
    remark = Column(String, nullable=False)
    protocol = Column(String, nullable=False) # vmess / vless / trojan / shadowsocks
    port = Column(Integer, unique=True, nullable=False)
    listen = Column(String, default="0.0.0.0")
    network = Column(String, default="tcp") # tcp / ws / grpc / http2 / kcp
    security = Column(String, default="none") # none / tls / reality
    stream_settings = Column(Text, nullable=True) # JSON string for transport settings
    sniffing = Column(Text, nullable=True) # JSON string for sniffing settings
    enabled = Column(Boolean, default=True)
    total_traffic_limit = Column(BigInteger, nullable=True) # bytes
    expire_at = Column(DateTime, nullable=True)
    node_id = Column(Integer, ForeignKey("nodes.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    node = relationship("Node", back_populates="inbounds")
    clients = relationship("Client", back_populates="inbound", cascade="all, delete-orphan")

class Client(Base):
    __tablename__ = "clients"

    id = Column(Integer, primary_key=True, index=True)
    inbound_id = Column(Integer, ForeignKey("inbounds.id"), nullable=False)
    uuid_or_password = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    flow = Column(String, nullable=True) # for XTLS
    limit_ip = Column(Integer, default=0)
    total_gb = Column(BigInteger, default=0) # bytes (0 = unlimited)
    up = Column(BigInteger, default=0)
    down = Column(BigInteger, default=0)
    expiry_time = Column(DateTime, nullable=True)
    enable = Column(Boolean, default=True)
    sub_id = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    inbound = relationship("Inbound", back_populates="clients")
    traffic_logs = relationship("TrafficLog", back_populates="client", cascade="all, delete-orphan")

class TrafficLog(Base):
    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    up = Column(BigInteger, default=0)
    down = Column(BigInteger, default=0)
    recorded_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client", back_populates="traffic_logs")

class Setting(Base):
    __tablename__ = "settings"

    key = Column(String, primary_key=True, index=True)
    value = Column(Text, nullable=False) # JSON or string

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey("admins.id"), nullable=True)
    action = Column(String, nullable=False)
    ip_address = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    admin = relationship("Admin", back_populates="audit_logs")
