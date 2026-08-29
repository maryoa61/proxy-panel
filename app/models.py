"""SQLAlchemy models for administrators, Xray objects and audit data."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from .database import Base


class Admin(Base):
    __tablename__ = "admins"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    totp_secret = Column(String(128), nullable=True)
    is_2fa_enabled = Column(Boolean, default=False, nullable=False)
    last_login_at = Column(DateTime, nullable=True)
    last_login_ip = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    audit_logs = relationship(
        "AuditLog",
        back_populates="admin",
        cascade="all, delete-orphan",
    )


class Node(Base):
    __tablename__ = "nodes"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False)
    api_address = Column(String(255), nullable=False)
    # This is intentionally only returned to authenticated administrators.
    api_token = Column(String(255), nullable=False)
    status = Column(String(24), default="offline", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    inbounds = relationship("Inbound", back_populates="node")


class Inbound(Base):
    __tablename__ = "inbounds"

    id = Column(Integer, primary_key=True, index=True)
    remark = Column(String(120), nullable=False)
    protocol = Column(String(32), nullable=False)
    port = Column(Integer, unique=True, nullable=False, index=True)
    listen = Column(String(255), default="0.0.0.0", nullable=False)
    # tcp/raw, ws, grpc, http/http2, kcp, quic, httpupgrade and xhttp are
    # supported by the config generator.
    network = Column(String(32), default="tcp", nullable=False)
    security = Column(String(32), default="none", nullable=False)
    # JSON blobs are kept as text so the schema remains compatible with old
    # installations and can preserve protocol-specific Xray options.
    stream_settings = Column(Text, default="{}", nullable=False)
    sniffing = Column(Text, default="{}", nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    total_traffic_limit = Column(BigInteger, nullable=True)
    expire_at = Column(DateTime, nullable=True)
    node_id = Column(Integer, ForeignKey("nodes.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    node = relationship("Node", back_populates="inbounds")
    clients = relationship(
        "Client",
        back_populates="inbound",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Client(Base):
    __tablename__ = "clients"

    id = Column(Integer, primary_key=True, index=True)
    inbound_id = Column(
        Integer,
        ForeignKey("inbounds.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    uuid_or_password = Column(String(255), nullable=False)
    email = Column(String(190), unique=True, index=True, nullable=False)
    flow = Column(String(64), default="", nullable=False)
    limit_ip = Column(Integer, default=0, nullable=False)
    # Kept in gigabytes because this is the unit exposed by the panel API.
    # A value of zero means unlimited.
    total_gb = Column(BigInteger, default=0, nullable=False)
    up = Column(BigInteger, default=0, nullable=False)
    down = Column(BigInteger, default=0, nullable=False)
    expiry_time = Column(DateTime, nullable=True)
    enable = Column(Boolean, default=True, nullable=False)
    sub_id = Column(String(64), unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    inbound = relationship("Inbound", back_populates="clients")
    traffic_logs = relationship(
        "TrafficLog",
        back_populates="client",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class TrafficLog(Base):
    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(
        Integer,
        ForeignKey("clients.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    up = Column(BigInteger, default=0, nullable=False)
    down = Column(BigInteger, default=0, nullable=False)
    recorded_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    client = relationship("Client", back_populates="traffic_logs")


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String(100), primary_key=True, index=True)
    value = Column(Text, nullable=False, default="")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(
        Integer,
        ForeignKey("admins.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    action = Column(String(255), nullable=False)
    ip_address = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    admin = relationship("Admin", back_populates="audit_logs")
