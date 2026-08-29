"""Versioned REST API for the Xray management panel."""

from __future__ import annotations

import base64
import json
import os
import secrets
import socket
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Mapping, Optional, Union
from urllib.parse import quote, urlencode, urlsplit

import requests
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .auth import create_access_token, get_current_admin, hash_password, verify_password
from .database import get_db
from .models import Admin, AuditLog, Client, Inbound, Node, Setting, TrafficLog
from .xray_manager import (
    SUPPORTED_NETWORKS,
    SUPPORTED_PROTOCOLS,
    generate_xray_config,
    get_xray_stats,
    save_and_reload_xray,
)


router = APIRouter(prefix="/api/v1")

ALLOWED_SETTINGS = {
    "server_domain",
    "server_ip",
    "server_host",
    "panel_name",
    "subscription_base_url",
    "xray_log_level",
    "xray_config_path",
    "timezone",
}


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)
    totp_code: Optional[str] = Field(default=None, max_length=16)


class InboundCreate(BaseModel):
    remark: str = Field(..., min_length=1, max_length=120)
    protocol: str = Field(default="vless", max_length=32)
    port: int = Field(default=443, ge=1, le=65535)
    listen: str = Field(default="0.0.0.0", max_length=255)
    network: str = Field(default="tcp", max_length=32)
    security: str = Field(default="none", max_length=32)
    # Legacy clients send a JSON string; the Vue client sends one too so the
    # database remains readable and compatible with existing installations.
    stream_settings: Union[str, Dict[str, Any], None] = "{}"
    sniffing: Union[str, Dict[str, Any], None] = "{}"
    total_traffic_limit: Optional[int] = Field(default=None, ge=0)
    expire_at: Optional[datetime] = None
    node_id: Optional[int] = Field(default=None, ge=1)
    enabled: bool = True


class ClientCreate(BaseModel):
    # Kept optional because the nested endpoint already carries the id, while
    # old API clients include it in their body.
    inbound_id: Optional[int] = Field(default=None, ge=1)
    email: str = Field(..., min_length=1, max_length=190)
    uuid_or_password: Optional[str] = Field(default=None, min_length=1, max_length=255)
    flow: Optional[str] = Field(default="", max_length=64)
    limit_ip: int = Field(default=0, ge=0, le=100000)
    total_gb: int = Field(default=0, ge=0)
    expiry_time: Optional[datetime] = None
    enable: bool = True


class ClientUpdate(BaseModel):
    email: Optional[str] = Field(default=None, min_length=1, max_length=190)
    uuid_or_password: Optional[str] = Field(default=None, min_length=1, max_length=255)
    flow: Optional[str] = Field(default=None, max_length=64)
    limit_ip: Optional[int] = Field(default=None, ge=0, le=100000)
    total_gb: Optional[int] = Field(default=None, ge=0)
    expiry_time: Optional[datetime] = None
    enable: Optional[bool] = None


class NodeCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    api_address: str = Field(..., min_length=1, max_length=255)
    api_token: str = Field(default="", max_length=255)


class NodeUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    api_address: Optional[str] = Field(default=None, min_length=1, max_length=255)
    api_token: Optional[str] = Field(default=None, max_length=255)
    status: Optional[str] = Field(default=None, max_length=24)


class SettingsUpdate(BaseModel):
    settings: Dict[str, Any]


class PasswordChange(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=72)


# ---------------------------------------------------------------------------
# Serialization and validation helpers
# ---------------------------------------------------------------------------
def _json_object(value: Any, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    fallback = dict(default or {})
    if value is None or value == "":
        return fallback
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return dict(parsed) if isinstance(parsed, Mapping) else fallback
        except (TypeError, ValueError, json.JSONDecodeError):
            return fallback
    return fallback


def _json_text(value: Any) -> str:
    if value is None or value == "":
        return "{}"
    if isinstance(value, str):
        # Validate JSON so a malformed stream object cannot poison config
        # generation later. Empty strings are treated as an empty object.
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=422, detail=f"JSON نامعتبر در تنظیمات: {exc}")
        if not isinstance(parsed, dict):
            raise HTTPException(status_code=422, detail="تنظیمات انتقال باید یک شیء JSON باشد")
        return json.dumps(parsed, ensure_ascii=False)
    if isinstance(value, Mapping):
        return json.dumps(dict(value), ensure_ascii=False)
    raise HTTPException(status_code=422, detail="تنظیمات انتقال باید JSON باشد")


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def _validate_inbound_options(req: InboundCreate) -> None:
    protocol = req.protocol.strip().lower()
    network = req.network.strip()
    security = req.security.strip().lower()
    if protocol not in SUPPORTED_PROTOCOLS:
        raise HTTPException(status_code=422, detail="پروتکل انتخاب‌شده پشتیبانی نمی‌شود")
    if network not in SUPPORTED_NETWORKS and network.lower() not in {n.lower() for n in SUPPORTED_NETWORKS}:
        raise HTTPException(status_code=422, detail="ترنسپورت انتخاب‌شده پشتیبانی نمی‌شود")
    if security not in {"none", "tls", "reality"}:
        raise HTTPException(status_code=422, detail="نوع امنیت باید none، tls یا reality باشد")
    if security == "reality" and protocol != "vless":
        raise HTTPException(status_code=422, detail="XTLS-Reality فقط برای VLESS فعال است")
    if not req.listen.strip():
        raise HTTPException(status_code=422, detail="آدرس listen نمی‌تواند خالی باشد")
    # Force JSON validation on both create and update.
    _json_text(req.stream_settings)
    _json_text(req.sniffing)


def _inbound_dict(ib: Inbound) -> Dict[str, Any]:
    return {
        "id": ib.id,
        "remark": ib.remark,
        "protocol": ib.protocol,
        "port": ib.port,
        "listen": ib.listen,
        "network": ib.network,
        "security": ib.security,
        "stream_settings": ib.stream_settings or "{}",
        "stream_settings_object": _json_object(ib.stream_settings),
        "sniffing": ib.sniffing or "{}",
        "enabled": bool(ib.enabled),
        "total_traffic_limit": ib.total_traffic_limit,
        "expire_at": _iso(ib.expire_at),
        "node_id": ib.node_id,
        "created_at": _iso(ib.created_at),
        "updated_at": _iso(ib.updated_at),
        "clients_count": len(ib.clients),
        "active_clients_count": sum(1 for client in ib.clients if client.enable),
    }


def _client_dict(client: Client, include_credential: bool = True) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "id": client.id,
        "inbound_id": client.inbound_id,
        "email": client.email,
        "flow": client.flow or "",
        "limit_ip": client.limit_ip or 0,
        "total_gb": client.total_gb or 0,
        "traffic_limit_bytes": (client.total_gb or 0) * 1024**3,
        "up": client.up or 0,
        "down": client.down or 0,
        "traffic_total": (client.up or 0) + (client.down or 0),
        "expiry_time": _iso(client.expiry_time),
        "enable": bool(client.enable),
        "sub_id": client.sub_id,
        "created_at": _iso(client.created_at),
        "updated_at": _iso(client.updated_at),
    }
    if include_credential:
        # This endpoint is private and the credential is required for copying
        # links in the admin UI. It is never returned by public subscription
        # routes or unauthenticated endpoints.
        result["uuid_or_password"] = client.uuid_or_password
        result["uuid"] = client.uuid_or_password
    if client.inbound is not None:
        result["inbound_remark"] = client.inbound.remark
        result["protocol"] = client.inbound.protocol
    return result


def _node_dict(node: Node) -> Dict[str, Any]:
    return {
        "id": node.id,
        "name": node.name,
        "api_address": node.api_address,
        "api_token": node.api_token,
        "api_token_masked": f"{node.api_token[:4]}••••{node.api_token[-4:]}" if len(node.api_token) > 8 else ("••••" if node.api_token else ""),
        "status": node.status,
        "created_at": _iso(node.created_at),
        "inbounds_count": len(node.inbounds),
    }


def _get_inbound(db: Session, inbound_id: int) -> Inbound:
    ib = db.query(Inbound).filter(Inbound.id == inbound_id).first()
    if not ib:
        raise HTTPException(status_code=404, detail="اینباند یافت نشد")
    return ib


def _get_client(db: Session, client_id: int) -> Client:
    client = db.query(Client).filter(Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="کلاینت یافت نشد")
    return client


def _audit(db: Session, admin_id: Optional[int], action: str, request: Optional[Request] = None) -> None:
    db.add(
        AuditLog(
            admin_id=admin_id,
            action=action,
            ip_address=(request.client.host if request and request.client else None),
        )
    )


def _admin_id(current_admin: dict) -> Optional[int]:
    try:
        return int(current_admin.get("id"))
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Dynamic server host resolution and client links
# ---------------------------------------------------------------------------
def _normalise_host(value: Any) -> str:
    """Return a host suitable for a client URI, without scheme or path."""

    if value is None:
        return ""
    raw = str(value).strip()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlsplit(raw)
        raw = parsed.hostname or parsed.netloc or parsed.path.split("/", 1)[0]
    else:
        raw = raw.split("/", 1)[0].strip()
    if raw.startswith("[") and raw.endswith("]"):
        return raw[1:-1]
    # Links always append the inbound port; discard an optional port entered
    # alongside a domain to avoid producing host:old-port:new-port.
    if raw.count(":") == 1:
        host, maybe_port = raw.rsplit(":", 1)
        if maybe_port.isdigit():
            return host
    return raw


def get_server_host(db: Session) -> str:
    """Resolve the public host in deterministic priority order.

    1. Non-empty ``server_domain``/``server_host``/``server_ip`` in Settings.
    2. ``SERVER_HOST`` or ``SERVER_DOMAIN`` environment variables.
    3. A short public-IP lookup (opt-out with ``ENABLE_PUBLIC_IP_LOOKUP=0``).
    4. The machine's local hostname/IP and finally 127.0.0.1.

    Settings are read on every call on purpose: changing a domain immediately
    changes newly generated links and subscriptions without restarting the app.
    """

    for key in ("server_domain", "server_host", "server_ip"):
        setting = db.query(Setting).filter(Setting.key == key).first()
        host = _normalise_host(setting.value if setting else "")
        if host:
            return host

    for key in ("SERVER_HOST", "SERVER_DOMAIN"):
        host = _normalise_host(os.getenv(key, ""))
        if host:
            return host

    if os.getenv("ENABLE_PUBLIC_IP_LOOKUP", "1").lower() not in {"0", "false", "no"}:
        try:
            response = requests.get("https://api.ipify.org", timeout=2)
            if response.ok:
                host = _normalise_host(response.text)
                if host:
                    return host
        except requests.RequestException:
            pass

    try:
        local = socket.gethostbyname(socket.gethostname())
        if local and not local.startswith("127."):
            return local
    except OSError:
        pass
    return "127.0.0.1"


def _link_host(host: str) -> str:
    # URI syntax requires brackets around a raw IPv6 address.
    if ":" in host and not host.startswith("[") and host.count(":") > 1:
        return f"[{host}]"
    return host


def _fragment(value: str) -> str:
    return quote(str(value or ""), safe="-._~")


def _stream_for_link(ib: Inbound) -> Dict[str, Any]:
    stream = _json_object(ib.stream_settings)
    # The API accepts both the panel-friendly flat form and native Xray's
    # nested ``wsSettings``/``realitySettings`` form. Flatten only missing
    # fields for link generation so either form produces the same URI.
    for nested_key in (
        "wsSettings",
        "grpcSettings",
        "httpSettings",
        "httpupgradeSettings",
        "xhttpSettings",
        "tlsSettings",
        "realitySettings",
    ):
        nested = stream.get(nested_key)
        if isinstance(nested, Mapping):
            for key, value in nested.items():
                stream.setdefault(key, value)
    return stream


def _link_query(ib: Inbound, client: Client) -> Dict[str, str]:
    stream = _stream_for_link(ib)
    network = ib.network or "tcp"
    query: Dict[str, str] = {
        "encryption": "none",
        "security": ib.security or "none",
        "type": {"http2": "http", "raw": "tcp", "gRPC": "grpc"}.get(network, network),
    }
    if client.flow:
        query["flow"] = client.flow
    if ib.security == "reality":
        for output, *keys in (
            ("sni", "serverName", "server_name", "sni"),
            ("fp", "fingerprint", "fp"),
            ("pbk", "publicKey", "public_key", "pbk"),
            ("sid", "shortId", "short_id", "sid"),
            ("spx", "spiderX", "spider_x", "spx"),
        ):
            for key in keys:
                if stream.get(key):
                    query[output] = str(stream[key])
                    break
        server_names = stream.get("serverNames") or stream.get("server_names")
        if isinstance(server_names, list) and server_names and "sni" not in query:
            query["sni"] = str(server_names[0])
    elif ib.security == "tls":
        server_name = stream.get("serverName") or stream.get("server_name")
        if server_name:
            query["sni"] = str(server_name)
        if stream.get("alpn"):
            alpn = stream["alpn"]
            query["alpn"] = ",".join(alpn) if isinstance(alpn, list) else str(alpn)

    if network in {"ws", "websocket"}:
        query["path"] = str(stream.get("path", "/ray"))
        headers = stream.get("headers") or {}
        if isinstance(headers, Mapping) and headers.get("Host"):
            query["host"] = str(headers["Host"])
    elif network in {"grpc", "gRPC"}:
        query["serviceName"] = str(stream.get("serviceName") or stream.get("service_name") or "grpc")
        if stream.get("mode"):
            query["mode"] = str(stream["mode"])
    elif network in {"http", "http2"}:
        query["path"] = str(stream.get("path", "/"))
        hosts = stream.get("host") or stream.get("hosts")
        if isinstance(hosts, list) and hosts:
            query["host"] = str(hosts[0])
        elif hosts:
            query["host"] = str(hosts)
    elif network in {"httpupgrade", "xhttp"}:
        query["path"] = str(stream.get("path", "/"))
        if stream.get("host"):
            query["host"] = str(stream["host"])
    return query


def build_client_link(client: Client, ib: Inbound, server_host: str) -> str:
    """Build a standard URI for VMess, VLESS, Trojan or Shadowsocks."""

    host = _link_host(_normalise_host(server_host) or "127.0.0.1")
    stream = _stream_for_link(ib)
    protocol = ib.protocol.lower()
    name = _fragment(client.email)

    if protocol == "vless":
        query = urlencode(_link_query(ib, client), doseq=True)
        return f"vless://{quote(client.uuid_or_password, safe='')}@{host}:{ib.port}?{query}#{name}"

    if protocol == "vmess":
        network = {"http2": "http", "raw": "tcp", "gRPC": "grpc"}.get(ib.network, ib.network)
        headers = stream.get("headers") if isinstance(stream.get("headers"), Mapping) else {}
        vmess = {
            "v": "2",
            "ps": client.email,
            "add": _normalise_host(server_host) or "127.0.0.1",
            "port": str(ib.port),
            "id": client.uuid_or_password,
            "aid": 0,
            "scy": "auto",
            "net": network,
            "type": "none",
            "host": str(headers.get("Host", stream.get("host", ""))) if headers else str(stream.get("host", "")),
            "path": str(stream.get("path", "/" if network == "http" else "")),
            "tls": "tls" if ib.security in {"tls", "reality"} else "",
            "sni": str(stream.get("serverName", "")),
        }
        return "vmess://" + base64.b64encode(json.dumps(vmess, ensure_ascii=False, separators=(",", ":")).encode()).decode()

    if protocol == "trojan":
        query = urlencode({k: v for k, v in _link_query(ib, client).items() if k != "encryption"})
        return f"trojan://{quote(client.uuid_or_password, safe='')}@{host}:{ib.port}?{query}#{name}"

    if protocol == "shadowsocks":
        method = str(stream.get("method", "aes-128-gcm"))
        userinfo = base64.urlsafe_b64encode(
            f"{method}:{client.uuid_or_password}".encode("utf-8")
        ).decode("ascii").rstrip("=")
        return f"ss://{userinfo}@{host}:{ib.port}#{name}"

    raise HTTPException(status_code=422, detail="پروتکل کلاینت پشتیبانی نمی‌شود")


# ---------------------------------------------------------------------------
# Config/reload helpers
# ---------------------------------------------------------------------------
def _inbounds_data(db: Session) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for ib in db.query(Inbound).order_by(Inbound.id.asc()).all():
        result.append(
            {
                "id": ib.id,
                "remark": ib.remark,
                "protocol": ib.protocol,
                "port": ib.port,
                "listen": ib.listen,
                "network": ib.network,
                "security": ib.security,
                "stream_settings": ib.stream_settings,
                "sniffing": ib.sniffing,
                "enabled": ib.enabled,
                "expire_at": ib.expire_at,
                "clients": [
                    {
                        "uuid_or_password": client.uuid_or_password,
                        "email": client.email,
                        "flow": client.flow,
                        "enable": client.enable,
                        "expiry_time": client.expiry_time,
                    }
                    for client in ib.clients
                ],
            }
        )
    return result


def trigger_xray_reload(db: Session) -> bool:
    return save_and_reload_xray(_inbounds_data(db))


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
@router.post("/auth/login")
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    admin = db.query(Admin).filter(Admin.username == req.username).first()
    if not admin or not verify_password(req.password, admin.password_hash):
        # Do not distinguish a missing user from a wrong password.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="نام کاربری یا کلمه عبور اشتباه است",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if admin.is_2fa_enabled and not req.totp_code:
        raise HTTPException(status_code=401, detail="کد تایید دو مرحله‌ای الزامی است")

    admin.last_login_at = datetime.utcnow()
    admin.last_login_ip = request.client.host if request.client else None
    _audit(db, admin.id, f"ورود مدیر {admin.username}", request)
    db.commit()

    token = create_access_token({"sub": admin.username, "id": admin.id})
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": int(os.getenv("JWT_EXPIRE_MINUTES", "1440")) * 60,
    }


@router.post("/auth/logout")
def logout(current_admin: dict = Depends(get_current_admin)):
    return {"status": "success", "message": "با موفقیت خارج شدید"}


@router.get("/auth/me")
def get_me(current_admin: dict = Depends(get_current_admin), db: Session = Depends(get_db)):
    admin = db.query(Admin).filter(Admin.id == _admin_id(current_admin)).first()
    if not admin:
        raise HTTPException(status_code=401, detail="حساب مدیر یافت نشد")
    return {
        "id": admin.id,
        "username": admin.username,
        "is_2fa_enabled": bool(admin.is_2fa_enabled),
        "last_login_at": _iso(admin.last_login_at),
    }


@router.post("/auth/change-password")
def change_password(
    req: PasswordChange,
    request: Request,
    current_admin: dict = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    admin = db.query(Admin).filter(Admin.id == _admin_id(current_admin)).first()
    if not admin or not verify_password(req.current_password, admin.password_hash):
        raise HTTPException(status_code=400, detail="کلمه عبور فعلی صحیح نیست")
    if req.current_password == req.new_password:
        raise HTTPException(status_code=400, detail="کلمه عبور جدید باید متفاوت باشد")
    admin.password_hash = hash_password(req.new_password)
    _audit(db, admin.id, "تغییر کلمه عبور", request)
    db.commit()
    return {"status": "success", "message": "کلمه عبور تغییر کرد؛ لطفاً دوباره وارد شوید"}


# ---------------------------------------------------------------------------
# Dashboard and metrics
# ---------------------------------------------------------------------------
@router.get("/dashboard/overview")
def dashboard_overview(
    db: Session = Depends(get_db),
    current_admin: dict = Depends(get_current_admin),
):
    total_inbounds = db.query(Inbound).count()
    total_clients = db.query(Client).count()
    active_clients = db.query(Client).filter(Client.enable.is_(True)).count()
    clients = db.query(Client).all()
    total_up = sum(client.up or 0 for client in clients)
    total_down = sum(client.down or 0 for client in clients)
    stats = get_xray_stats(db_active_clients_count=active_clients)
    return {
        "xray_status": stats,
        "total_inbounds": total_inbounds,
        "total_clients": total_clients,
        "active_clients": active_clients,
        "total_traffic": {"up": total_up, "down": total_down, "sum": total_up + total_down},
        "server_host": get_server_host(db),
    }


@router.get("/dashboard/traffic-chart")
def traffic_chart(
    period: str = Query(default="day", alias="range", pattern="^(day|week|month)$"),
    db: Session = Depends(get_db),
    current_admin: dict = Depends(get_current_admin),
):
    now = datetime.utcnow()
    if period == "day":
        count, step, label_format = 12, timedelta(hours=2), "%H:%M"
        start = now - timedelta(hours=24)
    elif period == "week":
        count, step, label_format = 7, timedelta(days=1), "%a"
        start = now - timedelta(days=7)
    else:
        count, step, label_format = 30, timedelta(days=1), "%d/%m"
        start = now - timedelta(days=30)

    logs = db.query(TrafficLog).filter(TrafficLog.recorded_at >= start).all()
    up = [0] * count
    down = [0] * count
    for log in logs:
        try:
            index = int((log.recorded_at - start) / step)
            if 0 <= index < count:
                up[index] += log.up or 0
                down[index] += log.down or 0
        except (TypeError, ValueError, ZeroDivisionError):
            continue
    labels = [(start + step * index).strftime(label_format) for index in range(count)]
    return {"range": period, "labels": labels, "up": up, "down": down}


# ---------------------------------------------------------------------------
# Inbounds
# ---------------------------------------------------------------------------
@router.get("/inbounds")
def get_inbounds(db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    return [_inbound_dict(ib) for ib in db.query(Inbound).order_by(Inbound.id.desc()).all()]


@router.get("/inbounds/{inbound_id}")
def get_inbound(
    inbound_id: int,
    db: Session = Depends(get_db),
    current_admin: dict = Depends(get_current_admin),
):
    return _inbound_dict(_get_inbound(db, inbound_id))


@router.post("/inbounds")
def create_inbound(
    req: InboundCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: dict = Depends(get_current_admin),
):
    _validate_inbound_options(req)
    if db.query(Inbound).filter(Inbound.port == req.port).first():
        raise HTTPException(status_code=400, detail="این پورت قبلاً استفاده شده است")
    if req.node_id is not None and not db.query(Node).filter(Node.id == req.node_id).first():
        raise HTTPException(status_code=404, detail="نود انتخاب‌شده یافت نشد")

    ib = Inbound(
        remark=req.remark.strip(),
        protocol=req.protocol.strip().lower(),
        port=req.port,
        listen=req.listen.strip(),
        network=req.network.strip(),
        security=req.security.strip().lower(),
        stream_settings=_json_text(req.stream_settings),
        sniffing=_json_text(req.sniffing),
        total_traffic_limit=req.total_traffic_limit,
        expire_at=req.expire_at,
        node_id=req.node_id,
        enabled=req.enabled,
    )
    db.add(ib)
    try:
        db.flush()
        _audit(db, _admin_id(current_admin), f"ایجاد اینباند {ib.remark}", request)
        db.commit()
        db.refresh(ib)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="اینباند تکراری یا نامعتبر است")

    reload_ok = trigger_xray_reload(db)
    return {"status": "success", "id": ib.id, "reload_ok": reload_ok, "inbound": _inbound_dict(ib)}


@router.put("/inbounds/{inbound_id}")
def update_inbound(
    inbound_id: int,
    req: InboundCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: dict = Depends(get_current_admin),
):
    _validate_inbound_options(req)
    ib = _get_inbound(db, inbound_id)
    port_owner = db.query(Inbound).filter(Inbound.port == req.port, Inbound.id != inbound_id).first()
    if port_owner:
        raise HTTPException(status_code=400, detail="این پورت قبلاً استفاده شده است")
    if req.node_id is not None and not db.query(Node).filter(Node.id == req.node_id).first():
        raise HTTPException(status_code=404, detail="نود انتخاب‌شده یافت نشد")
    ib.remark = req.remark.strip()
    ib.protocol = req.protocol.strip().lower()
    ib.port = req.port
    ib.listen = req.listen.strip()
    ib.network = req.network.strip()
    ib.security = req.security.strip().lower()
    ib.stream_settings = _json_text(req.stream_settings)
    ib.sniffing = _json_text(req.sniffing)
    ib.total_traffic_limit = req.total_traffic_limit
    ib.expire_at = req.expire_at
    ib.node_id = req.node_id
    ib.enabled = req.enabled
    _audit(db, _admin_id(current_admin), f"ویرایش اینباند {ib.remark}", request)
    db.commit()
    reload_ok = trigger_xray_reload(db)
    return {"status": "success", "reload_ok": reload_ok, "inbound": _inbound_dict(ib)}


@router.delete("/inbounds/{inbound_id}")
def delete_inbound(
    inbound_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: dict = Depends(get_current_admin),
):
    ib = _get_inbound(db, inbound_id)
    remark = ib.remark
    db.delete(ib)
    _audit(db, _admin_id(current_admin), f"حذف اینباند {remark}", request)
    db.commit()
    reload_ok = trigger_xray_reload(db)
    return {"status": "success", "reload_ok": reload_ok}


@router.post("/inbounds/{inbound_id}/toggle")
def toggle_inbound(
    inbound_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: dict = Depends(get_current_admin),
):
    ib = _get_inbound(db, inbound_id)
    ib.enabled = not ib.enabled
    _audit(db, _admin_id(current_admin), f"تغییر وضعیت اینباند {ib.remark}", request)
    db.commit()
    reload_ok = trigger_xray_reload(db)
    return {"status": "success", "enabled": bool(ib.enabled), "reload_ok": reload_ok}


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------
@router.get("/clients")
def get_clients(db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    clients = db.query(Client).order_by(Client.id.desc()).all()
    return [_client_dict(client) for client in clients]


@router.get("/inbounds/{inbound_id}/clients")
def get_inbound_clients(
    inbound_id: int,
    db: Session = Depends(get_db),
    current_admin: dict = Depends(get_current_admin),
):
    _get_inbound(db, inbound_id)
    clients = db.query(Client).filter(Client.inbound_id == inbound_id).order_by(Client.id.desc()).all()
    return [_client_dict(client) for client in clients]


@router.post("/inbounds/{inbound_id}/clients")
def create_client(
    inbound_id: int,
    req: ClientCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: dict = Depends(get_current_admin),
):
    ib = _get_inbound(db, inbound_id)
    if req.inbound_id is not None and req.inbound_id != inbound_id:
        raise HTTPException(status_code=422, detail="شناسه اینباند با مسیر درخواست یکسان نیست")
    if db.query(Client).filter(func.lower(Client.email) == req.email.lower()).first():
        raise HTTPException(status_code=400, detail="این ایمیل قبلاً استفاده شده است")

    credential = req.uuid_or_password or (
        str(uuid.uuid4()) if ib.protocol in {"vless", "vmess"} else secrets.token_urlsafe(18)
    )
    client = Client(
        inbound_id=inbound_id,
        email=req.email.strip(),
        uuid_or_password=credential,
        flow=req.flow or "",
        limit_ip=req.limit_ip,
        total_gb=req.total_gb,
        expiry_time=req.expiry_time,
        enable=req.enable,
        sub_id=uuid.uuid4().hex,
    )
    db.add(client)
    try:
        db.flush()
        _audit(db, _admin_id(current_admin), f"ایجاد کلاینت {client.email}", request)
        db.commit()
        db.refresh(client)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="ایمیل یا شناسه اشتراک تکراری است")

    reload_ok = trigger_xray_reload(db)
    result = _client_dict(client)
    return {
        "status": "success",
        "id": client.id,
        "uuid": credential,
        "sub_id": client.sub_id,
        "reload_ok": reload_ok,
        "client": result,
    }


@router.put("/clients/{client_id}")
def update_client(
    client_id: int,
    req: ClientUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: dict = Depends(get_current_admin),
):
    client = _get_client(db, client_id)
    if req.email is not None:
        duplicate = (
            db.query(Client)
            .filter(func.lower(Client.email) == req.email.lower(), Client.id != client_id)
            .first()
        )
        if duplicate:
            raise HTTPException(status_code=400, detail="این ایمیل قبلاً استفاده شده است")
        client.email = req.email.strip()
    for field in ("uuid_or_password", "flow", "limit_ip", "total_gb", "expiry_time", "enable"):
        value = getattr(req, field)
        if value is not None:
            setattr(client, field, value)
    _audit(db, _admin_id(current_admin), f"ویرایش کلاینت {client.email}", request)
    db.commit()
    reload_ok = trigger_xray_reload(db)
    return {"status": "success", "reload_ok": reload_ok, "client": _client_dict(client)}


@router.delete("/clients/{client_id}")
def delete_client(
    client_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: dict = Depends(get_current_admin),
):
    client = _get_client(db, client_id)
    email = client.email
    db.delete(client)
    _audit(db, _admin_id(current_admin), f"حذف کلاینت {email}", request)
    db.commit()
    reload_ok = trigger_xray_reload(db)
    return {"status": "success", "reload_ok": reload_ok}


@router.post("/clients/{client_id}/toggle")
def toggle_client(
    client_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: dict = Depends(get_current_admin),
):
    client = _get_client(db, client_id)
    client.enable = not client.enable
    _audit(db, _admin_id(current_admin), f"تغییر وضعیت کلاینت {client.email}", request)
    db.commit()
    reload_ok = trigger_xray_reload(db)
    return {"status": "success", "enable": bool(client.enable), "reload_ok": reload_ok}


@router.post("/clients/{client_id}/reset-traffic")
def reset_client_traffic(
    client_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: dict = Depends(get_current_admin),
):
    client = _get_client(db, client_id)
    client.up = 0
    client.down = 0
    _audit(db, _admin_id(current_admin), f"ریست ترافیک کلاینت {client.email}", request)
    db.commit()
    return {"status": "success"}


@router.get("/clients/{client_id}/config-link")
def get_client_config_link(
    client_id: int,
    db: Session = Depends(get_db),
    current_admin: dict = Depends(get_current_admin),
):
    client = _get_client(db, client_id)
    if not client.inbound:
        raise HTTPException(status_code=404, detail="اینباند مربوط به کلاینت یافت نشد")
    host = get_server_host(db)
    return {
        "link": build_client_link(client, client.inbound, host),
        "host": host,
        "protocol": client.inbound.protocol,
        "sub_id": client.sub_id,
    }


# Public subscription endpoint: no JWT by design, because clients use it in
# their apps. It only exposes a generated link, never database credentials.
@router.get("/sub/{sub_id}")
def public_subscription(sub_id: str, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.sub_id == sub_id).first()
    if not client or not client.inbound:
        raise HTTPException(status_code=404, detail="Subscription not found")
    if client.expiry_time:
        now = datetime.now(client.expiry_time.tzinfo) if client.expiry_time.tzinfo else datetime.utcnow()
        if client.expiry_time <= now:
            raise HTTPException(status_code=410, detail="Subscription expired")
    link = build_client_link(client, client.inbound, get_server_host(db))
    encoded = base64.b64encode(link.encode("utf-8")).decode("ascii")
    return Response(
        content=encoded,
        media_type="text/plain",
        headers={"Cache-Control": "no-store", "Content-Disposition": "inline"},
    )


# ---------------------------------------------------------------------------
# Nodes and settings
# ---------------------------------------------------------------------------
@router.get("/nodes")
def get_nodes(db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    return [_node_dict(node) for node in db.query(Node).order_by(Node.id.desc()).all()]


@router.post("/nodes")
def create_node(
    req: NodeCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: dict = Depends(get_current_admin),
):
    node = Node(name=req.name.strip(), api_address=req.api_address.strip(), api_token=req.api_token, status="offline")
    db.add(node)
    _audit(db, _admin_id(current_admin), f"ایجاد نود {node.name}", request)
    db.commit()
    db.refresh(node)
    return {"status": "success", "id": node.id, "node": _node_dict(node)}


@router.put("/nodes/{node_id}")
def update_node(
    node_id: int,
    req: NodeUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: dict = Depends(get_current_admin),
):
    node = db.query(Node).filter(Node.id == node_id).first()
    if not node:
        raise HTTPException(status_code=404, detail="نود یافت نشد")
    for field in ("name", "api_address", "api_token", "status"):
        value = getattr(req, field)
        if value is not None:
            setattr(node, field, value.strip() if isinstance(value, str) else value)
    _audit(db, _admin_id(current_admin), f"ویرایش نود {node.name}", request)
    db.commit()
    return {"status": "success", "node": _node_dict(node)}


@router.delete("/nodes/{node_id}")
def delete_node(
    node_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: dict = Depends(get_current_admin),
):
    node = db.query(Node).filter(Node.id == node_id).first()
    if not node:
        raise HTTPException(status_code=404, detail="نود یافت نشد")
    name = node.name
    db.delete(node)
    _audit(db, _admin_id(current_admin), f"حذف نود {name}", request)
    db.commit()
    return {"status": "success"}


@router.get("/settings")
def get_settings(db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    values = {setting.key: setting.value for setting in db.query(Setting).order_by(Setting.key.asc()).all()}
    values["_resolved_host"] = get_server_host(db)
    return values


@router.get("/settings/host")
def resolved_host(db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    return {"host": get_server_host(db), "source": "settings-or-fallback"}


@router.put("/settings")
def update_settings(
    req: SettingsUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: dict = Depends(get_current_admin),
):
    changed = []
    for key, value in req.settings.items():
        if key.startswith("_") or key not in ALLOWED_SETTINGS:
            raise HTTPException(status_code=422, detail=f"تنظیمات غیرمجاز: {key}")
        if isinstance(value, (dict, list)):
            text_value = json.dumps(value, ensure_ascii=False)
        elif value is None:
            text_value = ""
        else:
            text_value = str(value).strip()
        setting = db.query(Setting).filter(Setting.key == key).first()
        if setting:
            setting.value = text_value
        else:
            db.add(Setting(key=key, value=text_value))
        # The config generator is process-local and reads these knobs from the
        # environment. Updating them here keeps the preview/reload path in
        # sync without requiring an application restart.
        if key == "xray_log_level" and text_value:
            os.environ["XRAY_LOG_LEVEL"] = text_value
        if key == "xray_config_path":
            os.environ["XRAY_CONFIG_PATH"] = text_value
        changed.append(key)
    _audit(db, _admin_id(current_admin), f"به‌روزرسانی تنظیمات: {', '.join(changed)}", request)
    db.commit()
    return {"status": "success", "changed": changed, "resolved_host": get_server_host(db)}


# ---------------------------------------------------------------------------
# Xray config and audit endpoints
# ---------------------------------------------------------------------------
@router.get("/xray/config")
def preview_xray_config(db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    return generate_xray_config(_inbounds_data(db))


@router.get("/xray/config/download")
def download_xray_config(db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    payload = json.dumps(generate_xray_config(_inbounds_data(db)), ensure_ascii=False, indent=2) + "\n"
    return Response(
        content=payload,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=config.json"},
    )


@router.post("/xray/reload")
def reload_xray(
    request: Request,
    db: Session = Depends(get_db),
    current_admin: dict = Depends(get_current_admin),
):
    ok = trigger_xray_reload(db)
    _audit(db, _admin_id(current_admin), "تولید و reload کانفیگ Xray", request)
    db.commit()
    return {"status": "success", "reload_ok": ok, "config": generate_xray_config(_inbounds_data(db))}


@router.get("/xray/status")
def xray_status(db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    return get_xray_stats(db.query(Client).filter(Client.enable.is_(True)).count())


@router.get("/audit-logs")
def audit_logs(
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_admin: dict = Depends(get_current_admin),
):
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
    return [
        {
            "id": log.id,
            "admin_id": log.admin_id,
            "action": log.action,
            "ip_address": log.ip_address,
            "created_at": _iso(log.created_at),
        }
        for log in logs
    ]


@router.get("/meta/options")
def api_options(current_admin: dict = Depends(get_current_admin)):
    return {
        "protocols": sorted(SUPPORTED_PROTOCOLS),
        "networks": ["tcp", "ws", "grpc", "http2", "kcp", "quic", "httpupgrade", "xhttp"],
        "security": ["none", "tls", "reality"],
    }
