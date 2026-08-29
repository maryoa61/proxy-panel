import json
import base64
import uuid
from datetime import datetime, timedelta
from typing import List, Optional
import os
import requests
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

from .database import get_db
from .models import Admin, Inbound, Client, Node, Setting, AuditLog, TrafficLog
from .auth import hash_password, verify_password, create_access_token, get_current_admin
from .xray_manager import save_and_reload_xray, get_xray_stats

router = APIRouter(prefix="/api/v1")

# --- Pydantic Schemas ---
class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: Optional[str] = None

class InboundCreate(BaseModel):
    remark: str
    protocol: str # vmess, vless, trojan, shadowsocks
    port: int
    listen: Optional[str] = "0.0.0.0"
    network: Optional[str] = "tcp"
    security: Optional[str] = "none"
    stream_settings: Optional[str] = "{}"
    sniffing: Optional[str] = "{}"
    total_traffic_limit: Optional[int] = None
    expire_at: Optional[datetime] = None

class ClientCreate(BaseModel):
    inbound_id: int
    email: str
    uuid_or_password: Optional[str] = None
    flow: Optional[str] = ""
    limit_ip: Optional[int] = 0
    total_gb: Optional[int] = 0 # in GB or bytes
    expiry_time: Optional[datetime] = None

class NodeCreate(BaseModel):
    name: str
    api_address: str
    api_token: str

class SettingsUpdate(BaseModel):
    settings: dict

# --- Helper Functions ---
def get_server_host(db: Session) -> str:
    """
    1. Check settings table for server_domain or server_ip
    2. Check environment variable SERVER_HOST
    3. Fallback to public IP via api.ipify.org or local IP fallback
    """
    setting = db.query(Setting).filter(Setting.key.in_(["server_domain", "server_ip"])).first()
    if setting and setting.value:
        return setting.value

    env_host = os.getenv("SERVER_HOST")
    if env_host:
        return env_host

    try:
        resp = requests.get("https://api.ipify.org", timeout=3)
        if resp.status_code == 200:
            return resp.text.strip()
    except Exception:
        pass

    return "127.0.0.1"

def build_client_link(client: Client, ib: Inbound, server_host: str) -> str:
    link = ""
    if ib.protocol == "vless":
        link = f"vless://{client.uuid_or_password}@{server_host}:{ib.port}?encryption=none&security={ib.security}&type={ib.network}&flow={client.flow}#{client.email}"
    elif ib.protocol == "vmess":
        vmess_json = {
            "v": "2", "ps": client.email, "add": server_host, "port": ib.port,
            "id": client.uuid_or_password, "aid": 0, "net": ib.network, "type": "none",
            "host": "", "path": "", "tls": ib.security
        }
        link = "vmess://" + base64.b64encode(json.dumps(vmess_json).encode()).decode()
    elif ib.protocol == "trojan":
        link = f"trojan://{client.uuid_or_password}@{server_host}:{ib.port}?security={ib.security}&type={ib.network}#{client.email}"
    elif ib.protocol == "shadowsocks":
        link = f"ss://{client.uuid_or_password}@{server_host}:{ib.port}#{client.email}"
    return link

# --- Auth Endpoints ---
@router.post("/auth/login")
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    admin = db.query(Admin).filter(Admin.username == req.username).first()
    if not admin or not verify_password(req.password, admin.password_hash):
        raise HTTPException(status_code=400, detail="نام کاربری یا کلمه عبور اشتباه است")
    
    admin.last_login_at = datetime.utcnow()
    admin.last_login_ip = request.client.host if request.client else "127.0.0.1"
    db.commit()

    audit = AuditLog(admin_id=admin.id, action=f"Login: {admin.username}", ip_address=admin.last_login_ip)
    db.add(audit)
    db.commit()

    token = create_access_token({"sub": admin.username, "id": admin.id})
    return {"access_token": token, "token_type": "bearer"}

@router.post("/auth/logout")
def logout(current_admin: dict = Depends(get_current_admin)):
    return {"status": "success", "message": "با موفقیت خارج شدید"}

@router.get("/auth/me")
def get_me(current_admin: dict = Depends(get_current_admin), db: Session = Depends(get_db)):
    admin = db.query(Admin).filter(Admin.id == current_admin["id"]).first()
    return {"id": admin.id, "username": admin.username, "is_2fa_enabled": admin.is_2fa_enabled}

# --- Dashboard Endpoints ---
@router.get("/dashboard/overview")
def dashboard_overview(db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    total_inbounds = db.query(Inbound).count()
    total_clients = db.query(Client).count()
    active_clients = db.query(Client).filter(Client.enable == True).count()
    
    stats = get_xray_stats(db_active_clients_count=active_clients)
    
    clients = db.query(Client).all()
    total_up = sum(c.up for c in clients)
    total_down = sum(c.down for c in clients)

    return {
        "xray_status": stats,
        "total_inbounds": total_inbounds,
        "total_clients": total_clients,
        "active_clients": active_clients,
        "total_traffic": {
            "up": total_up,
            "down": total_down,
            "sum": total_up + total_down
        }
    }

@router.get("/dashboard/traffic-chart")
def traffic_chart(range: str = "day", current_admin: dict = Depends(get_current_admin)):
    return {
        "range": range,
        "labels": ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00"],
        "up": [120000, 340000, 560000, 890000, 450000, 670000],
        "down": [450000, 890000, 1200000, 2300000, 1500000, 1900000]
    }

# --- Inbound Endpoints ---
@router.get("/inbounds")
def get_inbounds(db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    inbounds = db.query(Inbound).all()
    result = []
    for ib in inbounds:
        ib_dict = {
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
            "total_traffic_limit": ib.total_traffic_limit,
            "expire_at": ib.expire_at,
            "created_at": ib.created_at,
            "clients_count": len(ib.clients)
        }
        result.append(ib_dict)
    return result

@router.post("/inbounds")
def create_inbound(req: InboundCreate, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    existing = db.query(Inbound).filter(Inbound.port == req.port).first()
    if existing:
        raise HTTPException(status_code=400, detail="این پورت قبلاً استفاده شده است")

    ib = Inbound(
        remark=req.remark,
        protocol=req.protocol,
        port=req.port,
        listen=req.listen or "0.0.0.0",
        network=req.network or "tcp",
        security=req.security or "none",
        stream_settings=req.stream_settings or "{}",
        sniffing=req.sniffing or "{}",
        total_traffic_limit=req.total_traffic_limit,
        expire_at=req.expire_at,
        enabled=True
    )
    db.add(ib)
    db.commit()
    db.refresh(ib)

    trigger_xray_reload(db)
    return {"status": "success", "id": ib.id}

@router.put("/inbounds/{id}")
def update_inbound(id: int, req: InboundCreate, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    ib = db.query(Inbound).filter(Inbound.id == id).first()
    if not ib:
        raise HTTPException(status_code=404, detail="اینباند یافت نشد")

    ib.remark = req.remark
    ib.protocol = req.protocol
    ib.port = req.port
    ib.listen = req.listen or ib.listen
    ib.network = req.network or ib.network
    ib.security = req.security or ib.security
    ib.stream_settings = req.stream_settings or ib.stream_settings
    ib.sniffing = req.sniffing or ib.sniffing
    ib.total_traffic_limit = req.total_traffic_limit
    ib.expire_at = req.expire_at

    db.commit()
    trigger_xray_reload(db)
    return {"status": "success"}

@router.delete("/inbounds/{id}")
def delete_inbound(id: int, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    ib = db.query(Inbound).filter(Inbound.id == id).first()
    if not ib:
        raise HTTPException(status_code=404, detail="اینباند یافت نشد")

    db.delete(ib)
    db.commit()
    trigger_xray_reload(db)
    return {"status": "success"}

@router.post("/inbounds/{id}/toggle")
def toggle_inbound(id: int, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    ib = db.query(Inbound).filter(Inbound.id == id).first()
    if not ib:
        raise HTTPException(status_code=404, detail="اینباند یافت نشد")
    ib.enabled = not ib.enabled
    db.commit()
    trigger_xray_reload(db)
    return {"status": "success", "enabled": ib.enabled}

# --- Client Endpoints ---
@router.get("/inbounds/{id}/clients")
def get_inbound_clients(id: int, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    clients = db.query(Client).filter(Client.inbound_id == id).all()
    return clients

@router.post("/inbounds/{id}/clients")
def create_client(id: int, req: ClientCreate, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    ib = db.query(Inbound).filter(Inbound.id == id).first()
    if not ib:
        raise HTTPException(status_code=404, detail="اینباند یافت نشد")

    client_uuid = req.uuid_or_password or str(uuid.uuid4())
    sub_id = str(uuid.uuid4())[:8]

    client = Client(
        inbound_id=id,
        email=req.email,
        uuid_or_password=client_uuid,
        flow=req.flow or "",
        limit_ip=req.limit_ip or 0,
        total_gb=req.total_gb or 0,
        expiry_time=req.expiry_time,
        enable=True,
        sub_id=sub_id
    )
    db.add(client)
    db.commit()
    db.refresh(client)

    trigger_xray_reload(db)
    return {"status": "success", "id": client.id, "uuid": client_uuid, "sub_id": sub_id}

@router.delete("/clients/{id}")
def delete_client(id: int, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    client = db.query(Client).filter(Client.id == id).first()
    if not client:
        raise HTTPException(status_code=404, detail="کلاینت یافت نشد")

    db.delete(client)
    db.commit()
    trigger_xray_reload(db)
    return {"status": "success"}

@router.post("/clients/{id}/reset-traffic")
def reset_client_traffic(id: int, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    client = db.query(Client).filter(Client.id == id).first()
    if not client:
        raise HTTPException(status_code=404, detail="کلاینت یافت نشد")
    client.up = 0
    client.down = 0
    db.commit()
    return {"status": "success"}

@router.get("/clients/{id}/config-link")
def get_client_config_link(id: int, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    client = db.query(Client).filter(Client.id == id).first()
    if not client:
        raise HTTPException(status_code=404, detail="کلاینت یافت نشد")
    ib = client.inbound
    if not ib:
        raise HTTPException(status_code=404, detail="اینباند مربوط به کلاینت یافت نشد")
    
    server_host = get_server_host(db)
    link = build_client_link(client, ib, server_host)
    return {"link": link}

# --- Subscription Endpoint (Public) ---
@router.get("/sub/{sub_id}")
def public_subscription(sub_id: str, db: Session = Depends(get_db)):
    client = db.query(Client).filter(Client.sub_id == sub_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    ib = client.inbound
    if not ib:
        raise HTTPException(status_code=404, detail="Inbound not found")

    server_host = get_server_host(db)
    link = build_client_link(client, ib, server_host)
    encoded = base64.b64encode(link.encode()).decode()
    return encoded

# --- Nodes Endpoints ---
@router.get("/nodes")
def get_nodes(db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    return db.query(Node).all()

@router.post("/nodes")
def create_node(req: NodeCreate, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    node = Node(name=req.name, api_address=req.api_address, api_token=req.api_token, status="online")
    db.add(node)
    db.commit()
    db.refresh(node)
    return {"status": "success", "id": node.id}

# --- Settings Endpoints ---
@router.get("/settings")
def get_settings(db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    settings = db.query(Setting).all()
    return {s.key: s.value for s in settings}

@router.put("/settings")
def update_settings(req: SettingsUpdate, db: Session = Depends(get_db), current_admin: dict = Depends(get_current_admin)):
    for k, v in req.settings.items():
        setting = db.query(Setting).filter(Setting.key == k).first()
        if setting:
            setting.value = str(v)
        else:
            db.add(Setting(key=k, value=str(v)))
    db.commit()
    return {"status": "success"}

# --- Helper to trigger Xray config reload ---
def trigger_xray_reload(db: Session):
    inbounds = db.query(Inbound).all()
    inbounds_data = []
    for ib in inbounds:
        clients_data = [
            {
                "uuid_or_password": c.uuid_or_password,
                "email": c.email,
                "flow": c.flow,
                "enable": c.enable
            }
            for c in ib.clients
        ]
        inbounds_data.append({
            "id": ib.id,
            "remark": ib.remark,
            "protocol": ib.protocol,
            "port": ib.port,
            "listen": ib.listen,
            "network": ib.network,
            "security": ib.security,
            "stream_settings": ib.stream_settings,
            "sniffing": ib.sniffing,
            "clients": clients_data
        })
    save_and_reload_xray(inbounds_data)
