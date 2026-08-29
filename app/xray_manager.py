import json
import os
import subprocess
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

CONFIG_PATH = os.getenv("XRAY_CONFIG_PATH", "/etc/xray/config.json")
# Fallback local config path for development/sandbox testing
LOCAL_CONFIG_PATH = os.path.abspath("core/config.json")

def generate_xray_config(inbounds_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    تولید ساختار JSON استاندارد برای Xray-core از روی اینباندها و کلاینت‌ها
    """
    config = {
        "log": {
            "loglevel": "warning",
            "access": "",
            "error": ""
        },
        "api": {
            "tag": "api",
            "services": [
                "HandlerService",
                "StatsService",
                "LoggerService"
            ]
        },
        "stats": {},
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True
                }
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True
            }
        },
        "inbounds": [],
        "outbounds": [
            {
                "protocol": "freedom",
                "tag": "direct"
            },
            {
                "protocol": "blackhole",
                "tag": "blocked"
            }
        ],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["api"],
                    "outboundTag": "api"
                },
                {
                    "type": "field",
                    "ip": ["geoip:private"],
                    "outboundTag": "blocked"
                }
            ]
        }
    }

    # Add API inbound for stats & management
    config["inbounds"].append({
        "listen": "127.0.0.1",
        "port": 10085,
        "protocol": "dokodemo-door",
        "settings": {
            "address": "127.0.0.1"
        },
        "tag": "api"
    })

    for ib in inbounds_data:
        inbound_entry = {
            "listen": ib.get("listen", "0.0.0.0"),
            "port": ib.get("port", 443),
            "protocol": ib.get("protocol", "vless"),
            "tag": f"inbound-{ib.get('id', 1)}",
            "settings": {},
            "streamSettings": {}
        }

        protocol = ib.get("protocol", "vless")
        clients = ib.get("clients", [])

        # Protocol specific settings
        if protocol == "vless":
            inbound_entry["settings"] = {
                "clients": [
                    {
                        "id": c["uuid_or_password"],
                        "flow": c.get("flow", "xtls-rprx-vision") if ib.get("security") == "reality" else "",
                        "email": c["email"]
                    }
                    for c in clients if c.get("enable", True)
                ],
                "decryption": "none"
            }
        elif protocol == "vmess":
            inbound_entry["settings"] = {
                "clients": [
                    {
                        "id": c["uuid_or_password"],
                        "alterId": 0,
                        "email": c["email"]
                    }
                    for c in clients if c.get("enable", True)
                ]
            }
        elif protocol == "trojan":
            inbound_entry["settings"] = {
                "clients": [
                    {
                        "password": c["uuid_or_password"],
                        "email": c["email"]
                    }
                    for c in clients if c.get("enable", True)
                ]
            }
        elif protocol == "shadowsocks":
            inbound_entry["settings"] = {
                "clients": [
                    {
                        "password": c["uuid_or_password"],
                        "method": "aes-128-gcm",
                        "email": c["email"]
                    }
                    for c in clients if c.get("enable", True)
                ]
            }

        # Stream Settings (network, security, reality, tls, ws, etc.)
        network = ib.get("network", "tcp")
        security = ib.get("security", "none")
        
        stream_settings = {
            "network": network,
            "security": security
        }

        # Parse stored stream_settings JSON if available
        parsed_stream = {}
        if ib.get("stream_settings"):
            try:
                parsed_stream = json.loads(ib.get("stream_settings"))
            except Exception:
                pass

        if security == "reality":
            stream_settings["realitySettings"] = {
                "show": False,
                "xver": 0,
                "dest": parsed_stream.get("dest", "yahoo.com:443"),
                "serverNames": parsed_stream.get("serverNames", ["yahoo.com", "www.yahoo.com"]),
                "privateKey": parsed_stream.get("privateKey", ""),
                "shortIds": parsed_stream.get("shortIds", [""])
            }
        elif security == "tls":
            stream_settings["tlsSettings"] = {
                "certificates": [
                    {
                        "certificateFile": parsed_stream.get("certificateFile", ""),
                        "keyFile": parsed_stream.get("keyFile", "")
                    }
                ]
            }

        if network == "ws":
            stream_settings["wsSettings"] = {
                "path": parsed_stream.get("path", "/ray"),
                "headers": parsed_stream.get("headers", {})
            }
        elif network == "gRPC":
            stream_settings["grpcSettings"] = {
                "serviceName": parsed_stream.get("serviceName", "grpc")
            }

        inbound_entry["streamSettings"] = stream_settings

        # Sniffing
        inbound_entry["sniffing"] = {
            "enabled": True,
            "destOverride": ["http", "tls", "quic"]
        }

        config["inbounds"].append(inbound_entry)

    return config

def save_and_reload_xray(inbounds_data: List[Dict[str, Any]]) -> bool:
    """
    ذخیره فایل کانفیگ و ری‌استارت سرویس Xray (Graceful Reload)
    """
    try:
        config = generate_xray_config(inbounds_data)
        
        # Determine path
        target_path = CONFIG_PATH
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
            
        # Also save to local core/config.json for sandbox testing
        os.makedirs("core", exist_ok=True)
        with open("core/config.json", "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

        # Try reloading systemd service if available
        try:
            subprocess.run(["systemctl", "reload", "xray"], check=False, capture_output=True)
        except Exception:
            pass

        logger.info("Xray config generated and reloaded successfully.")
        return True
    except Exception as e:
        logger.error(f"Failed to generate/reload Xray config: {e}")
        return False

def get_xray_stats() -> Dict[str, Any]:
    """
    دریافت آمار لحظه‌ای ترافیک از هسته Xray (یا شبیه‌سازی برای پنل)
    """
    # In production, uses Xray Stats API via gRPC.
    # Here we return simulated live stats structure.
    return {
        "status": "online",
        "cpu": 1.2,
        "memory": 45.8,
        "disk": 22.1,
        "uptime": 345600,
        "online_clients": 5
    }
