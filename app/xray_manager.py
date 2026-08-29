"""Xray configuration generation and safe reload helpers.

The manager is intentionally pure at its core: ``generate_xray_config`` accepts
plain dictionaries, which makes it useful from the API, the CLI and tests.  The
API layer is responsible for reading SQLAlchemy objects and this module is
responsible for emitting the Xray JSON shape.
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import shutil
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

try:  # psutil is optional for a small, dependency-light development install.
    import psutil
except ImportError:  # pragma: no cover - exercised only without the optional dep
    psutil = None


logger = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOCAL_CONFIG_PATH = str(PROJECT_ROOT / "core" / "config.json")
CONFIG_PATH = os.getenv("XRAY_CONFIG_PATH", LOCAL_CONFIG_PATH)
_PROCESS_START_TIME = time.time()

SUPPORTED_PROTOCOLS = {"vmess", "vless", "trojan", "shadowsocks"}
SUPPORTED_NETWORKS = {
    "tcp",
    "raw",
    "ws",
    "websocket",
    "grpc",
    "gRPC",
    "http",
    "http2",
    "kcp",
    "mkcp",
    "quic",
    "httpupgrade",
    "xhttp",
}


def _parse_json(value: Any, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Parse a JSON object supplied either as a dict or a legacy JSON string."""

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


def _pick(source: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in source and source[key] not in (None, ""):
            return source[key]
    return default


def _int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _normalise_network(network: Any) -> str:
    value = str(network or "tcp").strip()
    aliases = {
        "raw": "tcp",
        "websocket": "ws",
        "gRPC": "grpc",
        "grpc": "grpc",
        "http2": "http",
        "mkcp": "kcp",
    }
    return aliases.get(value, value.lower())


def _active_client(client: Mapping[str, Any]) -> bool:
    if not _bool(client.get("enable"), True):
        return False
    expiry = client.get("expiry_time") or client.get("expiryTime")
    if not expiry:
        return True
    if isinstance(expiry, str):
        try:
            expiry = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
        except ValueError:
            return True
    try:
        now = datetime.now(expiry.tzinfo) if getattr(expiry, "tzinfo", None) else datetime.utcnow()
        return expiry > now
    except TypeError:
        return True


def _protocol_settings(protocol: str, clients: Iterable[Mapping[str, Any]], stream: Mapping[str, Any]) -> Dict[str, Any]:
    active = [c for c in clients if _active_client(c)]
    if protocol == "vless":
        return {
            "clients": [
                {
                    "id": c.get("uuid_or_password") or c.get("uuid") or "",
                    **({"flow": c.get("flow")} if c.get("flow") else {}),
                    "email": c.get("email", ""),
                }
                for c in active
            ],
            "decryption": "none",
        }
    if protocol == "vmess":
        return {
            "clients": [
                {
                    "id": c.get("uuid_or_password") or c.get("uuid") or "",
                    "alterId": _int(c.get("alterId", c.get("alter_id", 0)), 0),
                    "security": c.get("security", "auto"),
                    "email": c.get("email", ""),
                }
                for c in active
            ]
        }
    if protocol == "trojan":
        return {
            "clients": [
                {
                    "password": c.get("uuid_or_password") or c.get("password") or "",
                    "email": c.get("email", ""),
                    **({"flow": c.get("flow")} if c.get("flow") else {}),
                }
                for c in active
            ],
            "fallbacks": stream.get("fallbacks", []),
        }
    if protocol == "shadowsocks":
        method = str(_pick(stream, "method", default="aes-128-gcm"))
        primary_password = _pick(stream, "password", default=(active[0].get("uuid_or_password", "") if active else ""))
        return {
            "method": method,
            "password": primary_password,
            "network": _pick(stream, "network", default="tcp"),
            "clients": [
                {
                    "password": c.get("uuid_or_password") or c.get("password") or "",
                    "email": c.get("email", ""),
                }
                for c in active
            ],
        }
    return {}


def _stream_settings(network: str, security: str, stream: Mapping[str, Any]) -> Dict[str, Any]:
    """Build transport/security settings while accepting snake/camel case input."""

    network_name = _normalise_network(network)
    result: Dict[str, Any] = {
        "network": network_name,
        "security": security or "none",
    }

    # Allow callers to send nested Xray objects, but let the panel-friendly flat
    # fields below fill in sensible defaults.
    nested = {
        "tcp": _pick(stream, "tcpSettings", "tcp_settings", default={}),
        "ws": _pick(stream, "wsSettings", "ws_settings", default={}),
        "grpc": _pick(stream, "grpcSettings", "grpc_settings", default={}),
        "http": _pick(stream, "httpSettings", "http_settings", default={}),
        "kcp": _pick(stream, "kcpSettings", "kcp_settings", default={}),
        "quic": _pick(stream, "quicSettings", "quic_settings", default={}),
        "httpupgrade": _pick(stream, "httpupgradeSettings", "httpupgrade_settings", default={}),
        "xhttp": _pick(stream, "xhttpSettings", "xhttp_settings", default={}),
    }
    for key, value in list(nested.items()):
        nested[key] = dict(value) if isinstance(value, Mapping) else {}

    if network_name == "tcp":
        tcp = nested["tcp"]
        header = dict(tcp.get("header", {})) if isinstance(tcp.get("header"), Mapping) else {}
        header.setdefault("type", _pick(stream, "headerType", "header_type", default="none"))
        tcp["header"] = header
        result["tcpSettings"] = tcp
    elif network_name == "ws":
        ws = nested["ws"]
        ws.setdefault("path", _pick(stream, "path", default="/ray"))
        ws.setdefault("headers", _pick(stream, "headers", default={}) or {})
        result["wsSettings"] = ws
    elif network_name == "grpc":
        grpc = nested["grpc"]
        grpc.setdefault("serviceName", _pick(stream, "serviceName", "service_name", default="grpc"))
        grpc.setdefault("multiMode", _bool(_pick(stream, "multiMode", "multi_mode", default=False)))
        result["grpcSettings"] = grpc
    elif network_name == "http":
        http = nested["http"]
        hosts = _pick(stream, "host", "hosts", default=[])
        if isinstance(hosts, str):
            hosts = [hosts] if hosts else []
        http.setdefault("host", hosts or [])
        http.setdefault("path", _pick(stream, "path", default="/"))
        result["httpSettings"] = http
    elif network_name == "kcp":
        kcp = nested["kcp"]
        kcp.setdefault("mtu", _int(_pick(stream, "mtu", default=1350), 1350))
        kcp.setdefault("tti", _int(_pick(stream, "tti", default=50), 50))
        kcp.setdefault("uplinkCapacity", _int(_pick(stream, "uplinkCapacity", "uplink_capacity", default=5), 5))
        kcp.setdefault("downlinkCapacity", _int(_pick(stream, "downlinkCapacity", "downlink_capacity", default=20), 20))
        kcp.setdefault("congestion", _bool(_pick(stream, "congestion", default=False)))
        kcp.setdefault("header", {"type": _pick(stream, "headerType", "header_type", default="none")})
        result["kcpSettings"] = kcp
    elif network_name == "quic":
        quic = nested["quic"]
        quic.setdefault("security", _pick(stream, "quicSecurity", "quic_security", default="none"))
        quic.setdefault("key", _pick(stream, "quicKey", "quic_key", default=""))
        quic.setdefault("header", {"type": _pick(stream, "headerType", "header_type", default="none")})
        result["quicSettings"] = quic
    elif network_name == "httpupgrade":
        upgrade = nested["httpupgrade"]
        upgrade.setdefault("path", _pick(stream, "path", default="/"))
        upgrade.setdefault("host", _pick(stream, "host", default=""))
        result["httpupgradeSettings"] = upgrade
    elif network_name == "xhttp":
        xhttp = nested["xhttp"]
        xhttp.setdefault("path", _pick(stream, "path", default="/"))
        xhttp.setdefault("host", _pick(stream, "host", default=""))
        xhttp.setdefault("mode", _pick(stream, "mode", default="auto"))
        result["xhttpSettings"] = xhttp

    if security == "reality":
        reality = _pick(stream, "realitySettings", "reality_settings", default={})
        reality = dict(reality) if isinstance(reality, Mapping) else {}
        reality.setdefault("show", _bool(_pick(stream, "show", default=False)))
        reality.setdefault("xver", _int(_pick(stream, "xver", default=0), 0))
        reality.setdefault("dest", _pick(stream, "dest", default="www.cloudflare.com:443"))
        reality.setdefault(
            "serverNames",
            _pick(stream, "serverNames", "server_names", default=["www.cloudflare.com"]),
        )
        reality.setdefault("privateKey", _pick(stream, "privateKey", "private_key", default=""))
        reality.setdefault("shortIds", _pick(stream, "shortIds", "short_ids", default=[""]))
        # Optional Reality tuning values are only emitted when configured.
        for output_key, *input_keys in (
            ("minClientVer", "minClientVer", "min_client_ver"),
            ("maxClientVer", "maxClientVer", "max_client_ver"),
            ("maxTimeDiff", "maxTimeDiff", "max_time_diff"),
        ):
            value = _pick(stream, *input_keys)
            if value not in (None, ""):
                reality[output_key] = _int(value, 0)
        result["realitySettings"] = reality
    elif security == "tls":
        tls = _pick(stream, "tlsSettings", "tls_settings", default={})
        tls = dict(tls) if isinstance(tls, Mapping) else {}
        tls.setdefault("serverName", _pick(stream, "serverName", "server_name", default=""))
        tls.setdefault("alpn", _pick(stream, "alpn", default=["h2", "http/1.1"]))
        certificates = _pick(stream, "certificates", default=None)
        if certificates is not None:
            tls["certificates"] = certificates
        elif not tls.get("certificates"):
            tls["certificates"] = [
                {
                    "certificateFile": _pick(stream, "certificateFile", "certificate_file", default=""),
                    "keyFile": _pick(stream, "keyFile", "key_file", default=""),
                }
            ]
        result["tlsSettings"] = tls

    return result


def _inbound_entry(inbound: Mapping[str, Any]) -> Dict[str, Any]:
    protocol = str(inbound.get("protocol", "vless")).lower()
    if protocol not in SUPPORTED_PROTOCOLS:
        raise ValueError(f"Unsupported Xray protocol: {protocol}")
    stream = _parse_json(inbound.get("stream_settings"), {})
    network = str(inbound.get("network", "tcp"))
    security = str(inbound.get("security", "none"))
    clients = inbound.get("clients") or []

    entry: Dict[str, Any] = {
        "listen": inbound.get("listen") or "0.0.0.0",
        "port": _int(inbound.get("port"), 443),
        "protocol": protocol,
        "tag": inbound.get("tag") or f"inbound-{inbound.get('id', 1)}",
        "settings": _protocol_settings(protocol, clients, stream),
        "streamSettings": _stream_settings(network, security, stream),
    }
    sniffing = _parse_json(inbound.get("sniffing"), {})
    if not sniffing:
        sniffing = {
            "enabled": True,
            "destOverride": ["http", "tls", "quic"],
        }
    else:
        sniffing.setdefault("enabled", True)
        sniffing.setdefault("destOverride", ["http", "tls", "quic"])
    entry["sniffing"] = sniffing
    return entry


def generate_xray_config(inbounds_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate a complete Xray-core JSON document from panel records.

    ``inbounds_data`` is intentionally a list of dictionaries for backwards
    compatibility with the first panel version and for straightforward tests.
    Disabled inbounds are omitted while the local Stats API inbound remains
    present so Xray statistics can still be collected.
    """

    config: Dict[str, Any] = {
        "log": {
            "loglevel": os.getenv("XRAY_LOG_LEVEL", "warning"),
            "access": os.getenv("XRAY_ACCESS_LOG", ""),
            "error": os.getenv("XRAY_ERROR_LOG", ""),
        },
        "api": {
            "tag": "api",
            "services": ["HandlerService", "StatsService", "LoggerService"],
        },
        "stats": {},
        "policy": {
            "levels": {
                "0": {
                    "handshake": 4,
                    "connIdle": 300,
                    "statsUserUplink": True,
                    "statsUserDownlink": True,
                }
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            },
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 10085,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
                "tag": "api",
            }
        ],
        "outbounds": [
            # The API routing rule points at this dedicated freedom outbound;
            # keeping it separate makes the generated document valid on Xray
            # versions that require every outboundTag to exist.
            {"protocol": "freedom", "tag": "api"},
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "blocked"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
            ],
        },
    }

    for inbound in inbounds_data:
        if not _bool(inbound.get("enabled"), True):
            continue
        entry = _inbound_entry(inbound)
        # Xray has no concept of an expired inbound, so the panel prevents it
        # from entering the generated document.
        expire_at = inbound.get("expire_at")
        if expire_at:
            if isinstance(expire_at, str):
                try:
                    expire_at = datetime.fromisoformat(expire_at.replace("Z", "+00:00"))
                except ValueError:
                    expire_at = None
            if expire_at:
                now = datetime.now(expire_at.tzinfo) if getattr(expire_at, "tzinfo", None) else datetime.utcnow()
                if expire_at <= now:
                    continue
        config["inbounds"].append(entry)

    return config


def _configured_path() -> Path:
    path = Path(os.getenv("XRAY_CONFIG_PATH", CONFIG_PATH))
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path


def _write_json_atomic(path: Path, config: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # A small backup makes an accidental bad edit recoverable without making
    # reload dependent on the backup succeeding.
    if path.exists():
        backup = path.with_suffix(path.suffix + ".bak")
        try:
            shutil.copy2(path, backup)
        except OSError:
            logger.warning("Could not create Xray config backup at %s", backup)

    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _reload_xray() -> bool:
    command = os.getenv("XRAY_RELOAD_COMMAND", "").strip()
    if not command:
        # The panel can run without Xray (for example while preparing a
        # container). The systemd installer opts in explicitly through
        # XRAY_RELOAD_COMMAND, so a generated config is still a successful
        # operation in development and Docker.
        return True
    try:
        completed = subprocess.run(
            shlex.split(command),
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if completed.returncode != 0:
            logger.warning("Xray reload failed: %s", (completed.stderr or completed.stdout).strip())
            return False
        return True
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("Could not reload Xray: %s", exc)
        return False


def save_and_reload_xray(inbounds_data: List[Dict[str, Any]]) -> bool:
    """Write a valid JSON document atomically and request an Xray reload.

    A reload failure does not erase the generated configuration. The return
    value is true only when both writing and the configured reload command
    succeed; API mutations remain successful because the database is the source
    of truth and the UI reports the reload result separately.
    """

    try:
        config = generate_xray_config(inbounds_data)
        local_path = Path(LOCAL_CONFIG_PATH)
        _write_json_atomic(local_path, config)
        target_path = _configured_path()
        if target_path.resolve() != local_path.resolve():
            try:
                _write_json_atomic(target_path, config)
            except OSError as exc:
                logger.warning("Could not write configured Xray path %s: %s", target_path, exc)
        reload_ok = _reload_xray()
        logger.info("Xray configuration generated at %s", target_path)
        return reload_ok
    except Exception:
        logger.exception("Failed to generate Xray configuration")
        return False


def check_xray_process() -> bool:
    """Return whether an Xray process/service is visible on this machine."""

    if psutil is not None:
        try:
            for proc in psutil.process_iter(["name", "cmdline"]):
                name = (proc.info.get("name") or "").lower()
                cmdline = proc.info.get("cmdline") or []
                executable_names = {"xray", "xray-core"}
                if name in executable_names or any(
                    Path(str(item)).name.lower() in executable_names for item in cmdline
                ):
                    return True
        except Exception:
            pass
    if shutil.which("systemctl"):
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "xray"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if result.returncode == 0 and result.stdout.strip() == "active":
                return True
        except (OSError, subprocess.SubprocessError):
            pass
    return False


def get_xray_stats(db_active_clients_count: int = 0) -> Dict[str, Any]:
    """Collect lightweight host metrics used by the dashboard."""

    cpu_percent, memory_percent, disk_percent = 0.0, 0.0, 0.0
    if psutil is not None:
        try:
            cpu_percent = float(psutil.cpu_percent(interval=0.05))
            memory_percent = float(psutil.virtual_memory().percent)
            disk_percent = float(psutil.disk_usage("/").percent)
        except Exception:
            pass

    uptime_seconds = int(time.time() - _PROCESS_START_TIME)
    if psutil is not None:
        try:
            uptime_seconds = max(0, int(time.time() - psutil.boot_time()))
        except Exception:
            pass

    process_online = check_xray_process()
    configured = Path(LOCAL_CONFIG_PATH).exists() or _configured_path().exists()
    # ``online`` is retained for compatibility with the original API. The
    # explicit configured/process flags let the UI distinguish dev mode from a
    # real Xray process.
    status = "online" if (process_online or configured) else "offline"
    return {
        "status": status,
        "process_online": process_online,
        "configured": configured,
        "cpu": round(cpu_percent, 1),
        "memory": round(memory_percent, 1),
        "disk": round(disk_percent, 1),
        "uptime": uptime_seconds,
        "online_clients": int(db_active_clients_count),
    }
