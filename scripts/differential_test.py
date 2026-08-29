#!/usr/bin/env python3
"""End-to-end and differential API test for a running panel.

Only Python's standard library is used so the script can run before optional
client tooling is installed. Run with:

    PANEL_URL=http://127.0.0.1:8000 ./scripts/test_api.sh
"""

from __future__ import annotations

import base64
import json
import os
import random
import sys
import urllib.error
import urllib.request
import uuid
from typing import Any, Dict, Optional


BASE_URL = (sys.argv[1] if len(sys.argv) > 1 else os.getenv("PANEL_URL", "http://127.0.0.1:8000")).rstrip("/")
API = BASE_URL + "/api/v1"
USERNAME = os.getenv("ADMIN_USERNAME", "admin")
PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")


def call(path: str, method: str = "GET", body: Optional[Dict[str, Any]] = None, token: str = "") -> tuple[int, Any, Dict[str, str]]:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read()
            content_type = response.headers.get("content-type", "")
            try:
                value = json.loads(raw.decode()) if "json" in content_type or raw.startswith(b"{") or raw.startswith(b"[") else raw.decode()
            except (UnicodeDecodeError, json.JSONDecodeError):
                value = raw
            return response.status, value, dict(response.headers)
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            value = json.loads(raw.decode())
        except Exception:
            value = raw.decode(errors="replace")
        return error.code, value, dict(error.headers)


def ok(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"  ✓ {message}")


def expect(path: str, method: str = "GET", body: Optional[Dict[str, Any]] = None, token: str = "", status: int = 200):
    code, value, headers = call(path, method, body, token)
    ok(code == status, f"{method} {path} → {code}")
    return value, headers


def main() -> int:
    suffix = str(random.randint(20000, 59000))
    ports = [random.randint(20000, 59000) for _ in range(4)]
    while len(set(ports)) != 4 or 10085 in ports:
        ports = [random.randint(20000, 59000) for _ in range(4)]
    stamp = uuid.uuid4().hex[:8]
    ids = []
    client_ids = []
    print(f"\nXray Control differential test: {BASE_URL}")

    # A public health probe and a private-route rejection prove both sides of
    # the middleware boundary.
    health_req = urllib.request.Request(BASE_URL + "/health", method="GET")
    with urllib.request.urlopen(health_req, timeout=10) as response:
        ok(response.status == 200, "GET /health → 200")
    code, _, _ = call("/dashboard/overview")
    ok(code == 401, "private dashboard rejects missing JWT")

    login, _ = expect("/auth/login", "POST", {"username": USERNAME, "password": PASSWORD})
    token = login.get("access_token", "") if isinstance(login, dict) else ""
    ok(bool(token), "login returns a JWT access token")
    private = lambda path, method="GET", body=None, status=200: expect(path, method, body, token, status)

    private("/auth/me")
    private("/settings", "PUT", {"settings": {"server_domain": "", "server_ip": "127.0.0.1"}})
    settings, _ = private("/settings")
    ok(settings.get("_resolved_host") == "127.0.0.1", "empty domain falls back to the configured IP")

    inbound_payloads = [
        {
            "remark": f"Diff VLESS Reality {suffix}",
            "protocol": "vless",
            "port": ports[0],
            "network": "tcp",
            "security": "reality",
            "stream_settings": {"dest": "www.cloudflare.com:443", "serverNames": ["www.cloudflare.com"], "privateKey": "test-private-key", "shortIds": ["1234"], "publicKey": "test-public-key"},
        },
        {
            "remark": f"Diff VMess WS {suffix}",
            "protocol": "vmess",
            "port": ports[1],
            "network": "ws",
            "security": "tls",
            "stream_settings": {"path": "/edge", "headers": {"Host": "cdn.example.com"}, "serverName": "cdn.example.com"},
        },
        {
            "remark": f"Diff Trojan gRPC {suffix}",
            "protocol": "trojan",
            "port": ports[2],
            "network": "grpc",
            "security": "tls",
            "stream_settings": {"serviceName": "secure-grpc", "serverName": "node.example.com"},
        },
        {
            "remark": f"Diff Shadowsocks HTTP2 {suffix}",
            "protocol": "shadowsocks",
            "port": ports[3],
            "network": "http2",
            "security": "none",
            "stream_settings": {"path": "/ss", "host": ["cdn.example.com"], "method": "aes-128-gcm"},
        },
    ]

    for index, payload in enumerate(inbound_payloads):
        result, _ = private("/inbounds", "POST", payload)
        inbound_id = result.get("id") if isinstance(result, dict) else None
        ok(isinstance(inbound_id, int), f"created {payload['protocol']} inbound")
        ids.append(inbound_id)
        client, _ = private(
            f"/inbounds/{inbound_id}/clients",
            "POST",
            {
                "inbound_id": inbound_id,
                "email": f"diff-{payload['protocol']}-{stamp}@proxy.local",
                "total_gb": 5,
                "flow": "xtls-rprx-vision" if payload["protocol"] == "vless" else "",
            },
        )
        client_id = client.get("id") if isinstance(client, dict) else None
        ok(isinstance(client_id, int) and bool(client.get("sub_id")), f"created {payload['protocol']} client")
        client_ids.append((client_id, client.get("sub_id")))

    config, _ = private("/xray/config")
    generated = [item for item in config.get("inbounds", []) if item.get("tag") != "api"]
    ok(len(generated) >= 4, "config contains all enabled inbounds")
    for payload in inbound_payloads:
        matches = [item for item in generated if item.get("protocol") == payload["protocol"]]
        ok(matches, f"config emits {payload['protocol']} protocol")
    reality = next(item for item in generated if item["protocol"] == "vless")
    ok(reality["streamSettings"].get("realitySettings", {}).get("privateKey") == "test-private-key", "Reality settings are preserved")
    ws = next(item for item in generated if item["protocol"] == "vmess")
    ok(ws["streamSettings"].get("wsSettings", {}).get("path") == "/edge", "WebSocket transport settings are preserved")

    first_id, first_sub = client_ids[0]
    before, _ = private(f"/clients/{first_id}/config-link")
    ok("127.0.0.1" in before.get("link", ""), "link initially uses fallback IP")
    new_domain = f"edge-{stamp}.example.com"
    private("/settings", "PUT", {"settings": {"server_domain": new_domain}})
    after, _ = private(f"/clients/{first_id}/config-link")
    ok(new_domain in after.get("link", ""), "link changes immediately after Settings domain update")

    encoded, headers = expect(f"/sub/{first_sub}")
    decoded = base64.b64decode(str(encoded).strip().strip('"')).decode()
    ok(new_domain in decoded, "public subscription uses the new dynamic domain")
    ok(headers.get("content-type", "").startswith("text/plain"), "subscription is returned as plain text")

    private(f"/clients/{first_id}", "PUT", {"flow": "", "total_gb": 7})
    private(f"/clients/{first_id}/toggle", "POST")
    private(f"/clients/{first_id}/reset-traffic", "POST")
    private(f"/inbounds/{ids[0]}/toggle", "POST")
    private("/dashboard/overview")
    private("/dashboard/traffic-chart?range=week")
    private("/xray/config/download")
    private("/xray/status")

    # Clean up test data so repeated runs do not pollute a production panel.
    for inbound_id in ids:
        private(f"/inbounds/{inbound_id}", "DELETE")
    print("\n✨ All differential API checks passed and test records were removed.\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, urllib.error.URLError) as error:
        print(f"\n✗ Differential test failed: {error}\n", file=sys.stderr)
        raise SystemExit(1)
