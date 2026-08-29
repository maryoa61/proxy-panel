"""FastAPI application entry point and small installation-time bootstrap."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api import router as api_router
from .auth import hash_password
from .database import Base, SessionLocal, engine
from .models import Admin, Setting


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("proxy-panel")
PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"


# Tables are intentionally created at import time so uvicorn, tests and the
# systemd service all work without a separate migration command. A future
# deployment can point DATABASE_URL at a migration-managed database.
Base.metadata.create_all(bind=engine)


def _seed_defaults() -> None:
    db = SessionLocal()
    try:
        username = os.getenv("ADMIN_USERNAME", "admin").strip() or "admin"
        password = os.getenv("ADMIN_PASSWORD", "admin123")
        admin = db.query(Admin).filter(Admin.username == username).first()
        if not admin:
            db.add(
                Admin(
                    username=username,
                    password_hash=hash_password(password),
                    is_2fa_enabled=False,
                )
            )
            logger.info("Created initial administrator account: %s", username)

        defaults = {
            "server_domain": "",
            "server_ip": "",
            "server_host": "",
            "panel_name": "Xray Control",
            "subscription_base_url": "",
            "xray_log_level": "warning",
            "xray_config_path": os.getenv("XRAY_CONFIG_PATH", ""),
            "timezone": "UTC",
        }
        for key, value in defaults.items():
            if db.query(Setting).filter(Setting.key == key).first() is None:
                db.add(Setting(key=key, value=str(value)))
        db.commit()
        # Apply persisted generator settings on boot. The API updates these
        # environment values as well, so both restarts and live edits behave
        # consistently.
        log_level = db.query(Setting).filter(Setting.key == "xray_log_level").first()
        config_path = db.query(Setting).filter(Setting.key == "xray_config_path").first()
        if log_level and log_level.value:
            os.environ.setdefault("XRAY_LOG_LEVEL", log_level.value)
        if config_path and config_path.value:
            os.environ.setdefault("XRAY_CONFIG_PATH", config_path.value)
    finally:
        db.close()


_seed_defaults()

app = FastAPI(
    title="Xray-core Management Panel",
    description="پنل مدیریت ماژولار Xray-core با API امن و رابط فارسی",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)


def _cors_origins() -> list[str]:
    raw = os.getenv("CORS_ORIGINS", "*")
    return [origin.strip() for origin in raw.split(",") if origin.strip()] or ["*"]


origins = _cors_origins()
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=(origins != ["*"]),
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-Request-ID"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


app.include_router(api_router)

if FRONTEND_DIST.is_dir():
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")


@app.get("/health", tags=["system"])
def health():
    return {"status": "ok", "service": "xray-panel", "version": app.version}


@app.get("/api/health", tags=["system"])
def api_health():
    return {"status": "ok", "service": "xray-panel", "version": app.version}


@app.get("/", include_in_schema=False)
def serve_spa():
    index_path = FRONTEND_DIST / "index.html"
    if index_path.is_file():
        return FileResponse(str(index_path))
    return {"name": "Xray-core Management Panel API", "status": "running", "docs": "/docs"}


@app.get("/{full_path:path}", include_in_schema=False)
def serve_spa_path(full_path: str):
    # API routes that were not found should remain JSON-ish instead of
    # returning the HTML app, which makes curl and integration tests clearer.
    if full_path.startswith("api/"):
        return {"detail": "Not Found"}
    requested = FRONTEND_DIST / full_path
    if requested.is_file() and FRONTEND_DIST in requested.parents:
        return FileResponse(str(requested))
    index_path = FRONTEND_DIST / "index.html"
    if index_path.is_file():
        return FileResponse(str(index_path))
    return {"detail": "Not Found"}
