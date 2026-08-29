from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

from .database import engine, Base, SessionLocal
from .models import Admin, Setting
from .auth import hash_password
from .api import router as api_router

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Xray-core Management Panel", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Seed default admin if not exists
def seed_admin():
    db = SessionLocal()
    try:
        admin = db.query(Admin).filter(Admin.username == "admin").first()
        if not admin:
            hashed = hash_password("admin123")
            default_admin = Admin(username="admin", password_hash=hashed, is_2fa_enabled=False)
            db.add(default_admin)
            db.commit()
            print("Default admin created: username=admin, password=admin123")
    finally:
        db.close()

seed_admin()

# Include API router
app.include_router(api_router)

# Mount Frontend static files if frontend build exists
frontend_dist = os.path.abspath("frontend/dist")
assets_dir = os.path.join(frontend_dist, "assets")
if os.path.exists(assets_dir):
    app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

@app.get("/")
def serve_spa():
    index_path = os.path.join(frontend_dist, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {
        "name": "Xray-core Management Panel API",
        "status": "running",
        "docs": "/docs"
    }

@app.get("/{full_path:path}")
def serve_spa_path(full_path: str):
    if full_path.startswith("api/"):
        return {"error": "Not Found"}
    file_path = os.path.join(frontend_dist, full_path)
    if os.path.exists(file_path) and os.path.isfile(file_path):
        return FileResponse(file_path)
    index_path = os.path.join(frontend_dist, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"error": "Not Found"}
