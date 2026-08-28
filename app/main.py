from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from .database import engine, Base, get_db
from . import models

# ساخت خودکار جدول‌ها در دیتابیس SQLite
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Simple Proxy Panel")

@app.get("/")
def read_root():
    return {"message": "Proxy Panel is running!", "status": "active"}

@app.get("/users")
def get_users(db: Session = Depends(get_db)):
    users = db.query(models.User).all()
    return {"users": users}
