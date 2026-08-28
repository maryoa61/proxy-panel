from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
import uuid
from .database import engine, Base, get_db
from . import models, xray_api

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Proxy Panel")

@app.post("/users/add")
def create_user(username: str, traffic_limit: int = 10737418240, db: Session = Depends(get_db)):
    # ۱. تولید UUID یکتا
    user_uuid = str(uuid.uuid4())
    
    # ۲. اعمال کاربر روی هسته Xray
    success = xray_api.add_user_to_xray(email=username, uuid_str=user_uuid)
    if not success:
        raise HTTPException(status_code=500, detail="خطا در ارتباط با هسته Xray")
    
    # ۳. ذخیره در دیتابیس
    db_user = models.User(
        username=username,
        uuid=user_uuid,
        traffic_limit=traffic_limit
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # ۴. ساخت لینک کانکشن (فرمت استاندارد VLESS Reality)
    # آدرس سرور را جایگزین آدرس زیر کن
    server_address = "YOUR_SERVER_IP_OR_DOMAIN"
    vless_link = f"vless://{user_uuid}@{server_address}:443?encryption=none&security=reality&sni=yahoo.com&fp=chrome&type=tcp&flow=xtls-rprx-vision# {username}"

    return {
        "status": "success",
        "username": username,
        "uuid": user_uuid,
        "link": vless_link
    }

@app.get("/users")
def get_users(db: Session = Depends(get_db)):
    return db.query(models.User).all()
