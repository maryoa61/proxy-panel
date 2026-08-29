# Xray Control Panel

پنل مدیریت ماژولار و فارسی برای **Xray-core** با API امن، تولیدگر پویا و اتمیک `config.json` و رابط کاربری RTL. این پروژه برای مدیریت یک سرور یا آماده‌سازی معماری چندنودی طراحی شده و از پروتکل‌های VMess، VLESS، Trojan و Shadowsocks پشتیبانی می‌کند.

> **هشدار امنیتی:** این پروژه یک نقطه ورود اینترنتی است. قبل از استفاده در محیط واقعی، `JWT_SECRET_KEY`، کلمه عبور مدیر، HTTPS و فایروال را تنظیم کنید. مقدارهای `admin / admin123` فقط برای شروع توسعه هستند.

## امکانات

- **Backend:** Python 3.11، FastAPI، SQLAlchemy 2 و SQLite با session مستقل برای هر درخواست.
- **احراز هویت:** JWT کوتاه‌عمر، bcrypt با cost قابل تنظیم، احراز هویت Bearer و endpoint تغییر کلمه عبور.
- **Xray config generator:** تولید کامل ساختار Xray شامل API/Stats/Policy/Routing و اینباندهای VMess، VLESS، Trojan و Shadowsocks.
- **ترنسپورت‌ها:** TCP/Raw، WebSocket، gRPC، HTTP/2، mKCP، QUIC، HTTP Upgrade و XHTTP.
- **امنیت انتقال:** none، TLS و VLESS + XTLS-Reality با `dest`، `serverNames`، `privateKey` و `shortIds`.
- **مدیریت کلاینت:** تولید خودکار UUID/password، Flow، سهمیه GB، محدودیت IP، انقضا، فعال/خاموش کردن، reset ترافیک و لینک اتصال.
- **Subscription:** مسیر عمومی `/api/v1/sub/{sub_id}` با خروجی Base64 و بدون افشای API یا داده‌های مدیریتی.
- **هاست پویا:** خواندن زنده از جدول `settings` با اولویت دامنه، host، IP، متغیر محیطی، public IP و fallback محلی. تغییر دامنه بدون restart در لینک‌های جدید اعمال می‌شود.
- **داشبورد:** وضعیت هسته، منابع سیستم، مصرف ترافیک، نمودار بازه‌ای و خلاصه اینباندها.
- **رابط کاربری:** Vue 3 + Tailwind CSS CDN، responsive، حالت روشن/تاریک، RTL و متون فارسی.
- **عملیات:** preview و download کانفیگ، reload اختیاری هسته، نودها، audit log و health endpoint.
- **استقرار:** Docker/Compose، سرویس systemd، اسکریپت نصب و تست end-to-end differential.

## ساختار پروژه

```text
.
├── app/
│   ├── api.py             # REST API نسخه‌بندی‌شده و schemaهای ورودی
│   ├── auth.py            # JWT و bcrypt
│   ├── database.py        # engine، SessionLocal و Base
│   ├── main.py            # FastAPI app، seed و SPA fallback
│   ├── models.py          # مدل‌های SQLAlchemy
│   └── xray_manager.py    # تولید JSON، backup اتمیک و reload
├── frontend/
│   ├── index.html         # سورس SPA Vue 3/Tailwind
│   └── dist/index.html    # فایل سرو شده توسط FastAPI
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── scripts/
│   ├── install.sh
│   ├── test_api.sh
│   └── differential_test.py
└── systemd/panel.service
```

## اجرای محلی

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# برای توسعه مقدارهای امن را خودتان تعیین کنید
export JWT_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
export ENABLE_PUBLIC_IP_LOOKUP=0
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

سپس به `http://127.0.0.1:8000` بروید. در اولین اجرای دیتابیس، مدیر اولیه ساخته می‌شود:

```text
username: admin
password: admin123
```

برای تعیین حساب دیگری قبل از اولین اجرا:

```bash
export ADMIN_USERNAME=operator
export ADMIN_PASSWORD='یک-کلمه-عبور-قوی-حداقل-۸-کاراکتری'
```

مستندات تعاملی در `/docs` و `/redoc` و سلامت سرویس در `/health` قرار دارد.

## متغیرهای محیطی

| متغیر | مقدار پیش‌فرض | توضیح |
|---|---|---|
| `DATABASE_URL` | SQLite در ریشه پروژه | برای نصب systemd به `/var/lib/xray-panel/panel.db` تنظیم می‌شود |
| `JWT_SECRET_KEY` | مقدار توسعه‌ای | در production حتماً مقدار تصادفی طولانی قرار دهید |
| `JWT_EXPIRE_MINUTES` | `1440` | عمر access token |
| `BCRYPT_ROUNDS` | `12` | cost هش bcrypt |
| `ADMIN_USERNAME` | `admin` | فقط برای seed اولیه |
| `ADMIN_PASSWORD` | `admin123` | فقط برای seed اولیه؛ بعداً از پنل تغییر دهید |
| `XRAY_CONFIG_PATH` | `core/config.json` | مسیر مقصد کانفیگ Xray |
| `XRAY_RELOAD_COMMAND` | خالی | مثل `systemctl reload xray`؛ خالی بودن مانع تولید JSON نمی‌شود |
| `ENABLE_PUBLIC_IP_LOOKUP` | `1` | برای محیط بسته روی `0` بگذارید |
| `SERVER_HOST` / `SERVER_DOMAIN` | خالی | fallback قبل از public IP |
| `CORS_ORIGINS` | `*` | در محیط واقعی فهرست originهای مجاز را comma-separated کنید |

## Docker Compose

Compose فقط پنل را اجرا می‌کند و کانفیگ تولیدشده را در volume مشترک `xray_config` نگه می‌دارد. علت جدا بودن Xray این است که Reality key، گواهی TLS، پورت‌ها و policy شبکه به محیط استقرار وابسته هستند.

```bash
cp .env.example .env 2>/dev/null || true
# حداقل JWT_SECRET_KEY و ADMIN_PASSWORD را در .env تنظیم کنید
docker compose -f docker/docker-compose.yml up -d --build

docker compose -f docker/docker-compose.yml logs -f panel
```

اگر `.env.example` وجود نداشت، یک `.env` بسازید:

```dotenv
JWT_SECRET_KEY=یک-رشته-تصادفی-طولانی
ADMIN_USERNAME=admin
ADMIN_PASSWORD=یک-کلمه-عبور-قوی
PANEL_PORT=8000
ENABLE_PUBLIC_IP_LOOKUP=0
```

کانفیگ در volume `/etc/xray/config.json` داخل کانتینر پنل نوشته می‌شود. برای اجرای Xray در همان ماشین، می‌توانید volume را به مسیر host bind کنید یا کانتینر Xray خودتان را به همین volume وصل کنید؛ در این حالت `XRAY_RELOAD_COMMAND` را متناسب با runtime تنظیم کنید. اجرای Xray با کانفیگ دارای Reality بدون key واقعی توصیه نمی‌شود.

## نصب روی Linux با systemd

روی Debian/Ubuntu:

```bash
sudo ADMIN_PASSWORD='کلمه-عبور-قوی' bash scripts/install.sh
```

اسکریپت:

1. Python و virtualenv را نصب می‌کند؛
2. پنل را در `/usr/local/panel` و دیتابیس را در `/var/lib/xray-panel` قرار می‌دهد؛
3. یک `JWT_SECRET_KEY` تصادفی می‌سازد؛
4. در صورت نیاز Xray-core را نصب می‌کند؛
5. سرویس `xray-panel.service` را فعال می‌کند.

بدون نصب Xray:

```bash
sudo INSTALL_XRAY=0 bash scripts/install.sh
```

وضعیت سرویس:

```bash
systemctl status xray-panel
journalctl -u xray-panel -f
```

فایل محیطی محرمانه در `/etc/xray-panel/panel.env` ذخیره می‌شود. سرویس روی `0.0.0.0:8000` گوش می‌دهد؛ برای اینترنت عمومی بهتر است آن را پشت Nginx/Caddy با HTTPS قرار دهید.

## API مهم

همه مسیرهای زیر به جز subscription و health نیازمند هدر زیر هستند:

```http
Authorization: Bearer <access_token>
```

| متد | مسیر | کاربرد |
|---|---|---|
| `POST` | `/api/v1/auth/login` | دریافت JWT |
| `GET` | `/api/v1/auth/me` | حساب جاری |
| `POST` | `/api/v1/auth/change-password` | تغییر کلمه عبور |
| `GET` | `/api/v1/dashboard/overview` | آمار داشبورد |
| `GET` | `/api/v1/dashboard/traffic-chart?range=day` | نمودار `day/week/month` |
| `GET/POST` | `/api/v1/inbounds` | فهرست/ساخت اینباند |
| `PUT/DELETE` | `/api/v1/inbounds/{id}` | ویرایش/حذف اینباند |
| `POST` | `/api/v1/inbounds/{id}/toggle` | فعال/خاموش کردن |
| `GET/POST` | `/api/v1/inbounds/{id}/clients` | فهرست/ساخت کلاینت |
| `PUT/DELETE` | `/api/v1/clients/{id}` | ویرایش/حذف کلاینت |
| `GET` | `/api/v1/clients/{id}/config-link` | لینک اختصاصی اتصال |
| `POST` | `/api/v1/clients/{id}/toggle` | فعال/خاموش کردن کلاینت |
| `POST` | `/api/v1/clients/{id}/reset-traffic` | صفر کردن مصرف |
| `GET` | `/api/v1/sub/{sub_id}` | subscription عمومی Base64 |
| `GET/PUT` | `/api/v1/settings` | تنظیمات و دامنه پویا |
| `GET` | `/api/v1/settings/host` | هاست resolve شده |
| `GET` | `/api/v1/xray/config` | preview JSON |
| `GET` | `/api/v1/xray/config/download` | دانلود `config.json` |
| `POST` | `/api/v1/xray/reload` | تولید و reload اختیاری |
| `GET` | `/api/v1/xray/status` | وضعیت پردازش/کانفیگ |
| `GET` | `/api/v1/audit-logs` | رویدادهای مدیریتی |

نمونه ساخت VLESS Reality:

```bash
TOKEN=$(curl -s http://127.0.0.1:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' | python3 -c \
  'import json,sys; print(json.load(sys.stdin)["access_token"])')

curl -X POST http://127.0.0.1:8000/api/v1/inbounds \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "remark": "VLESS Reality",
    "protocol": "vless",
    "port": 443,
    "network": "tcp",
    "security": "reality",
    "stream_settings": {
      "dest": "www.cloudflare.com:443",
      "serverNames": ["www.cloudflare.com"],
      "privateKey": "REAL_PRIVATE_KEY",
      "shortIds": ["1234abcd"]
    }
  }'
```

برای VMess/Trojan/Shadowsocks نیز همان endpoint استفاده می‌شود و فقط `protocol`، `network` و `stream_settings` تغییر می‌کند. در Shadowsocks، `method` داخل `stream_settings` قابل تنظیم است.

## منطق هاست و fallback

تابع `get_server_host` در هر درخواست لینک، Settings را دوباره می‌خواند:

```text
server_domain → server_host → server_ip → SERVER_HOST/SERVER_DOMAIN
→ https://api.ipify.org → IP محلی → 127.0.0.1
```

مقدار خالی نادیده گرفته می‌شود. بنابراین اگر `server_domain` از `old.example.com` به `new.example.com` تغییر کند، لینک endpoint و subscription بعدی بدون restart شامل دامنه جدید خواهد بود.

## تولید کانفیگ و reload

`generate_xray_config` یک تابع pure است و از `list[dict]` نیز پشتیبانی می‌کند تا تست و استفاده بیرون از API آسان باشد. خروجی شامل موارد زیر است:

- inbound داخلی `dokodemo-door` روی `127.0.0.1:10085` برای API/Stats؛
- `settings.clients` متناسب با پروتکل؛
- `streamSettings` با بخش درست transport و TLS/Reality؛
- حذف inbounds/clients خاموش یا منقضی؛
- routing پایه و آمار uplink/downlink.

در زمان ذخیره، فایل با temp file، `fsync` و `os.replace` نوشته می‌شود و نسخه قبلی با پسوند `.bak` نگه‌داری می‌شود. خطای reload فایل جدید را حذف نمی‌کند. اگر `XRAY_RELOAD_COMMAND` خالی باشد، تولید config موفق است و فقط reload خارجی انجام نمی‌شود.

## تست جامع Differential

بعد از اجرای پنل:

```bash
PANEL_URL=http://127.0.0.1:8000 ./scripts/test_api.sh
```

تست استاندارد کتابخانه دیگری لازم ندارد و موارد زیر را بررسی می‌کند:

- health و رد درخواست خصوصی بدون JWT؛
- login و `/auth/me`؛
- fallback دامنه به IP؛
- ساخت هر چهار پروتکل؛
- transportهای Reality، WebSocket، gRPC و HTTP/2؛
- ساخت کلاینت و تولید UUID/password؛
- حضور رکوردها و settings در config؛
- تغییر دامنه در Settings و تغییر فوری لینک؛
- decode subscription عمومی؛
- toggle، update، reset traffic، chart، status و download؛
- پاک‌سازی رکوردهای ساخته‌شده پس از تست.

برای تست unit یا توسعه، می‌توان از `fastapi.testclient.TestClient` و تابع pure `generate_xray_config` استفاده کرد.

## نگهداری و امنیت

- کلمه عبور پیش‌فرض را بلافاصله تغییر دهید: `POST /api/v1/auth/change-password`.
- JWT secret را در Git یا Docker image قرار ندهید؛ Compose از `.env` می‌خواند.
- فقط پورت‌های لازم را در فایروال باز کنید و `/docs` را در صورت نیاز محدود کنید.
- API token نودها فقط در endpointهای خصوصی برمی‌گردد؛ در رابط کاربری نسخه mask شده نمایش داده می‌شود.
- subscription عمداً public است؛ `sub_id` را مانند یک secret در نظر بگیرید و در صورت افشا کلاینت را حذف/تعویض کنید.
- قبل از اعمال Reality/TLS، کلید خصوصی، public key و مسیر گواهی واقعی را قرار دهید و JSON تولیدشده را در `/api/v1/xray/config` بررسی کنید.

## مجوز

این پروژه تحت مجوز MIT ارائه می‌شود.
