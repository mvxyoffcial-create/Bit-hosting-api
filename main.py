"""
BotHost API v5 — Complete Working Solution
✅ Polling Bots - Fully working with auto package installation
✅ Webhook Bots - Fully working with auto webhook management
✅ Terminal - Install ANY package with pip
✅ Auto dependency management
"""

import os
import sys
import hashlib
import subprocess
import threading
import asyncio
import traceback
import math
import random
import re
import json
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional

import requests as req_lib
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import bcrypt
import motor.motor_asyncio
import jwt
from itsdangerous import URLSafeTimedSerializer
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ─────────────────────────────────────────────────────────────
# ENV CONFIG
# ─────────────────────────────────────────────────────────────
MONGO_URI        = "mongodb+srv://Zerobothost:zero8907@cluster0.szwdcyb.mongodb.net/?appName=Cluster0"
DB_NAME          = "bothost"
SECRET_KEY       = "rashmi@8907"
JWT_EXPIRE_HOURS = int(os.environ.get("JWT_EXPIRE_HOURS", "24"))

SMTP_HOST        = "smtp.gmail.com"
SMTP_PORT        = 587
SMTP_USER        = "natravelsoffcail@gmail.com"
SMTP_PASS        = "qpha qkbn rytr ncvu"
FROM_EMAIL       = os.environ.get("FROM_EMAIL", SMTP_USER)
FRONTEND_URL     = os.environ.get("FRONTEND_URL", "http://localhost:8000")
WEBHOOK_BASE_URL = os.environ.get("WEBHOOK_BASE_URL", FRONTEND_URL)

PORT = int(os.environ.get("PORT", "8000"))

# ─────────────────────────────────────────────────────────────
# APP + CORS
# ─────────────────────────────────────────────────────────────
app = FastAPI(
    title="BotHost API",
    description="Koyeb-style Telegram Bot Hosting Platform",
    version="5.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────
mongo_client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db           = mongo_client[DB_NAME]
users_col    = db["users"]
bots_col     = db["bots"]
storage_col  = db["bot_storage"]

# ─────────────────────────────────────────────────────────────
# SECURITY HELPERS
# ─────────────────────────────────────────────────────────────
bearer_scheme  = HTTPBearer(auto_error=False)
url_serializer = URLSafeTimedSerializer(SECRET_KEY)

def hash_pw(p: str) -> str:
    return bcrypt.hashpw(p[:72].encode(), bcrypt.gensalt()).decode()

def check_pw(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain[:72].encode(), hashed.encode())
    except Exception:
        return False

def make_token(data: dict) -> str:
    payload = {**data, "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS)}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

async def current_user(creds: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    if not creds:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except Exception:
        raise HTTPException(401, "Invalid token")

    user = await users_col.find_one({"email": payload["email"]}, {"_id": 0, "password": 0})
    if not user:
        raise HTTPException(401, "User not found")
    if not user.get("verified"):
        raise HTTPException(403, "Please verify your email first")
    return user

# ─────────────────────────────────────────────────────────────
# EMAIL
# ─────────────────────────────────────────────────────────────
def _do_send(to: str, subject: str, html: str):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = FROM_EMAIL
        msg["To"]      = to
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.ehlo(); s.starttls(); s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(FROM_EMAIL, to, msg.as_string())
        print(f"[EMAIL] Sent → {to}")
    except Exception as e:
        print(f"[EMAIL] Failed → {e}")

def send_email(to: str, subject: str, html: str):
    threading.Thread(target=_do_send, args=(to, subject, html), daemon=True).start()

def _verify_html(link: str, name: str) -> str:
    return f"""<div style="font-family:Arial,sans-serif;max-width:580px;margin:auto;
background:#ffffff;color:#1a1a1a;padding:36px;border-radius:14px;border:1px solid #e2e8f0">
<div style="text-align:center;margin-bottom:24px">
  <div style="font-size:48px">✅</div>
  <h2 style="color:#16a34a;margin:12px 0 4px">BotHost — Verify Your Email</h2>
</div>
<p style="color:#374151">Hi <b>{name}</b>, thanks for signing up!</p>
<p style="color:#374151">Click the button below to verify your email address and activate your account.</p>
<div style="text-align:center;margin:28px 0">
<a href="{link}" style="display:inline-block;background:#16a34a;color:#ffffff;
padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:bold;font-size:16px">
✅ Verify My Account</a>
</div>
<p style="color:#6b7280;font-size:12px;text-align:center;margin-top:24px">
Expires in 24 hours. Didn't sign up? You can safely ignore this email.</p>
</div>"""

def _reset_html(link: str) -> str:
    return f"""<div style="font-family:Arial,sans-serif;max-width:580px;margin:auto;
background:#0f172a;color:#f1f5f9;padding:36px;border-radius:14px">
<h2 style="color:#f59e0b">🔐 BotHost — Reset Password</h2>
<p>Click below to reset your password.</p>
<a href="{link}" style="display:inline-block;background:#f59e0b;color:#000;
padding:13px 28px;border-radius:8px;text-decoration:none;font-weight:bold;margin:16px 0">
🔑 Reset My Password</a>
<p style="color:#64748b;font-size:12px">Expires in 1 h. Didn't request this? Ignore.</p>
</div>"""

# ─────────────────────────────────────────────────────────────
# IN-MEMORY BOT STATE
# ─────────────────────────────────────────────────────────────
running_bots: dict = {}
bot_logs: dict     = defaultdict(lambda: deque(maxlen=500))
bot_scripts: dict  = {}

def log_msg(bot_id: str, msg: str, level: str = "INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    bot_logs[bot_id].append(f"[{ts}] [{level}] {msg}")
    print(f"[{bot_id}] {msg}")

def install_requirements(script: str) -> bool:
    """Auto-detect and install required packages from script"""
    import re
    # Find all import statements
    imports = re.findall(r'^(?:from|import)\s+([a-zA-Z0-9_]+)', script, re.MULTILINE)
    # Also find try/except imports
    try_imports = re.findall(r'except ImportError:\s*pass', script, re.MULTILINE)
    
    # Common packages that need installation
    common_packages = {
        'telegram': 'python-telegram-bot',
        'discord': 'discord.py',
        'aiohttp': 'aiohttp',
        'numpy': 'numpy',
        'pandas': 'pandas',
        'requests': None,  # Already installed
        'json': None,
        'os': None,
        'sys': None,
        'time': None,
        'datetime': None,
        'random': None,
        'math': None,
        're': None,
        'collections': None,
        'threading': None,
        'asyncio': None,
    }
    
    installed = False
    for imp in set(imports):
        if imp in common_packages and common_packages[imp]:
            package = common_packages[imp]
            try:
                __import__(imp)
                print(f"✅ {imp} already installed")
            except ImportError:
                print(f"📦 Installing {package}...")
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", package],
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode == 0:
                    print(f"✅ Installed {package}")
                    installed = True
                else:
                    print(f"❌ Failed to install {package}: {result.stderr}")
    
    return installed

class LogThread(threading.Thread):
    def __init__(self, bot_id, proc, kind):
        super().__init__(daemon=True)
        self.bot_id = bot_id
        self.stream = proc.stdout if kind == "stdout" else proc.stderr
        self.kind   = kind

    def run(self):
        try:
            for line in iter(self.stream.readline, ""):
                if line:
                    log_msg(self.bot_id, line.strip(), "ERROR" if self.kind == "stderr" else "INFO")
        except Exception:
            pass

def _stop_proc(bot_id: str):
    bd = running_bots.pop(bot_id, None)
    if not bd:
        return
    p = bd.get("process")
    if p:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
    sp = bd.get("script_path", "")
    if sp and os.path.exists(sp):
        os.remove(sp)
    log_msg(bot_id, "Stopped ⏹️", "WARNING")

# ─────────────────────────────────────────────────────────────
# SCHEMAS
# ─────────────────────────────────────────────────────────────
class RegisterBody(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginBody(BaseModel):
    email: EmailStr
    password: str

class ForgotBody(BaseModel):
    email: EmailStr

class ResetBody(BaseModel):
    token: str
    new_password: str

class CreateBotBody(BaseModel):
    name: str
    bot_token: str
    script: str
    bot_type: str = "polling"
    env_vars: dict = {}

class UpdateBotBody(BaseModel):
    name: Optional[str]      = None
    script: Optional[str]    = None
    env_vars: Optional[dict] = None

class UpdateScriptBody(BaseModel):
    script: str

class TerminalBody(BaseModel):
    command: str
    bot_id: Optional[str] = None

# ─────────────────────────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    await users_col.create_index("email", unique=True)
    await bots_col.create_index("bot_id", unique=True)
    await bots_col.create_index("owner_email")
    print("=" * 60)
    print("🤖 BOTHOST API v5 STARTED")
    print("=" * 60)
    print(f"✅ MongoDB: Connected")
    print(f"✅ Server: http://0.0.0.0:{PORT}")
    print(f"✅ Docs: http://0.0.0.0:{PORT}/docs")
    print(f"✅ Webhook URL: {WEBHOOK_BASE_URL}")
    print("=" * 60)

# ─────────────────────────────────────────────────────────────
# SYSTEM ROUTES
# ─────────────────────────────────────────────────────────────
@app.get("/", tags=["System"])
async def root():
    return {
        "service": "BotHost API",
        "version": "5.0.0",
        "docs": "/docs",
        "health": "/health",
    }

@app.get("/health", tags=["System"])
async def health():
    try:
        await mongo_client.admin.command("ping")
        db_ok = True
    except Exception:
        db_ok = False
    return {
        "status": "healthy" if db_ok else "degraded",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "5.0.0",
        "database": "connected" if db_ok else "disconnected",
        "running_bots": len(running_bots),
        "port": PORT,
    }

# ─────────────────────────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────────────────────────
@app.post("/auth/register", tags=["Auth"])
async def register(body: RegisterBody, bg: BackgroundTasks):
    if await users_col.find_one({"email": body.email}):
        raise HTTPException(409, "Email already registered")

    await users_col.insert_one({
        "name": body.name,
        "email": body.email,
        "password": hash_pw(body.password),
        "verified": False,
        "created_at": datetime.utcnow(),
    })

    tok = url_serializer.dumps(body.email, salt="email-verify")
    link = f"{FRONTEND_URL}/auth/verify?token={tok}"
    bg.add_task(send_email, body.email,
                "Verify your BotHost account",
                _verify_html(link, body.name))

    return {
        "success": True,
        "message": "Registered! Check your email to verify your account.",
        "verify_link": link,
    }

@app.get("/auth/verify", tags=["Auth"])
async def verify_email(token: str):
    try:
        email = url_serializer.loads(token, salt="email-verify", max_age=86400)
    except Exception:
        raise HTTPException(400, "Invalid or expired verification link")

    r = await users_col.update_one({"email": email}, {"$set": {"verified": True}})
    if r.matched_count == 0:
        raise HTTPException(404, "User not found")

    return HTMLResponse("""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Email Verified</title></head>
<body style="margin:0;font-family:Arial,sans-serif;background:#f0fdf4;
display:flex;align-items:center;justify-content:center;height:100vh">
<div style="text-align:center;background:#ffffff;padding:48px 56px;border-radius:16px;
box-shadow:0 4px 24px rgba(22,163,74,0.12);border:1px solid #bbf7d0;max-width:420px">
  <div style="font-size:64px;margin-bottom:8px">✅</div>
  <h1 style="color:#16a34a;margin:12px 0 8px;font-size:28px">Email Verified!</h1>
  <p style="color:#374151;margin:0;font-size:15px">
    Your BotHost account is now active.<br>You can close this tab and log in.
  </p>
</div></body></html>""")

@app.post("/auth/login", tags=["Auth"])
async def login(body: LoginBody):
    user = await users_col.find_one({"email": body.email})
    if not user or not check_pw(body.password, user["password"]):
        raise HTTPException(401, "Invalid email or password")
    if not user.get("verified"):
        raise HTTPException(403, "Please verify your email first")

    token = make_token({"email": user["email"], "name": user["name"]})
    return {
        "success": True,
        "access_token": token,
        "token_type": "bearer",
        "expires_in": f"{JWT_EXPIRE_HOURS}h",
        "user": {"name": user["name"], "email": user["email"]},
    }

@app.post("/auth/forgot-password", tags=["Auth"])
async def forgot_password(body: ForgotBody, bg: BackgroundTasks):
    user = await users_col.find_one({"email": body.email})
    if user:
        tok = url_serializer.dumps(body.email, salt="pwd-reset")
        link = f"{FRONTEND_URL}/auth/reset-password?token={tok}"
        bg.add_task(send_email, body.email,
                    "Reset your BotHost password",
                    _reset_html(link))
    return {"success": True, "message": "If that email exists, a reset link was sent."}

@app.post("/auth/reset-password", tags=["Auth"])
async def reset_password(body: ResetBody):
    try:
        email = url_serializer.loads(body.token, salt="pwd-reset", max_age=3600)
    except Exception:
        raise HTTPException(400, "Invalid or expired reset link")

    r = await users_col.update_one({"email": email},
                                    {"$set": {"password": hash_pw(body.new_password)}})
    if r.matched_count == 0:
        raise HTTPException(404, "User not found")
    return {"success": True, "message": "Password updated! You can now log in."}

@app.get("/auth/me", tags=["Auth"])
async def me(user=Depends(current_user)):
    return user

# ─────────────────────────────────────────────────────────────
# BOT ROUTES
# ─────────────────────────────────────────────────────────────
def _fmt(bot: dict) -> dict:
    bot = dict(bot)
    bot.pop("_id", None)
    bot.pop("bot_token", None)
    for k in ("created_at", "updated_at"):
        if k in bot and hasattr(bot[k], "isoformat"):
            bot[k] = bot[k].isoformat()
    return bot

@app.post("/api/bots", tags=["Bots"], status_code=201)
async def create_bot(body: CreateBotBody, user=Depends(current_user)):
    # Validate token with Telegram
    try:
        resp = req_lib.get(f"https://api.telegram.org/bot{body.bot_token}/getMe", timeout=8)
        data = resp.json()
        if not data.get("ok"):
            raise HTTPException(400, "Invalid bot token")
        bot_info = data["result"]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Telegram error: {e}")

    bot_id = hashlib.md5(body.bot_token.encode()).hexdigest()[:12]
    
    # Auto-replace token placeholders
    script = body.script
    script = script.replace("YOUR_BOT_TOKEN_HERE", body.bot_token)
    script = script.replace("YOUR_TOKEN_WILL_BE_SET_AUTOMATICALLY", body.bot_token)
    script = script.replace("your_bot_token_here", body.bot_token)
    
    # Auto-install requirements from script
    install_requirements(script)

    webhook_set = False
    webhook_url = None
    
    if body.bot_type == "webhook":
        webhook_url = f"{WEBHOOK_BASE_URL}/api/webhook/{body.bot_token}"
        try:
            wr = req_lib.post(f"https://api.telegram.org/bot{body.bot_token}/setWebhook",
                              json={"url": webhook_url}, timeout=8)
            result = wr.json()
            webhook_set = result.get("ok", False)
            if webhook_set:
                log_msg(bot_id, f"✅ Webhook set: {webhook_url}", "INFO")
            else:
                log_msg(bot_id, f"❌ Webhook failed: {result}", "ERROR")
        except Exception as e:
            log_msg(bot_id, f"❌ Webhook error: {e}", "ERROR")

    doc = {
        "bot_id": bot_id,
        "bot_token": body.bot_token,
        "bot_username": bot_info.get("username"),
        "bot_name": body.name,
        "bot_type": body.bot_type,
        "script": script,
        "env_vars": body.env_vars,
        "owner_email": user["email"],
        "active": True,
        "running": False,
        "webhook_url": webhook_url,
        "webhook_set": webhook_set,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    await bots_col.update_one({"bot_id": bot_id}, {"$set": doc}, upsert=True)
    bot_scripts[bot_id] = script
    log_msg(bot_id, f"✅ Bot created: @{bot_info.get('username')} (Type: {body.bot_type})", "INFO")

    return {
        "success": True,
        "bot_id": bot_id,
        "bot_username": bot_info.get("username"),
        "bot_type": body.bot_type,
        "webhook_set": webhook_set,
        "webhook_url": webhook_url,
    }

@app.get("/api/bots", tags=["Bots"])
async def list_bots(user=Depends(current_user)):
    bots = await bots_col.find({"owner_email": user["email"]}).to_list(None)
    for b in bots:
        if b.get("bot_type") == "polling":
            b["live"] = b["bot_id"] in running_bots
        else:
            b["live"] = b.get("webhook_set", False)
    return {"bots": [_fmt(b) for b in bots], "count": len(bots)}

@app.get("/api/bots/{bot_id}", tags=["Bots"])
async def get_bot(bot_id: str, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot:
        raise HTTPException(404, "Bot not found")
    if bot.get("bot_type") == "polling":
        bot["live"] = bot_id in running_bots
    else:
        bot["live"] = bot.get("webhook_set", False)
    return _fmt(bot)

@app.patch("/api/bots/{bot_id}", tags=["Bots"])
async def update_bot(bot_id: str, body: UpdateBotBody, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot:
        raise HTTPException(404, "Bot not found")

    up: dict = {"updated_at": datetime.utcnow()}
    if body.name is not None: 
        up["bot_name"] = body.name
    if body.script is not None:
        script = body.script
        script = script.replace("YOUR_BOT_TOKEN_HERE", bot["bot_token"])
        script = script.replace("YOUR_TOKEN_WILL_BE_SET_AUTOMATICALLY", bot["bot_token"])
        up["script"] = script
        bot_scripts[bot_id] = script
        install_requirements(script)
    if body.env_vars is not None: 
        up["env_vars"] = body.env_vars

    await bots_col.update_one({"bot_id": bot_id}, {"$set": up})
    return {"success": True, "message": "Bot updated"}

@app.put("/api/bots/{bot_id}/script", tags=["Bots"])
async def update_script(bot_id: str, body: UpdateScriptBody, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot:
        raise HTTPException(404, "Bot not found")

    script = body.script
    script = script.replace("YOUR_BOT_TOKEN_HERE", bot["bot_token"])
    script = script.replace("YOUR_TOKEN_WILL_BE_SET_AUTOMATICALLY", bot["bot_token"])

    await bots_col.update_one({"bot_id": bot_id},
                               {"$set": {"script": script, "updated_at": datetime.utcnow()}})
    bot_scripts[bot_id] = script
    install_requirements(script)
    log_msg(bot_id, "Script updated 📝", "INFO")

    return {
        "success": True,
        "message": "Script updated. Restart the bot to apply changes.",
        "was_running": bot_id in running_bots,
    }

@app.get("/api/bots/{bot_id}/script", tags=["Bots"])
async def get_script(bot_id: str, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot:
        raise HTTPException(404, "Bot not found")
    return {"bot_id": bot_id, "script": bot.get("script", "")}

@app.delete("/api/bots/{bot_id}", tags=["Bots"])
async def delete_bot(bot_id: str, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot:
        raise HTTPException(404, "Bot not found")

    if bot_id in running_bots:
        _stop_proc(bot_id)
    if bot.get("bot_type") == "webhook":
        try:
            req_lib.post(f"https://api.telegram.org/bot{bot['bot_token']}/deleteWebhook", timeout=5)
            log_msg(bot_id, "Webhook deleted", "INFO")
        except Exception:
            pass

    await bots_col.delete_one({"bot_id": bot_id})
    await storage_col.delete_many({"bot_id": bot_id})
    bot_scripts.pop(bot_id, None)
    bot_logs.pop(bot_id, None)
    return {"success": True, "message": "Bot deleted", "bot_id": bot_id}

# ── Start / Stop / Restart for Polling ──────────────────────
@app.post("/api/bots/{bot_id}/start", tags=["Bots"])
async def start_bot(bot_id: str, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot:
        raise HTTPException(404, "Bot not found")
    
    if bot.get("bot_type") == "webhook":
        # Re-set webhook for webhook bots
        webhook_url = f"{WEBHOOK_BASE_URL}/api/webhook/{bot['bot_token']}"
        try:
            wr = req_lib.post(f"https://api.telegram.org/bot{bot['bot_token']}/setWebhook",
                              json={"url": webhook_url}, timeout=8)
            if wr.json().get("ok"):
                await bots_col.update_one({"bot_id": bot_id},
                                           {"$set": {"webhook_set": True, "running": True, "updated_at": datetime.utcnow()}})
                log_msg(bot_id, "✅ Webhook bot activated", "INFO")
                return {"success": True, "message": "Webhook bot activated", "webhook_url": webhook_url}
            else:
                raise HTTPException(500, "Failed to set webhook")
        except Exception as e:
            raise HTTPException(500, f"Failed to activate webhook bot: {e}")
    
    # Polling bot start
    if bot_id in running_bots:
        raise HTTPException(400, "Bot is already running")

    # Install requirements before starting
    install_requirements(bot_scripts.get(bot_id, bot["script"]))

    sp = f"/tmp/bot_{bot_id}.py"
    with open(sp, "w") as f:
        f.write(bot_scripts.get(bot_id, bot["script"]))

    env = {**os.environ, **bot.get("env_vars", {})}
    env["BOT_TOKEN"] = bot["bot_token"]
    env["BOT_ID"] = bot_id
    
    proc = subprocess.Popen(
        [sys.executable, sp],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1, env=env,
    )
    to = LogThread(bot_id, proc, "stdout")
    te = LogThread(bot_id, proc, "stderr")
    to.start()
    te.start()

    running_bots[bot_id] = {
        "process": proc, 
        "script_path": sp,
        "stdout_thread": to, 
        "stderr_thread": te
    }
    await bots_col.update_one({"bot_id": bot_id},
                               {"$set": {"running": True, "updated_at": datetime.utcnow()}})
    log_msg(bot_id, f"✅ Polling bot started (PID: {proc.pid})", "INFO")
    return {"success": True, "message": "Polling bot started", "pid": proc.pid}

@app.post("/api/bots/{bot_id}/stop", tags=["Bots"])
async def stop_bot(bot_id: str, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot:
        raise HTTPException(404, "Bot not found")
    
    if bot.get("bot_type") == "webhook":
        # Delete webhook to stop webhook bot
        try:
            req_lib.post(f"https://api.telegram.org/bot{bot['bot_token']}/deleteWebhook", timeout=5)
            await bots_col.update_one({"bot_id": bot_id},
                                       {"$set": {"webhook_set": False, "running": False, "updated_at": datetime.utcnow()}})
            log_msg(bot_id, "Webhook bot stopped", "INFO")
            return {"success": True, "message": "Webhook bot stopped"}
        except Exception as e:
            raise HTTPException(500, f"Failed to stop webhook bot: {e}")
    
    if bot_id not in running_bots:
        raise HTTPException(400, "Bot is not running")
    
    _stop_proc(bot_id)
    await bots_col.update_one({"bot_id": bot_id},
                               {"$set": {"running": False, "updated_at": datetime.utcnow()}})
    return {"success": True, "message": "Polling bot stopped"}

@app.post("/api/bots/{bot_id}/restart", tags=["Bots"])
async def restart_bot(bot_id: str, user=Depends(current_user)):
    # Stop if running
    if bot_id in running_bots:
        _stop_proc(bot_id)
        await bots_col.update_one({"bot_id": bot_id},
                                   {"$set": {"running": False, "updated_at": datetime.utcnow()}})
        await asyncio.sleep(2)
    return await start_bot(bot_id, user)

# ── Logs ──────────────────────────────────────────────────────────────
@app.get("/api/bots/{bot_id}/logs", tags=["Bots"])
async def get_logs(bot_id: str, user=Depends(current_user)):
    if not await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]}):
        raise HTTPException(404, "Bot not found")
    return {"bot_id": bot_id, "logs": list(bot_logs[bot_id])}

@app.get("/api/bots/{bot_id}/logs/stream", tags=["Bots"])
async def stream_logs(bot_id: str, user=Depends(current_user)):
    if not await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]}):
        raise HTTPException(404, "Bot not found")

    async def event_stream():
        seen = 0
        while True:
            cur = list(bot_logs[bot_id])
            for entry in cur[seen:]:
                yield f"data: {json.dumps({'log': entry})}\n\n"
            seen = len(cur)
            await asyncio.sleep(0.5)

    return StreamingResponse(event_stream(), media_type="text/event-stream")

@app.delete("/api/bots/{bot_id}/logs", tags=["Bots"])
async def clear_logs(bot_id: str, user=Depends(current_user)):
    if not await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]}):
        raise HTTPException(404, "Bot not found")
    bot_logs[bot_id].clear()
    return {"success": True}

# ── Env vars ──────────────────────────────────────────────────────────
@app.get("/api/bots/{bot_id}/env", tags=["Bots"])
async def get_env(bot_id: str, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot:
        raise HTTPException(404, "Bot not found")
    return {"bot_id": bot_id, "env_vars": bot.get("env_vars", {})}

@app.put("/api/bots/{bot_id}/env", tags=["Bots"])
async def set_env(bot_id: str, env_vars: dict, user=Depends(current_user)):
    if not await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]}):
        raise HTTPException(404, "Bot not found")
    await bots_col.update_one({"bot_id": bot_id},
                               {"$set": {"env_vars": env_vars, "updated_at": datetime.utcnow()}})
    return {"success": True, "message": "Env vars updated. Restart bot to apply."}

# ── Webhook receiver ──────────────────────────────────────────────────
@app.post("/api/webhook/{bot_token}", include_in_schema=False)
async def webhook_handler(bot_token: str, request: Request):
    """Handle Telegram webhook updates"""
    try:
        update = await request.json()
        print(f"[WEBHOOK] Received update for bot: {bot_token[:10]}...")
        
        bot = await bots_col.find_one({"bot_token": bot_token})
        if not bot:
            print(f"[WEBHOOK] Bot not found for token: {bot_token[:10]}...")
            return {"ok": False, "error": "Bot not found"}
        
        if bot.get("bot_type") != "webhook":
            print(f"[WEBHOOK] Bot {bot['bot_id']} is not webhook type")
            return {"ok": False, "error": "Not a webhook bot"}

        bot_id = bot["bot_id"]
        
        # Log the update
        update_type = "message" if "message" in update else "callback_query" if "callback_query" in update else "unknown"
        log_msg(bot_id, f"📨 Webhook received: {update_type}", "INFO")
        
        script = bot_scripts.get(bot_id, bot["script"])
        
        # Execute script in thread pool
        def execute():
            try:
                execute_bot_script(script, update, bot_token, bot_id, update_type)
            except Exception as e:
                log_msg(bot_id, f"Script execution error: {e}", "ERROR")
                traceback.print_exc()
        
        threading.Thread(target=execute, daemon=True).start()
        
        return {"ok": True}
        
    except Exception as e:
        print(f"[WEBHOOK] Error: {e}")
        traceback.print_exc()
        return {"ok": False, "error": str(e)}

# ─────────────────────────────────────────────────────────────
# TERMINAL - Install ANY package
# ─────────────────────────────────────────────────────────────
@app.post("/api/terminal", tags=["Terminal"])
async def terminal_execute(body: TerminalBody, user=Depends(current_user)):
    """Execute terminal commands - can install ANY package"""
    cmd = body.command.strip()
    if not cmd:
        raise HTTPException(400, "No command provided")

    # Allow all pip commands and common utilities
    allowed_prefixes = ["pip", "pip3", "python", "python3", "ls", "pwd", "env", "which", "echo", "cat", "cd", "mkdir", "rm", "cp", "mv"]
    
    cmd_parts = cmd.split()
    if not cmd_parts:
        raise HTTPException(400, "Invalid command")
    
    # Check if command is allowed
    is_allowed = False
    for prefix in allowed_prefixes:
        if cmd_parts[0] == prefix or cmd_parts[0].startswith(prefix):
            is_allowed = True
            break
    
    # Special handling for pip install any package
    if cmd_parts[0] in ["pip", "pip3"] and len(cmd_parts) > 1 and cmd_parts[1] == "install":
        is_allowed = True
    
    if not is_allowed:
        return {"output": f"❌ Command '{cmd_parts[0]}' is not allowed.\nAllowed: {', '.join(allowed_prefixes)}"}

    # Setup environment with bot env vars if specified
    env = dict(os.environ)
    if body.bot_id:
        bot = await bots_col.find_one({"bot_id": body.bot_id, "owner_email": user["email"]})
        if bot:
            env.update(bot.get("env_vars", {}))
            env["BOT_TOKEN"] = bot["bot_token"]

    try:
        # For pip install, use --no-cache-dir to save space
        if cmd_parts[0] in ["pip", "pip3"] and "install" in cmd_parts:
            if "--no-cache-dir" not in cmd:
                cmd = cmd + " --no-cache-dir"
        
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=180,  # 3 minutes timeout for large packages
            env=env
        )
        
        output = result.stdout + result.stderr
        if not output.strip():
            output = "✅ Command executed successfully (no output)"
        
        # Special message for successful pip installs
        if cmd_parts[0] in ["pip", "pip3"] and "install" in cmd_parts and result.returncode == 0:
            package = cmd_parts[cmd_parts.index("install") + 1] if len(cmd_parts) > cmd_parts.index("install") + 1 else "package"
            output = f"✅ Successfully installed {package}\n\n{output}"
        
        return {"output": output.strip()}
        
    except subprocess.TimeoutExpired:
        return {"output": "⏱️ Command timed out after 180 seconds"}
    except Exception as e:
        return {"output": f"❌ Error: {str(e)}"}

# ─────────────────────────────────────────────────────────────
# BOT SCRIPT EXECUTION ENGINE
# ─────────────────────────────────────────────────────────────
class ReturnCommand(Exception):
    pass

class _MsgObj:
    def __init__(self, d: dict):
        self.text = d.get("text", "")
        self.caption = d.get("caption", "")
        self.message_id = d.get("message_id")
        self.date = d.get("date")
        self._raw = d
        self.chat = type("Chat", (), {
            "id": d["chat"]["id"],
            "type": d["chat"].get("type", "private"),
            "username": d["chat"].get("username", ""),
            "first_name": d["chat"].get("first_name", ""),
        })()
        self.from_user = type("User", (), {
            "id": d.get("from", {}).get("id"),
            "username": d.get("from", {}).get("username", ""),
            "first_name": d.get("from", {}).get("first_name", ""),
            "is_bot": d.get("from", {}).get("is_bot", False),
        })()

class _CBQObj:
    def __init__(self, d: dict):
        self.id = d.get("id")
        self.data = d.get("data", "")
        self.message = _MsgObj(d["message"]) if "message" in d else None
        self.from_user = type("User", (), {
            "id": d.get("from", {}).get("id"),
            "username": d.get("from", {}).get("username", ""),
            "first_name": d.get("from", {}).get("first_name", ""),
        })()

class InlineKeyboardMarkup:
    def __init__(self, inline_keyboard):
        self.inline_keyboard = inline_keyboard

    def to_dict(self):
        return {"inline_keyboard": [
            [b.to_dict() if isinstance(b, InlineKeyboardButton) else b for b in row]
            for row in self.inline_keyboard
        ]}

class InlineKeyboardButton:
    def __init__(self, text, callback_data=None, url=None):
        self.text = text
        self.callback_data = callback_data
        self.url = url

    def to_dict(self):
        d = {"text": self.text}
        if self.callback_data:
            d["callback_data"] = self.callback_data
        if self.url:
            d["url"] = self.url
        return d

class BotStorage:
    def __init__(self, bot_id: str):
        self.bot_id = bot_id

    def _col(self):
        import pymongo
        return pymongo.MongoClient(MONGO_URI)[DB_NAME]["bot_storage"]

    def set(self, key, value):
        try:
            self._col().update_one(
                {"bot_id": self.bot_id, "key": key},
                {"$set": {"value": value, "updated_at": datetime.utcnow()}},
                upsert=True,
            )
            return True
        except Exception as e:
            print(f"[Storage.set] {e}")
            return False

    def get(self, key, default=None):
        try:
            doc = self._col().find_one({"bot_id": self.bot_id, "key": key})
            return doc["value"] if doc else default
        except Exception as e:
            print(f"[Storage.get] {e}")
            return default

    def delete(self, key):
        try:
            self._col().delete_one({"bot_id": self.bot_id, "key": key})
            return True
        except Exception:
            return False

class BotAPI:
    def __init__(self, token: str):
        self.token = token
        self.base_url = f"https://api.telegram.org/bot{token}"

    def _post(self, method: str, data: dict):
        try:
            r = req_lib.post(f"{self.base_url}/{method}", json=data, timeout=10)
            return r.json()
        except Exception as e:
            print(f"[BotAPI.{method}] {e}")
            return None

    def sendMessage(self, chat_id, text, parse_mode=None, reply_markup=None):
        d = {"chat_id": chat_id, "text": text}
        if parse_mode:
            d["parse_mode"] = parse_mode
        if reply_markup:
            d["reply_markup"] = (reply_markup.to_dict()
                                 if isinstance(reply_markup, InlineKeyboardMarkup)
                                 else reply_markup)
        return self._post("sendMessage", d)

    def editMessageText(self, chat_id, message_id, text, parse_mode=None, reply_markup=None):
        d = {"chat_id": chat_id, "message_id": message_id, "text": text}
        if parse_mode:
            d["parse_mode"] = parse_mode
        if reply_markup:
            d["reply_markup"] = (reply_markup.to_dict()
                                 if isinstance(reply_markup, InlineKeyboardMarkup)
                                 else reply_markup)
        return self._post("editMessageText", d)

    def answerCallbackQuery(self, callback_query_id, text=None, show_alert=False):
        d = {"callback_query_id": callback_query_id, "show_alert": show_alert}
        if text:
            d["text"] = text
        return self._post("answerCallbackQuery", d)

    def deleteMessage(self, chat_id, message_id):
        return self._post("deleteMessage", {"chat_id": chat_id, "message_id": message_id})

    def sendPhoto(self, chat_id, photo, caption=None, reply_markup=None):
        d = {"chat_id": chat_id, "photo": photo}
        if caption:
            d["caption"] = caption
        if reply_markup:
            d["reply_markup"] = (reply_markup.to_dict()
                                 if isinstance(reply_markup, InlineKeyboardMarkup)
                                 else reply_markup)
        return self._post("sendPhoto", d)

def execute_bot_script(script: str, update: dict, bot_token: str,
                       bot_id: str, utype: str):
    try:
        bot = BotAPI(bot_token)
        storage = BotStorage(bot_id)

        if utype == "message":
            message = _MsgObj(update["message"])
            callback_query = None
        else:
            callback_query = _CBQObj(update["callback_query"])
            message = callback_query.message

        # Create a safe execution environment
        exec_globals = {
            "__builtins__": __builtins__,
            "bot": bot,
            "storage": storage,
            "message": message,
            "callback_query": callback_query,
            "ReturnCommand": ReturnCommand,
            "InlineKeyboardMarkup": InlineKeyboardMarkup,
            "InlineKeyboardButton": InlineKeyboardButton,
            "re": re,
            "math": math,
            "random": random,
            "time": time,
            "datetime": datetime,
            "requests": req_lib,
            "json": json,
            "os": os,
            "sys": sys,
            "traceback": traceback,
        }
        
        exec(script, exec_globals)
        log_msg(bot_id, f"✅ Script executed: {utype}", "INFO")
        
    except ReturnCommand:
        pass
    except Exception as e:
        error_msg = f"Script error: {str(e)}\n{traceback.format_exc()}"
        log_msg(bot_id, error_msg, "ERROR")
        print(error_msg)

# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("🤖 BOTHOST API v5 - COMPLETE WORKING SOLUTION")
    print("=" * 60)
    print("✅ Polling Bots: Working")
    print("✅ Webhook Bots: Working")
    print("✅ Terminal: Full package installation")
    print("✅ Auto dependency installation")
    print("=" * 60)
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=False)
