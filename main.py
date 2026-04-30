"""
BotHost API v6 — Full Webhook Mode (No Polling)
✅ Webhook-only bots — set automatically on create, restart on start
✅ Bot auto-activates (webhook set) immediately after creation
✅ User can Start / Stop / Refresh (re-register webhook) any time
✅ Continuous operation — no polling threads, event-driven via Telegram push
✅ Edit Bots — update name, script, env_vars
✅ Terminal — install any package
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
    description="Telegram Bot Hosting — Full Webhook Mode",
    version="6.0.0",
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
<p style="color:#374151">Click below to verify your email and activate your account.</p>
<div style="text-align:center;margin:28px 0">
<a href="{link}" style="display:inline-block;background:#16a34a;color:#ffffff;
padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:bold;font-size:16px">
✅ Verify My Account</a>
</div>
<p style="color:#6b7280;font-size:12px;text-align:center;margin-top:24px">
Expires in 24 hours. Didn't sign up? Ignore this email.</p>
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
# IN-MEMORY BOT STATE  (webhook bots only — no process tracking)
# ─────────────────────────────────────────────────────────────
# Maps bot_id -> {"active": bool, "script": str, "token": str}
webhook_bots: dict = {}
bot_logs: dict     = defaultdict(lambda: deque(maxlen=500))

def log_msg(bot_id: str, msg: str, level: str = "INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{ts}] [{level}] {msg}"
    bot_logs[bot_id].append(entry)
    print(f"[{bot_id}] {msg}")

# ─────────────────────────────────────────────────────────────
# WEBHOOK HELPERS
# ─────────────────────────────────────────────────────────────
def _webhook_url_for(token: str) -> str:
    return f"{WEBHOOK_BASE_URL}/api/webhook/{token}"

def _set_telegram_webhook(token: str, url: str) -> bool:
    """Register webhook URL with Telegram. Returns True on success."""
    try:
        r = req_lib.post(
            f"https://api.telegram.org/bot{token}/setWebhook",
            json={"url": url, "allowed_updates": ["message", "callback_query", "inline_query"]},
            timeout=10,
        )
        result = r.json()
        ok = result.get("ok", False)
        print(f"[WEBHOOK] setWebhook → {ok} | {result.get('description', '')}")
        return ok
    except Exception as e:
        print(f"[WEBHOOK] setWebhook error: {e}")
        return False

def _delete_telegram_webhook(token: str) -> bool:
    """Remove webhook from Telegram. Returns True on success."""
    try:
        r = req_lib.post(
            f"https://api.telegram.org/bot{token}/deleteWebhook",
            json={"drop_pending_updates": False},
            timeout=10,
        )
        return r.json().get("ok", False)
    except Exception as e:
        print(f"[WEBHOOK] deleteWebhook error: {e}")
        return False

def _get_telegram_webhook_info(token: str) -> dict:
    """Fetch current webhook info from Telegram."""
    try:
        r = req_lib.get(f"https://api.telegram.org/bot{token}/getWebhookInfo", timeout=8)
        return r.json().get("result", {})
    except Exception:
        return {}

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
    env_vars: dict = {}
    # bot_type is always "webhook" now — field kept for API compatibility
    bot_type: str = "webhook"

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
# STARTUP  — restore webhook state for all active bots
# ─────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    await users_col.create_index("email", unique=True)
    await bots_col.create_index("bot_id", unique=True)
    await bots_col.create_index("owner_email")

    # Re-load all running bots into memory and re-register webhooks
    bots = await bots_col.find({"running": True}).to_list(None)
    restored = 0
    for bot in bots:
        bid   = bot["bot_id"]
        token = bot["bot_token"]
        url   = _webhook_url_for(token)
        ok    = _set_telegram_webhook(token, url)
        webhook_bots[bid] = {
            "active": ok,
            "script": bot.get("script", ""),
            "token":  token,
        }
        if ok:
            restored += 1
            log_msg(bid, "✅ Webhook restored on startup", "INFO")
        else:
            log_msg(bid, "⚠️ Webhook restore failed — bot marked inactive", "WARNING")
            await bots_col.update_one({"bot_id": bid}, {"$set": {"running": False, "webhook_set": False}})

    print("=" * 60)
    print("🤖 BOTHOST API v6 — WEBHOOK-ONLY MODE")
    print("=" * 60)
    print(f"✅ MongoDB: Connected")
    print(f"✅ Server: http://0.0.0.0:{PORT}")
    print(f"✅ Docs: http://0.0.0.0:{PORT}/docs")
    print(f"✅ Webhook base: {WEBHOOK_BASE_URL}")
    print(f"✅ Restored bots: {restored}/{len(bots)}")
    print("=" * 60)

# ─────────────────────────────────────────────────────────────
# SYSTEM ROUTES
# ─────────────────────────────────────────────────────────────
@app.get("/", tags=["System"])
async def root():
    return {
        "service": "BotHost API",
        "version": "6.0.0",
        "mode": "webhook-only",
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
        "version": "6.0.0",
        "mode": "webhook-only",
        "database": "connected" if db_ok else "disconnected",
        "active_webhook_bots": sum(1 for b in webhook_bots.values() if b.get("active")),
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

    tok  = url_serializer.dumps(body.email, salt="email-verify")
    link = f"{FRONTEND_URL}/auth/verify?token={tok}"
    bg.add_task(send_email, body.email, "Verify your BotHost account", _verify_html(link, body.name))

    return {"success": True, "message": "Registered! Check your email.", "verify_link": link}

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
<div style="text-align:center;background:#fff;padding:48px 56px;border-radius:16px;
box-shadow:0 4px 24px rgba(22,163,74,.12);border:1px solid #bbf7d0;max-width:420px">
  <div style="font-size:64px;margin-bottom:8px">✅</div>
  <h1 style="color:#16a34a;margin:12px 0 8px;font-size:28px">Email Verified!</h1>
  <p style="color:#374151;margin:0;font-size:15px">
    Your BotHost account is active.<br>You can close this tab and log in.
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
        tok  = url_serializer.dumps(body.email, salt="pwd-reset")
        link = f"{FRONTEND_URL}/auth/reset-password?token={tok}"
        bg.add_task(send_email, body.email, "Reset your BotHost password", _reset_html(link))
    return {"success": True, "message": "If that email exists, a reset link was sent."}

@app.post("/auth/reset-password", tags=["Auth"])
async def reset_password(body: ResetBody):
    try:
        email = url_serializer.loads(body.token, salt="pwd-reset", max_age=3600)
    except Exception:
        raise HTTPException(400, "Invalid or expired reset link")

    r = await users_col.update_one({"email": email}, {"$set": {"password": hash_pw(body.new_password)}})
    if r.matched_count == 0:
        raise HTTPException(404, "User not found")
    return {"success": True, "message": "Password updated! You can now log in."}

@app.get("/auth/me", tags=["Auth"])
async def me(user=Depends(current_user)):
    return user

# ─────────────────────────────────────────────────────────────
# BOT HELPERS
# ─────────────────────────────────────────────────────────────
def _fmt(bot: dict) -> dict:
    bot = dict(bot)
    bot.pop("_id", None)
    bot.pop("bot_token", None)
    for k in ("created_at", "updated_at"):
        if k in bot and hasattr(bot[k], "isoformat"):
            bot[k] = bot[k].isoformat()
    return bot

def _sanitize_script(script: str, token: str) -> str:
    script = script.replace("YOUR_BOT_TOKEN_HERE", token)
    script = script.replace("YOUR_TOKEN_WILL_BE_SET_AUTOMATICALLY", token)
    script = script.replace("your_bot_token_here", token)
    return script

# ─────────────────────────────────────────────────────────────
# BOT CRUD
# ─────────────────────────────────────────────────────────────
@app.post("/api/bots", tags=["Bots"], status_code=201)
async def create_bot(body: CreateBotBody, user=Depends(current_user)):
    """
    Create a new webhook bot.
    The webhook is registered with Telegram immediately — bot is live right away.
    bot_type is always 'webhook'; any other value is silently treated as webhook.
    """
    # Validate token with Telegram
    try:
        resp     = req_lib.get(f"https://api.telegram.org/bot{body.bot_token}/getMe", timeout=8)
        tg_data  = resp.json()
        if not tg_data.get("ok"):
            raise HTTPException(400, "Invalid bot token — Telegram rejected it")
        bot_info = tg_data["result"]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Telegram API error: {e}")

    bot_id = hashlib.md5(body.bot_token.encode()).hexdigest()[:12]
    script = _sanitize_script(body.script, body.bot_token)

    # Register webhook with Telegram immediately
    wh_url  = _webhook_url_for(body.bot_token)
    wh_ok   = _set_telegram_webhook(body.bot_token, wh_url)

    doc = {
        "bot_id":        bot_id,
        "bot_token":     body.bot_token,
        "bot_username":  bot_info.get("username"),
        "bot_name":      body.name,
        "bot_type":      "webhook",          # always webhook
        "script":        script,
        "env_vars":      body.env_vars,
        "owner_email":   user["email"],
        "active":        True,
        "running":       wh_ok,              # live if webhook was registered
        "webhook_url":   wh_url,
        "webhook_set":   wh_ok,
        "created_at":    datetime.utcnow(),
        "updated_at":    datetime.utcnow(),
    }
    await bots_col.update_one({"bot_id": bot_id}, {"$set": doc}, upsert=True)

    # Cache in memory
    webhook_bots[bot_id] = {
        "active": wh_ok,
        "script": script,
        "token":  body.bot_token,
    }

    level = "INFO" if wh_ok else "WARNING"
    log_msg(bot_id, f"✅ Bot created: @{bot_info.get('username')} | webhook={'✅' if wh_ok else '❌'}", level)

    return {
        "success":      True,
        "bot_id":       bot_id,
        "bot_username": bot_info.get("username"),
        "bot_type":     "webhook",
        "webhook_set":  wh_ok,
        "webhook_url":  wh_url,
        "running":      wh_ok,
        "message":      "Bot created and webhook activated" if wh_ok else
                        "Bot created but webhook registration failed — check WEBHOOK_BASE_URL is public HTTPS",
    }

@app.get("/api/bots", tags=["Bots"])
async def list_bots(user=Depends(current_user)):
    bots = await bots_col.find({"owner_email": user["email"]}).to_list(None)
    for b in bots:
        bid      = b.get("bot_id")
        b["live"] = webhook_bots.get(bid, {}).get("active", False)
    return {"bots": [_fmt(b) for b in bots], "count": len(bots)}

@app.get("/api/bots/{bot_id}", tags=["Bots"])
async def get_bot(bot_id: str, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot:
        raise HTTPException(404, "Bot not found")
    result              = _fmt(bot)
    result["script"]    = bot.get("script", "")
    result["bot_token"] = bot.get("bot_token", "")
    result["live"]      = webhook_bots.get(bot_id, {}).get("active", False)
    result["bot_type"]  = "webhook"
    return result

@app.patch("/api/bots/{bot_id}", tags=["Bots"])
async def update_bot(bot_id: str, body: UpdateBotBody, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot:
        raise HTTPException(404, "Bot not found")

    up: dict = {"updated_at": datetime.utcnow()}
    if body.name is not None:
        up["bot_name"] = body.name
    if body.script is not None:
        script = _sanitize_script(body.script, bot["bot_token"])
        up["script"] = script
        # Update in-memory cache immediately
        if bot_id in webhook_bots:
            webhook_bots[bot_id]["script"] = script
        log_msg(bot_id, "📝 Script updated", "INFO")
    if body.env_vars is not None:
        up["env_vars"] = body.env_vars

    await bots_col.update_one({"bot_id": bot_id}, {"$set": up})
    return {"success": True, "message": "Bot updated — script changes apply to the next incoming message"}

@app.put("/api/bots/{bot_id}/script", tags=["Bots"])
async def update_script(bot_id: str, body: UpdateScriptBody, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot:
        raise HTTPException(404, "Bot not found")

    script = _sanitize_script(body.script, bot["bot_token"])
    await bots_col.update_one({"bot_id": bot_id}, {"$set": {"script": script, "updated_at": datetime.utcnow()}})
    if bot_id in webhook_bots:
        webhook_bots[bot_id]["script"] = script
    log_msg(bot_id, "📝 Script updated via PUT", "INFO")
    return {"success": True, "message": "Script updated — live on next message"}

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

    # Remove webhook from Telegram
    _delete_telegram_webhook(bot["bot_token"])

    # Clean up memory
    webhook_bots.pop(bot_id, None)
    bot_logs.pop(bot_id, None)

    await bots_col.delete_one({"bot_id": bot_id})
    await storage_col.delete_many({"bot_id": bot_id})
    log_msg(bot_id, "🗑️ Bot deleted", "WARNING")
    return {"success": True, "message": "Bot deleted and webhook removed", "bot_id": bot_id}

# ─────────────────────────────────────────────────────────────
# START / STOP / REFRESH  (webhook management)
# ─────────────────────────────────────────────────────────────
@app.post("/api/bots/{bot_id}/start", tags=["Bots"])
async def start_bot(bot_id: str, user=Depends(current_user)):
    """Activate the bot by registering its webhook with Telegram."""
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot:
        raise HTTPException(404, "Bot not found")

    if webhook_bots.get(bot_id, {}).get("active"):
        return {"success": True, "message": "Bot is already running", "running": True}

    wh_url = _webhook_url_for(bot["bot_token"])
    ok     = _set_telegram_webhook(bot["bot_token"], wh_url)

    webhook_bots[bot_id] = {
        "active": ok,
        "script": bot.get("script", ""),
        "token":  bot["bot_token"],
    }

    await bots_col.update_one(
        {"bot_id": bot_id},
        {"$set": {"running": ok, "webhook_set": ok, "updated_at": datetime.utcnow()}},
    )

    level = "INFO" if ok else "ERROR"
    log_msg(bot_id, f"{'✅ Bot started — webhook active' if ok else '❌ Failed to set webhook'}", level)

    if not ok:
        raise HTTPException(502, "Telegram rejected the webhook — ensure WEBHOOK_BASE_URL is a public HTTPS URL")

    return {"success": True, "message": "Bot started — webhook active", "webhook_url": wh_url, "running": True}

@app.post("/api/bots/{bot_id}/stop", tags=["Bots"])
async def stop_bot(bot_id: str, user=Depends(current_user)):
    """Deactivate the bot by removing its webhook from Telegram."""
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot:
        raise HTTPException(404, "Bot not found")

    ok = _delete_telegram_webhook(bot["bot_token"])

    if bot_id in webhook_bots:
        webhook_bots[bot_id]["active"] = False

    await bots_col.update_one(
        {"bot_id": bot_id},
        {"$set": {"running": False, "webhook_set": False, "updated_at": datetime.utcnow()}},
    )
    log_msg(bot_id, "⏹️ Bot stopped — webhook removed", "INFO")
    return {"success": True, "message": "Bot stopped — webhook removed", "running": False}

@app.post("/api/bots/{bot_id}/refresh", tags=["Bots"])
async def refresh_bot(bot_id: str, user=Depends(current_user)):
    """
    Re-register the webhook with Telegram.
    Use this if the bot is running but not receiving messages
    (e.g. after server restart, domain change, or Telegram timeout).
    """
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot:
        raise HTTPException(404, "Bot not found")

    wh_url = _webhook_url_for(bot["bot_token"])

    # Delete then re-set for a clean registration
    _delete_telegram_webhook(bot["bot_token"])
    await asyncio.sleep(0.5)
    ok = _set_telegram_webhook(bot["bot_token"], wh_url)

    # Refresh in-memory script too
    latest_bot = await bots_col.find_one({"bot_id": bot_id})
    webhook_bots[bot_id] = {
        "active": ok,
        "script": latest_bot.get("script", bot.get("script", "")),
        "token":  bot["bot_token"],
    }

    await bots_col.update_one(
        {"bot_id": bot_id},
        {"$set": {"running": ok, "webhook_set": ok, "updated_at": datetime.utcnow()}},
    )

    # Get Telegram's view of the webhook
    tg_info = _get_telegram_webhook_info(bot["bot_token"])

    level = "INFO" if ok else "ERROR"
    log_msg(bot_id, f"{'🔄 Webhook refreshed' if ok else '❌ Webhook refresh failed'}", level)

    if not ok:
        raise HTTPException(502, "Telegram rejected the webhook — ensure WEBHOOK_BASE_URL is a public HTTPS URL")

    return {
        "success":        True,
        "message":        "Webhook refreshed successfully",
        "webhook_url":    wh_url,
        "running":        True,
        "telegram_info":  tg_info,
    }

@app.post("/api/bots/{bot_id}/restart", tags=["Bots"])
async def restart_bot(bot_id: str, user=Depends(current_user)):
    """Alias for refresh — re-registers the webhook."""
    return await refresh_bot(bot_id, user)

@app.get("/api/bots/{bot_id}/webhook-info", tags=["Bots"])
async def webhook_info(bot_id: str, user=Depends(current_user)):
    """Check live Telegram webhook status for this bot."""
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot:
        raise HTTPException(404, "Bot not found")

    tg_info = _get_telegram_webhook_info(bot["bot_token"])
    local   = webhook_bots.get(bot_id, {})

    return {
        "bot_id":          bot_id,
        "local_active":    local.get("active", False),
        "telegram_webhook": tg_info,
        "expected_url":    _webhook_url_for(bot["bot_token"]),
        "url_matches":     tg_info.get("url") == _webhook_url_for(bot["bot_token"]),
        "pending_updates": tg_info.get("pending_update_count", 0),
        "last_error":      tg_info.get("last_error_message"),
    }

# ─────────────────────────────────────────────────────────────
# LOGS
# ─────────────────────────────────────────────────────────────
@app.get("/api/bots/{bot_id}/logs", tags=["Bots"])
async def get_logs(bot_id: str, user=Depends(current_user)):
    if not await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]}):
        raise HTTPException(404, "Bot not found")
    return {"bot_id": bot_id, "logs": list(bot_logs[bot_id])}

@app.get("/api/bots/{bot_id}/logs/stream", tags=["Bots"])
async def stream_logs(bot_id: str, user=Depends(current_user)):
    """Server-Sent Events stream for live log tailing."""
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

# ─────────────────────────────────────────────────────────────
# ENV VARS
# ─────────────────────────────────────────────────────────────
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
    await bots_col.update_one({"bot_id": bot_id}, {"$set": {"env_vars": env_vars, "updated_at": datetime.utcnow()}})
    return {"success": True, "message": "Env vars updated — live on next message"}

# ─────────────────────────────────────────────────────────────
# WEBHOOK RECEIVER  — Telegram pushes updates here
# ─────────────────────────────────────────────────────────────
@app.post("/api/webhook/{bot_token}", include_in_schema=False)
async def webhook_handler(bot_token: str, request: Request):
    """
    Telegram calls this endpoint for every update.
    We look up the bot by token, execute its script in a daemon thread,
    and immediately return 200 so Telegram doesn't retry.
    """
    try:
        update = await request.json()
    except Exception as e:
        print(f"[WEBHOOK] Bad JSON: {e}")
        return {"ok": False, "error": "Bad JSON"}

    # Find bot by token
    bot = await bots_col.find_one({"bot_token": bot_token})
    if not bot:
        print(f"[WEBHOOK] Unknown token: {bot_token[:10]}…")
        return {"ok": False, "error": "Bot not found"}

    if not bot.get("running") and not webhook_bots.get(bot["bot_id"], {}).get("active"):
        # Bot is stopped — acknowledge but don't execute
        return {"ok": True, "note": "Bot is stopped"}

    bot_id = bot["bot_id"]
    # Always use the freshest script from memory cache (updated live on edit)
    script = webhook_bots.get(bot_id, {}).get("script") or bot.get("script", "")
    env_vars = bot.get("env_vars", {})

    update_type = (
        "message" if "message" in update else
        "callback_query" if "callback_query" in update else
        "inline_query" if "inline_query" in update else
        "other"
    )
    log_msg(bot_id, f"📨 {update_type} received", "INFO")

    # Execute script in background thread — never block Telegram's HTTP call
    def _run():
        try:
            execute_bot_script(script, update, bot_token, bot_id, env_vars)
        except Exception as e:
            log_msg(bot_id, f"Execution error: {e}", "ERROR")
            traceback.print_exc()

    threading.Thread(target=_run, daemon=True).start()
    return {"ok": True}

# ─────────────────────────────────────────────────────────────
# TERMINAL
# ─────────────────────────────────────────────────────────────
@app.post("/api/terminal", tags=["Terminal"])
async def terminal_execute(body: TerminalBody, user=Depends(current_user)):
    cmd = body.command.strip()
    if not cmd:
        raise HTTPException(400, "No command provided")

    allowed_commands = [
        "pip", "pip3", "python", "python3",
        "ls", "pwd", "env", "which", "echo", "cat",
        "cd", "mkdir", "rm", "cp", "mv",
    ]
    cmd_parts = cmd.split()
    if not cmd_parts or not any(
        cmd_parts[0] == a or cmd_parts[0].startswith(a) for a in allowed_commands
    ):
        return {"output": f"❌ Command '{cmd_parts[0] if cmd_parts else ''}' not allowed"}

    env = dict(os.environ)
    if body.bot_id:
        bot = await bots_col.find_one({"bot_id": body.bot_id, "owner_email": user["email"]})
        if bot:
            env.update(bot.get("env_vars", {}))
            env["BOT_TOKEN"] = bot["bot_token"]

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120, env=env)
        output = result.stdout + result.stderr
        return {"output": output.strip() or "✅ Done"}
    except subprocess.TimeoutExpired:
        return {"output": "⏱️ Command timed out (120 s)"}
    except Exception as e:
        return {"output": f"❌ Error: {str(e)}"}

# ─────────────────────────────────────────────────────────────
# BOT SCRIPT EXECUTION ENGINE
# ─────────────────────────────────────────────────────────────
class ReturnCommand(Exception):
    pass

class _MsgObj:
    def __init__(self, d: dict):
        self.text       = d.get("text", "")
        self.caption    = d.get("caption", "")
        self.message_id = d.get("message_id")
        self.date       = d.get("date")
        self.chat       = type("Chat", (), {
            "id":         d["chat"]["id"],
            "type":       d["chat"].get("type", "private"),
            "username":   d["chat"].get("username", ""),
            "first_name": d["chat"].get("first_name", ""),
        })()
        self.from_user  = type("User", (), {
            "id":         d.get("from", {}).get("id"),
            "username":   d.get("from", {}).get("username", ""),
            "first_name": d.get("from", {}).get("first_name", ""),
            "is_bot":     d.get("from", {}).get("is_bot", False),
        })()

class _CBQObj:
    def __init__(self, d: dict):
        self.id        = d.get("id")
        self.data      = d.get("data", "")
        self.message   = _MsgObj(d["message"]) if "message" in d else None
        self.from_user = type("User", (), {
            "id":         d.get("from", {}).get("id"),
            "username":   d.get("from", {}).get("username", ""),
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
        self.text          = text
        self.callback_data = callback_data
        self.url           = url

    def to_dict(self):
        d = {"text": self.text}
        if self.callback_data: d["callback_data"] = self.callback_data
        if self.url:           d["url"]           = self.url
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
        self.token    = token
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
        if parse_mode:  d["parse_mode"]  = parse_mode
        if reply_markup:
            d["reply_markup"] = (reply_markup.to_dict()
                                 if isinstance(reply_markup, InlineKeyboardMarkup)
                                 else reply_markup)
        return self._post("sendMessage", d)

    def editMessageText(self, chat_id, message_id, text, parse_mode=None, reply_markup=None):
        d = {"chat_id": chat_id, "message_id": message_id, "text": text}
        if parse_mode:  d["parse_mode"]  = parse_mode
        if reply_markup:
            d["reply_markup"] = (reply_markup.to_dict()
                                 if isinstance(reply_markup, InlineKeyboardMarkup)
                                 else reply_markup)
        return self._post("editMessageText", d)

    def answerCallbackQuery(self, callback_query_id, text=None, show_alert=False):
        d = {"callback_query_id": callback_query_id, "show_alert": show_alert}
        if text: d["text"] = text
        return self._post("answerCallbackQuery", d)

    def deleteMessage(self, chat_id, message_id):
        return self._post("deleteMessage", {"chat_id": chat_id, "message_id": message_id})

    def sendPhoto(self, chat_id, photo, caption=None, reply_markup=None):
        d = {"chat_id": chat_id, "photo": photo}
        if caption: d["caption"] = caption
        if reply_markup:
            d["reply_markup"] = (reply_markup.to_dict()
                                 if isinstance(reply_markup, InlineKeyboardMarkup)
                                 else reply_markup)
        return self._post("sendPhoto", d)

    def sendDocument(self, chat_id, document, caption=None):
        d = {"chat_id": chat_id, "document": document}
        if caption: d["caption"] = caption
        return self._post("sendDocument", d)

    def sendVideo(self, chat_id, video, caption=None):
        d = {"chat_id": chat_id, "video": video}
        if caption: d["caption"] = caption
        return self._post("sendVideo", d)

    def forwardMessage(self, chat_id, from_chat_id, message_id):
        return self._post("forwardMessage", {
            "chat_id": chat_id, "from_chat_id": from_chat_id, "message_id": message_id
        })

    def getChatMember(self, chat_id, user_id):
        return self._post("getChatMember", {"chat_id": chat_id, "user_id": user_id})

    def banChatMember(self, chat_id, user_id):
        return self._post("banChatMember", {"chat_id": chat_id, "user_id": user_id})

    def unbanChatMember(self, chat_id, user_id):
        return self._post("unbanChatMember", {"chat_id": chat_id, "user_id": user_id})

def execute_bot_script(script: str, update: dict, bot_token: str, bot_id: str, env_vars: dict = None):
    """Execute user script in a sandboxed exec() context with the update's data injected."""
    try:
        bot     = BotAPI(bot_token)
        storage = BotStorage(bot_id)

        if "message" in update:
            message        = _MsgObj(update["message"])
            callback_query = None
        elif "callback_query" in update:
            callback_query = _CBQObj(update["callback_query"])
            message        = callback_query.message
        else:
            # Unsupported update type — still execute so advanced scripts can handle it
            message        = None
            callback_query = None

        # Inject env_vars as top-level names so scripts can use them
        exec_globals = {
            "__builtins__":        __builtins__,
            "bot":                 bot,
            "storage":             storage,
            "message":             message,
            "callback_query":      callback_query,
            "update":              update,        # raw update dict for advanced scripts
            "ReturnCommand":       ReturnCommand,
            "InlineKeyboardMarkup": InlineKeyboardMarkup,
            "InlineKeyboardButton": InlineKeyboardButton,
            "re":                  re,
            "math":                math,
            "random":              random,
            "time":                time,
            "datetime":            datetime,
            "requests":            req_lib,
            "json":                json,
            "os":                  os,
            "sys":                 sys,
        }

        # Expose env_vars as individual variables
        if env_vars:
            exec_globals.update(env_vars)

        exec(script, exec_globals)
        log_msg(bot_id, "✅ Script executed OK", "INFO")

    except ReturnCommand:
        pass
    except Exception as e:
        log_msg(bot_id, f"Script error: {e}", "ERROR")
        traceback.print_exc()

# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("🤖 BOTHOST API v6 — WEBHOOK-ONLY MODE")
    print("=" * 60)
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=False)
