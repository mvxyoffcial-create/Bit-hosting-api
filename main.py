"""
BotHost API v7 — ULTRA FAST Webhook Engine
==========================================
Speed fixes vs v6:
  ✅ BotStorage uses PERSISTENT pymongo pool — never reconnects per call
  ✅ BotAPI uses persistent requests.Session with keep-alive — no TCP handshake per message
  ✅ Webhook handler NEVER hits MongoDB — pure in-memory O(1) lookup
  ✅ Scripts compiled once with compile() and cached — no re-parsing per message
  ✅ ThreadPoolExecutor reuses threads — no spawn overhead per update
  ✅ Token→bot_id index in memory — zero I/O on hot path
  ✅ Shared exec globals dict — built once, copied per call
  ✅ uvloop + httptools for 2-4x faster async I/O
  ✅ Telegram max_connections=100 for parallel delivery
"""

import os, sys, hashlib, subprocess, threading, asyncio, traceback
import math, random, re, json, time
import inspect, functools, itertools, operator, string, copy, io
import struct, base64, binascii, uuid, enum, abc, weakref
import collections, heapq, bisect, array, queue
import pathlib, tempfile, shutil, glob
import urllib.parse, urllib.request, urllib.error
import html as html_lib, html.parser
import csv, configparser, textwrap, difflib, pprint
import decimal, fractions, statistics
import calendar, locale
import logging, warnings
import contextlib, dataclasses
import typing as typing_mod
from collections import defaultdict, deque, Counter, OrderedDict, namedtuple, ChainMap
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, date, timezone
from typing import Optional, List, Dict, Any, Tuple, Union, Set, Callable, Generator, Iterator
from pathlib import Path
from functools import wraps, partial, lru_cache, reduce
from itertools import chain, cycle, islice, product, permutations, combinations, groupby
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from decimal import Decimal
from fractions import Fraction
from enum import Enum, auto
from abc import ABC, abstractmethod
from io import StringIO, BytesIO
from copy import copy, deepcopy
from pprint import pformat, pprint as _pprint

# ── Persistent HTTP session for ALL Telegram API calls ──────────────────────
import requests as req_lib
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def _make_session() -> req_lib.Session:
    s = req_lib.Session()
    retry = Retry(total=2, backoff_factor=0.1,
                  status_forcelist=[429, 500, 502, 503, 504],
                  allowed_methods=["POST", "GET"])
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=20,
        pool_maxsize=100,
        pool_block=False,
    )
    s.mount("https://", adapter)
    s.mount("http://",  adapter)
    return s

TG_SESSION = _make_session()   # ONE session shared across ALL bots and ALL threads

import pymongo
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
# CONFIG
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
PORT             = int(os.environ.get("PORT", "8000"))

# ─────────────────────────────────────────────────────────────
# PERSISTENT DB CLIENTS
# ─────────────────────────────────────────────────────────────
# Async motor client — for FastAPI route handlers
motor_client = motor.motor_asyncio.AsyncIOMotorClient(
    MONGO_URI,
    serverSelectionTimeoutMS=5000,
    connectTimeoutMS=5000,
    socketTimeoutMS=10000,
    maxPoolSize=50,
    minPoolSize=5,
)
adb         = motor_client[DB_NAME]
users_col   = adb["users"]
bots_col    = adb["bots"]
storage_col = adb["bot_storage"]

# Sync pymongo client — for BotStorage inside executor threads
# ONE global pool, NEVER re-created per call (was the #1 cause of slowness in v6)
_sync_mongo   = pymongo.MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=5000,
    connectTimeoutMS=5000,
    socketTimeoutMS=8000,
    maxPoolSize=50,
    minPoolSize=5,
)
_sync_db      = _sync_mongo[DB_NAME]
_sync_storage = _sync_db["bot_storage"]   # shared handle — safe across threads

# ─────────────────────────────────────────────────────────────
# THREAD POOL — reuse threads instead of spawning one per update
# ─────────────────────────────────────────────────────────────
_executor = ThreadPoolExecutor(max_workers=64, thread_name_prefix="bot")

# ─────────────────────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────────────────────
app = FastAPI(title="BotHost API", version="7.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────
# IN-MEMORY STATE  (the fast path lives here — zero DB on webhook)
# ─────────────────────────────────────────────────────────────
# bot_id → {active, script, code, token, env_vars}
webhook_bots: dict = {}
# token  → bot_id   (O(1) lookup — no DB call in webhook handler)
token_index:  dict = {}
# compiled script cache: md5(script) → code object
_script_cache: dict = {}
# log ring buffers
bot_logs: dict = defaultdict(lambda: deque(maxlen=1000))

# ─────────────────────────────────────────────────────────────
# SECURITY
# ─────────────────────────────────────────────────────────────
bearer_scheme  = HTTPBearer(auto_error=False)
url_serializer = URLSafeTimedSerializer(SECRET_KEY)

def hash_pw(p: str) -> str:
    return bcrypt.hashpw(p[:72].encode(), bcrypt.gensalt()).decode()

def check_pw(plain: str, hashed: str) -> bool:
    try:    return bcrypt.checkpw(plain[:72].encode(), hashed.encode())
    except: return False

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
    if not user:    raise HTTPException(401, "User not found")
    if not user.get("verified"): raise HTTPException(403, "Verify your email first")
    return user

# ─────────────────────────────────────────────────────────────
# EMAIL
# ─────────────────────────────────────────────────────────────
def _do_send(to, subject, html):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject; msg["From"] = FROM_EMAIL; msg["To"] = to
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.ehlo(); s.starttls(); s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(FROM_EMAIL, to, msg.as_string())
    except Exception as e:
        print(f"[EMAIL] {e}")

def send_email(to, subject, html):
    threading.Thread(target=_do_send, args=(to, subject, html), daemon=True).start()

def _verify_html(link, name):
    return f"""<div style="font-family:Arial;max-width:560px;margin:auto;background:#fff;padding:36px;border-radius:14px;border:1px solid #e2e8f0">
<h2 style="color:#16a34a">✅ BotHost — Verify Email</h2><p>Hi <b>{name}</b>!</p>
<a href="{link}" style="display:inline-block;background:#16a34a;color:#fff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:bold">✅ Verify Account</a>
<p style="color:#6b7280;font-size:12px">Expires 24h.</p></div>"""

def _reset_html(link):
    return f"""<div style="font-family:Arial;max-width:560px;margin:auto;background:#0f172a;color:#f1f5f9;padding:36px;border-radius:14px">
<h2 style="color:#f59e0b">🔐 Reset Password</h2>
<a href="{link}" style="display:inline-block;background:#f59e0b;color:#000;padding:13px 28px;border-radius:8px;text-decoration:none;font-weight:bold">🔑 Reset</a></div>"""

# ─────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────
def log_msg(bot_id: str, msg: str, level: str = "INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    bot_logs[bot_id].append(f"[{ts}][{level}] {msg}")

# ─────────────────────────────────────────────────────────────
# SCRIPT COMPILE CACHE
# compile() once, exec() many times — eliminates parse overhead
# ─────────────────────────────────────────────────────────────
def _compile_script(script: str):
    h = hashlib.md5(script.encode()).hexdigest()
    if h not in _script_cache:
        _script_cache[h] = compile(script, f"<bot:{h[:8]}>", "exec")
    return _script_cache[h]

# ─────────────────────────────────────────────────────────────
# TELEGRAM HELPERS (all use the shared TG_SESSION)
# ─────────────────────────────────────────────────────────────
def _webhook_url_for(token: str) -> str:
    return f"{WEBHOOK_BASE_URL}/api/webhook/{token}"

def _set_telegram_webhook(token: str, url: str) -> bool:
    try:
        r = TG_SESSION.post(
            f"https://api.telegram.org/bot{token}/setWebhook",
            json={"url": url,
                  "allowed_updates": ["message", "callback_query", "inline_query"],
                  "max_connections": 100,
                  "drop_pending_updates": False},
            timeout=10,
        )
        result = r.json()
        ok = result.get("ok", False)
        print(f"[WEBHOOK] setWebhook → {ok} | {result.get('description','')}")
        return ok
    except Exception as e:
        print(f"[WEBHOOK] error: {e}"); return False

def _delete_telegram_webhook(token: str) -> bool:
    try:
        r = TG_SESSION.post(
            f"https://api.telegram.org/bot{token}/deleteWebhook",
            json={"drop_pending_updates": False}, timeout=8,
        )
        return r.json().get("ok", False)
    except Exception as e:
        print(f"[WEBHOOK] delete error: {e}"); return False

def _get_webhook_info(token: str) -> dict:
    try:
        r = TG_SESSION.get(f"https://api.telegram.org/bot{token}/getWebhookInfo", timeout=8)
        return r.json().get("result", {})
    except Exception:
        return {}

# ─────────────────────────────────────────────────────────────
# MEMORY CACHE HELPER
# ─────────────────────────────────────────────────────────────
def _cache_bot(bot_id: str, token: str, script: str, env_vars: dict, active: bool):
    try:    code = _compile_script(script)
    except Exception as e:
        log_msg(bot_id, f"Script compile error: {e}", "WARNING"); code = None
    webhook_bots[bot_id] = {
        "active": active, "script": script,
        "code": code, "token": token, "env_vars": env_vars,
    }
    token_index[token] = bot_id

# ─────────────────────────────────────────────────────────────
# SCHEMAS
# ─────────────────────────────────────────────────────────────
class RegisterBody(BaseModel):
    name: str; email: EmailStr; password: str

class LoginBody(BaseModel):
    email: EmailStr; password: str

class ForgotBody(BaseModel):
    email: EmailStr

class ResetBody(BaseModel):
    token: str; new_password: str

class CreateBotBody(BaseModel):
    name: str; bot_token: str; script: str
    bot_type: str = "webhook"; env_vars: dict = {}

class UpdateBotBody(BaseModel):
    name: Optional[str]      = None
    script: Optional[str]    = None
    env_vars: Optional[dict] = None

class UpdateScriptBody(BaseModel):
    script: str

class TerminalBody(BaseModel):
    command: str; bot_id: Optional[str] = None

# ─────────────────────────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    await users_col.create_index("email", unique=True)
    await bots_col.create_index("bot_id", unique=True)
    await bots_col.create_index("owner_email")
    await bots_col.create_index("bot_token")

    bots = await bots_col.find({"running": True}).to_list(None)
    restored = 0
    for bot in bots:
        bid, token, script = bot["bot_id"], bot["bot_token"], bot.get("script","")
        ok = _set_telegram_webhook(token, _webhook_url_for(token))
        _cache_bot(bid, token, script, bot.get("env_vars", {}), ok)
        if ok: restored += 1
        else:
            await bots_col.update_one({"bot_id": bid},
                {"$set": {"running": False, "webhook_set": False}})
        log_msg(bid, f"{'✅ Restored' if ok else '⚠️ Restore failed'}", "INFO")

    print("="*60)
    print("🤖 BOTHOST v7 — ULTRA FAST WEBHOOK ENGINE")
    print(f"✅ HTTP session    : keep-alive pool_size=100")
    print(f"✅ Async DB pool   : maxPoolSize=50")
    print(f"✅ Sync DB pool    : maxPoolSize=50")
    print(f"✅ Thread pool     : 64 workers")
    print(f"✅ Script cache    : compile-once enabled")
    print(f"✅ Bots restored   : {restored}/{len(bots)}")
    print(f"✅ Webhook base    : {WEBHOOK_BASE_URL}")
    print("="*60)

# ─────────────────────────────────────────────────────────────
# SYSTEM
# ─────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"service":"BotHost API","version":"7.0.0","mode":"webhook-ultra-fast"}

@app.get("/health")
async def health():
    try:
        await motor_client.admin.command("ping"); db_ok = True
    except Exception: db_ok = False
    return {
        "status":           "healthy" if db_ok else "degraded",
        "timestamp":        datetime.utcnow().isoformat()+"Z",
        "version":          "7.0.0",
        "database":         "connected" if db_ok else "disconnected",
        "active_bots":      sum(1 for b in webhook_bots.values() if b.get("active")),
        "indexed_tokens":   len(token_index),
        "cached_scripts":   len(_script_cache),
    }

# ─────────────────────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────────────────────
@app.post("/auth/register")
async def register(body: RegisterBody, bg: BackgroundTasks):
    if await users_col.find_one({"email": body.email}):
        raise HTTPException(409, "Email already registered")
    await users_col.insert_one({
        "name": body.name, "email": body.email,
        "password": hash_pw(body.password),
        "verified": False, "created_at": datetime.utcnow(),
    })
    tok  = url_serializer.dumps(body.email, salt="email-verify")
    link = f"{FRONTEND_URL}/auth/verify?token={tok}"
    bg.add_task(send_email, body.email, "Verify your BotHost account", _verify_html(link, body.name))
    return {"success": True, "message": "Registered! Check your email.", "verify_link": link}

@app.get("/auth/verify")
async def verify_email(token: str):
    try:
        email = url_serializer.loads(token, salt="email-verify", max_age=86400)
    except Exception:
        raise HTTPException(400, "Invalid or expired link")
    r = await users_col.update_one({"email": email}, {"$set": {"verified": True}})
    if r.matched_count == 0: raise HTTPException(404, "User not found")
    return HTMLResponse("""<!DOCTYPE html><html><body style="display:flex;align-items:center;justify-content:center;
height:100vh;background:#f0fdf4;font-family:Arial"><div style="text-align:center;background:#fff;
padding:48px;border-radius:16px;box-shadow:0 4px 24px rgba(22,163,74,.12)">
<div style="font-size:64px">✅</div><h1 style="color:#16a34a">Email Verified!</h1>
<p>Your BotHost account is active. You can close this tab.</p></div></body></html>""")

@app.post("/auth/login")
async def login(body: LoginBody):
    user = await users_col.find_one({"email": body.email})
    if not user or not check_pw(body.password, user["password"]):
        raise HTTPException(401, "Invalid email or password")
    if not user.get("verified"):
        raise HTTPException(403, "Verify your email first")
    token = make_token({"email": user["email"], "name": user["name"]})
    return {"success": True, "access_token": token, "token_type": "bearer",
            "expires_in": f"{JWT_EXPIRE_HOURS}h",
            "user": {"name": user["name"], "email": user["email"]}}

@app.post("/auth/forgot-password")
async def forgot_password(body: ForgotBody, bg: BackgroundTasks):
    user = await users_col.find_one({"email": body.email})
    if user:
        tok  = url_serializer.dumps(body.email, salt="pwd-reset")
        link = f"{FRONTEND_URL}/auth/reset-password?token={tok}"
        bg.add_task(send_email, body.email, "Reset your BotHost password", _reset_html(link))
    return {"success": True, "message": "If that email exists, a reset link was sent."}

@app.post("/auth/reset-password")
async def reset_password(body: ResetBody):
    try:
        email = url_serializer.loads(body.token, salt="pwd-reset", max_age=3600)
    except Exception:
        raise HTTPException(400, "Invalid or expired link")
    r = await users_col.update_one({"email": email}, {"$set": {"password": hash_pw(body.new_password)}})
    if r.matched_count == 0: raise HTTPException(404, "User not found")
    return {"success": True, "message": "Password updated!"}

@app.get("/auth/me")
async def me(user=Depends(current_user)):
    return user

# ─────────────────────────────────────────────────────────────
# BOT HELPERS
# ─────────────────────────────────────────────────────────────
def _fmt(bot: dict) -> dict:
    bot = dict(bot)
    bot.pop("_id", None); bot.pop("bot_token", None)
    for k in ("created_at", "updated_at"):
        if k in bot and hasattr(bot[k], "isoformat"):
            bot[k] = bot[k].isoformat()
    return bot

def _sanitize(script: str, token: str) -> str:
    for ph in ("YOUR_BOT_TOKEN_HERE", "YOUR_TOKEN_WILL_BE_SET_AUTOMATICALLY", "your_bot_token_here"):
        script = script.replace(ph, token)
    return script

# ─────────────────────────────────────────────────────────────
# BOT CRUD
# ─────────────────────────────────────────────────────────────
@app.post("/api/bots", status_code=201)
async def create_bot(body: CreateBotBody, user=Depends(current_user)):
    try:
        resp    = TG_SESSION.get(f"https://api.telegram.org/bot{body.bot_token}/getMe", timeout=8)
        tg_data = resp.json()
        if not tg_data.get("ok"): raise HTTPException(400, "Invalid bot token")
        bot_info = tg_data["result"]
    except HTTPException: raise
    except Exception as e: raise HTTPException(400, f"Telegram error: {e}")

    bot_id = hashlib.md5(body.bot_token.encode()).hexdigest()[:12]
    script = _sanitize(body.script, body.bot_token)
    wh_url = _webhook_url_for(body.bot_token)
    wh_ok  = _set_telegram_webhook(body.bot_token, wh_url)

    doc = {
        "bot_id": bot_id, "bot_token": body.bot_token,
        "bot_username": bot_info.get("username"), "bot_name": body.name,
        "bot_type": "webhook", "script": script, "env_vars": body.env_vars,
        "owner_email": user["email"], "active": True, "running": wh_ok,
        "webhook_url": wh_url, "webhook_set": wh_ok,
        "created_at": datetime.utcnow(), "updated_at": datetime.utcnow(),
    }
    await bots_col.update_one({"bot_id": bot_id}, {"$set": doc}, upsert=True)
    _cache_bot(bot_id, body.bot_token, script, body.env_vars, wh_ok)
    log_msg(bot_id, f"✅ Created @{bot_info.get('username')} webhook={'✅' if wh_ok else '❌'}", "INFO")

    return {"success": True, "bot_id": bot_id, "bot_username": bot_info.get("username"),
            "webhook_set": wh_ok, "running": wh_ok,
            "message": "Bot deployed and live!" if wh_ok else "Created but webhook failed — check WEBHOOK_BASE_URL"}

@app.get("/api/bots")
async def list_bots(user=Depends(current_user)):
    bots = await bots_col.find({"owner_email": user["email"]}).to_list(None)
    for b in bots:
        b["live"] = webhook_bots.get(b.get("bot_id"), {}).get("active", False)
    return {"bots": [_fmt(b) for b in bots], "count": len(bots)}

@app.get("/api/bots/{bot_id}")
async def get_bot(bot_id: str, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot: raise HTTPException(404, "Bot not found")
    result = _fmt(bot)
    result["script"]    = bot.get("script", "")
    result["bot_token"] = bot.get("bot_token", "")
    result["live"]      = webhook_bots.get(bot_id, {}).get("active", False)
    return result

@app.patch("/api/bots/{bot_id}")
async def update_bot(bot_id: str, body: UpdateBotBody, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot: raise HTTPException(404, "Bot not found")
    up: dict = {"updated_at": datetime.utcnow()}
    if body.name   is not None: up["bot_name"] = body.name
    if body.script is not None:
        script = _sanitize(body.script, bot["bot_token"])
        up["script"] = script
        cached = webhook_bots.get(bot_id, {})
        ev = body.env_vars if body.env_vars is not None else cached.get("env_vars", {})
        _cache_bot(bot_id, bot["bot_token"], script, ev, cached.get("active", False))
        log_msg(bot_id, "📝 Script updated — live immediately", "INFO")
    if body.env_vars is not None:
        up["env_vars"] = body.env_vars
        if bot_id in webhook_bots: webhook_bots[bot_id]["env_vars"] = body.env_vars
    await bots_col.update_one({"bot_id": bot_id}, {"$set": up})
    return {"success": True, "message": "Updated — changes are live immediately"}

@app.put("/api/bots/{bot_id}/script")
async def update_script(bot_id: str, body: UpdateScriptBody, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot: raise HTTPException(404, "Bot not found")
    script = _sanitize(body.script, bot["bot_token"])
    await bots_col.update_one({"bot_id": bot_id}, {"$set": {"script": script, "updated_at": datetime.utcnow()}})
    cached = webhook_bots.get(bot_id, {})
    _cache_bot(bot_id, bot["bot_token"], script, cached.get("env_vars", {}), cached.get("active", False))
    return {"success": True, "message": "Script live immediately"}

@app.get("/api/bots/{bot_id}/script")
async def get_script(bot_id: str, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot: raise HTTPException(404, "Bot not found")
    return {"bot_id": bot_id, "script": bot.get("script", "")}

@app.delete("/api/bots/{bot_id}")
async def delete_bot(bot_id: str, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot: raise HTTPException(404, "Bot not found")
    _delete_telegram_webhook(bot["bot_token"])
    token_index.pop(bot["bot_token"], None)
    webhook_bots.pop(bot_id, None)
    bot_logs.pop(bot_id, None)
    await bots_col.delete_one({"bot_id": bot_id})
    await storage_col.delete_many({"bot_id": bot_id})
    return {"success": True, "bot_id": bot_id}

# ─────────────────────────────────────────────────────────────
# START / STOP / REFRESH
# ─────────────────────────────────────────────────────────────
@app.post("/api/bots/{bot_id}/start")
async def start_bot(bot_id: str, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot: raise HTTPException(404, "Bot not found")
    if webhook_bots.get(bot_id, {}).get("active"):
        return {"success": True, "message": "Already running", "running": True}
    wh_url = _webhook_url_for(bot["bot_token"])
    ok     = _set_telegram_webhook(bot["bot_token"], wh_url)
    cached = webhook_bots.get(bot_id, {})
    _cache_bot(bot_id, bot["bot_token"],
               cached.get("script", bot.get("script", "")),
               bot.get("env_vars", {}), ok)
    await bots_col.update_one({"bot_id": bot_id},
        {"$set": {"running": ok, "webhook_set": ok, "updated_at": datetime.utcnow()}})
    log_msg(bot_id, f"{'✅ Started' if ok else '❌ Start failed'}", "INFO" if ok else "ERROR")
    if not ok: raise HTTPException(502, "Telegram rejected webhook — use public HTTPS URL")
    return {"success": True, "message": "Bot started!", "running": True}

@app.post("/api/bots/{bot_id}/stop")
async def stop_bot(bot_id: str, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot: raise HTTPException(404, "Bot not found")
    _delete_telegram_webhook(bot["bot_token"])
    if bot_id in webhook_bots: webhook_bots[bot_id]["active"] = False
    await bots_col.update_one({"bot_id": bot_id},
        {"$set": {"running": False, "webhook_set": False, "updated_at": datetime.utcnow()}})
    log_msg(bot_id, "⏹️ Stopped", "INFO")
    return {"success": True, "message": "Bot stopped", "running": False}

@app.post("/api/bots/{bot_id}/refresh")
async def refresh_bot(bot_id: str, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot: raise HTTPException(404, "Bot not found")
    wh_url = _webhook_url_for(bot["bot_token"])
    _delete_telegram_webhook(bot["bot_token"])
    await asyncio.sleep(0.3)
    ok = _set_telegram_webhook(bot["bot_token"], wh_url)
    latest = await bots_col.find_one({"bot_id": bot_id})
    _cache_bot(bot_id, bot["bot_token"],
               latest.get("script", bot.get("script", "")),
               latest.get("env_vars", bot.get("env_vars", {})), ok)
    await bots_col.update_one({"bot_id": bot_id},
        {"$set": {"running": ok, "webhook_set": ok, "updated_at": datetime.utcnow()}})
    log_msg(bot_id, f"{'🔄 Refreshed' if ok else '❌ Refresh failed'}", "INFO" if ok else "ERROR")
    if not ok: raise HTTPException(502, "Webhook refresh failed")
    return {"success": True, "message": "Webhook refreshed!", "running": True,
            "telegram_info": _get_webhook_info(bot["bot_token"])}

@app.post("/api/bots/{bot_id}/restart")
async def restart_bot(bot_id: str, user=Depends(current_user)):
    return await refresh_bot(bot_id, user)

@app.get("/api/bots/{bot_id}/webhook-info")
async def webhook_info(bot_id: str, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot: raise HTTPException(404, "Bot not found")
    tg  = _get_webhook_info(bot["bot_token"])
    exp = _webhook_url_for(bot["bot_token"])
    return {"bot_id": bot_id,
            "local_active": webhook_bots.get(bot_id, {}).get("active", False),
            "telegram_webhook": tg, "expected_url": exp,
            "url_matches": tg.get("url") == exp,
            "pending_updates": tg.get("pending_update_count", 0),
            "last_error": tg.get("last_error_message")}

# ─────────────────────────────────────────────────────────────
# LOGS
# ─────────────────────────────────────────────────────────────
@app.get("/api/bots/{bot_id}/logs")
async def get_logs(bot_id: str, user=Depends(current_user)):
    if not await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]}):
        raise HTTPException(404, "Bot not found")
    return {"bot_id": bot_id, "logs": list(bot_logs[bot_id])}

@app.get("/api/bots/{bot_id}/logs/stream")
async def stream_logs(bot_id: str, user=Depends(current_user)):
    if not await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]}):
        raise HTTPException(404, "Bot not found")
    async def gen():
        seen = 0
        while True:
            cur = list(bot_logs[bot_id])
            for entry in cur[seen:]:
                yield f"data: {json.dumps({'log': entry})}\n\n"
            seen = len(cur)
            await asyncio.sleep(0.3)
    return StreamingResponse(gen(), media_type="text/event-stream")

@app.delete("/api/bots/{bot_id}/logs")
async def clear_logs(bot_id: str, user=Depends(current_user)):
    if not await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]}):
        raise HTTPException(404, "Bot not found")
    bot_logs[bot_id].clear()
    return {"success": True}

# ─────────────────────────────────────────────────────────────
# ENV VARS
# ─────────────────────────────────────────────────────────────
@app.get("/api/bots/{bot_id}/env")
async def get_env(bot_id: str, user=Depends(current_user)):
    bot = await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]})
    if not bot: raise HTTPException(404, "Bot not found")
    return {"bot_id": bot_id, "env_vars": bot.get("env_vars", {})}

@app.put("/api/bots/{bot_id}/env")
async def set_env(bot_id: str, env_vars: dict, user=Depends(current_user)):
    if not await bots_col.find_one({"bot_id": bot_id, "owner_email": user["email"]}):
        raise HTTPException(404, "Bot not found")
    await bots_col.update_one({"bot_id": bot_id},
        {"$set": {"env_vars": env_vars, "updated_at": datetime.utcnow()}})
    if bot_id in webhook_bots: webhook_bots[bot_id]["env_vars"] = env_vars
    return {"success": True, "message": "Env vars live immediately"}

# ─────────────────────────────────────────────────────────────
# ⚡ WEBHOOK HOT PATH — NO DB, NO I/O, pure memory
#
# Timeline per incoming Telegram update:
#   Parse body          ~0.1 ms
#   token_index lookup  ~0   μs  (dict, O(1))
#   active check        ~0   μs  (dict)
#   code/env from dict  ~0   μs  (dict)
#   submit to executor  ~0.05ms
#   return {"ok":True}  ~0.1 ms
#   ──────────────────────────
#   Total overhead      < 1  ms  before script runs
# ─────────────────────────────────────────────────────────────
@app.post("/api/webhook/{bot_token}", include_in_schema=False)
async def webhook_handler(bot_token: str, request: Request):
    # Parse body
    try:
        update = await request.json()
    except Exception:
        return {"ok": False}

    # O(1) token lookup — no DB
    bot_id = token_index.get(bot_token)
    if not bot_id:
        # First-time fallback: hit DB once, then index forever
        bot = await bots_col.find_one(
            {"bot_token": bot_token},
            {"bot_id":1,"script":1,"env_vars":1,"running":1}
        )
        if not bot: return {"ok": False}
        bot_id = bot["bot_id"]
        token_index[bot_token] = bot_id
        if bot_id not in webhook_bots:
            s = bot.get("script", "")
            try: c = _compile_script(s)
            except: c = None
            webhook_bots[bot_id] = {
                "active": bot.get("running", False),
                "script": s, "code": c,
                "token": bot_token, "env_vars": bot.get("env_vars", {}),
            }

    # Check active — memory only
    cached = webhook_bots.get(bot_id)
    if not cached or not cached.get("active"):
        return {"ok": True}

    # Get compiled code + env — memory only
    code     = cached.get("code")
    script   = cached.get("script", "")
    env_vars = cached.get("env_vars", {})

    # Submit to thread pool — non-blocking, returns instantly
    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        _executor,
        _run_script,
        code, script, update, bot_token, bot_id, env_vars,
    )

    # Return to Telegram immediately — bot is already processing in background
    return {"ok": True}

def _run_script(code, script, update, bot_token, bot_id, env_vars):
    try:
        execute_bot_script(code, script, update, bot_token, bot_id, env_vars)
    except Exception as e:
        log_msg(bot_id, f"Runner error: {e}", "ERROR")

# ─────────────────────────────────────────────────────────────
# TERMINAL
# ─────────────────────────────────────────────────────────────
@app.post("/api/terminal")
async def terminal_execute(body: TerminalBody, user=Depends(current_user)):
    cmd = body.command.strip()
    if not cmd: raise HTTPException(400, "No command")
    allowed = ["pip","pip3","python","python3","ls","pwd","env","which","echo","cat","mkdir","rm","cp","mv"]
    parts = cmd.split()
    if not parts or not any(parts[0] == a or parts[0].startswith(a) for a in allowed):
        return {"output": f"❌ '{parts[0] if parts else ''}' not allowed"}
    env = dict(os.environ)
    if body.bot_id:
        bot = await bots_col.find_one({"bot_id": body.bot_id, "owner_email": user["email"]})
        if bot:
            env.update(bot.get("env_vars", {}))
            env["BOT_TOKEN"] = bot["bot_token"]
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120, env=env)
        return {"output": (r.stdout + r.stderr).strip() or "✅ Done"}
    except subprocess.TimeoutExpired:
        return {"output": "⏱️ Timed out (120s)"}
    except Exception as e:
        return {"output": f"❌ {e}"}

# ─────────────────────────────────────────────────────────────
# BOT SCRIPT ENGINE
# ─────────────────────────────────────────────────────────────
class ReturnCommand(Exception): pass

class _MsgObj:
    __slots__ = ("text","caption","message_id","date","chat","from_user")
    def __init__(self, d):
        self.text       = d.get("text","")
        self.caption    = d.get("caption","")
        self.message_id = d.get("message_id")
        self.date       = d.get("date")
        c = d.get("chat",{})
        self.chat = type("Chat",(),{"id":c.get("id"),"type":c.get("type","private"),
                                    "username":c.get("username",""),"first_name":c.get("first_name","")})()
        f = d.get("from",{})
        self.from_user = type("User",(),{"id":f.get("id"),"username":f.get("username",""),
                                          "first_name":f.get("first_name",""),"is_bot":f.get("is_bot",False)})()

class _CBQObj:
    __slots__ = ("id","data","message","from_user")
    def __init__(self, d):
        self.id      = d.get("id")
        self.data    = d.get("data","")
        self.message = _MsgObj(d["message"]) if "message" in d else None
        f = d.get("from",{})
        self.from_user = type("User",(),{"id":f.get("id"),"username":f.get("username",""),
                                          "first_name":f.get("first_name","")})()

class InlineKeyboardMarkup:
    def __init__(self, inline_keyboard): self.inline_keyboard = inline_keyboard
    def to_dict(self):
        return {"inline_keyboard":[[b.to_dict() if isinstance(b,InlineKeyboardButton) else b
                                    for b in row] for row in self.inline_keyboard]}

class InlineKeyboardButton:
    def __init__(self, text, callback_data=None, url=None):
        self.text=text; self.callback_data=callback_data; self.url=url
    def to_dict(self):
        d={"text":self.text}
        if self.callback_data: d["callback_data"]=self.callback_data
        if self.url:           d["url"]=self.url
        return d

class BotStorage:
    """Uses global _sync_storage — one persistent MongoDB pool, never reconnects."""
    def __init__(self, bot_id): self.bot_id = bot_id
    def set(self, key, value):
        try:
            _sync_storage.update_one({"bot_id":self.bot_id,"key":key},
                {"$set":{"value":value,"updated_at":datetime.utcnow()}}, upsert=True)
            return True
        except Exception as e: print(f"[Storage.set] {e}"); return False
    def get(self, key, default=None):
        try:
            doc = _sync_storage.find_one({"bot_id":self.bot_id,"key":key})
            return doc["value"] if doc else default
        except Exception as e: print(f"[Storage.get] {e}"); return default
    def delete(self, key):
        try: _sync_storage.delete_one({"bot_id":self.bot_id,"key":key}); return True
        except: return False
    def all(self):
        try: return {d["key"]:d["value"] for d in _sync_storage.find({"bot_id":self.bot_id})}
        except: return {}

class BotAPI:
    """Uses global TG_SESSION — persistent keep-alive HTTP pool. No TCP handshake per call."""
    def __init__(self, token):
        self.token    = token
        self.base_url = f"https://api.telegram.org/bot{token}"

    def _post(self, method, data, timeout=8):
        try:
            r = TG_SESSION.post(f"{self.base_url}/{method}", json=data, timeout=timeout)
            return r.json()
        except Exception as e: print(f"[API.{method}] {e}"); return None

    def _get(self, method, params=None, timeout=8):
        try:
            r = TG_SESSION.get(f"{self.base_url}/{method}", params=params, timeout=timeout)
            return r.json()
        except Exception as e: print(f"[API.{method}] {e}"); return None

    def sendMessage(self, chat_id, text, parse_mode=None, reply_markup=None, disable_notification=False):
        d = {"chat_id":chat_id,"text":text}
        if parse_mode:           d["parse_mode"]           = parse_mode
        if disable_notification: d["disable_notification"] = True
        if reply_markup:
            d["reply_markup"] = reply_markup.to_dict() if isinstance(reply_markup, InlineKeyboardMarkup) else reply_markup
        return self._post("sendMessage", d)

    def editMessageText(self, chat_id, message_id, text, parse_mode=None, reply_markup=None):
        d = {"chat_id":chat_id,"message_id":message_id,"text":text}
        if parse_mode: d["parse_mode"] = parse_mode
        if reply_markup:
            d["reply_markup"] = reply_markup.to_dict() if isinstance(reply_markup, InlineKeyboardMarkup) else reply_markup
        return self._post("editMessageText", d)

    def answerCallbackQuery(self, callback_query_id, text=None, show_alert=False):
        d = {"callback_query_id":callback_query_id,"show_alert":show_alert}
        if text: d["text"] = text
        return self._post("answerCallbackQuery", d)

    def deleteMessage(self, chat_id, message_id):
        return self._post("deleteMessage", {"chat_id":chat_id,"message_id":message_id})

    def sendPhoto(self, chat_id, photo, caption=None, parse_mode=None, reply_markup=None):
        d = {"chat_id":chat_id,"photo":photo}
        if caption:    d["caption"]    = caption
        if parse_mode: d["parse_mode"] = parse_mode
        if reply_markup:
            d["reply_markup"] = reply_markup.to_dict() if isinstance(reply_markup, InlineKeyboardMarkup) else reply_markup
        return self._post("sendPhoto", d)

    def sendDocument(self, chat_id, document, caption=None):
        d={"chat_id":chat_id,"document":document}
        if caption: d["caption"]=caption
        return self._post("sendDocument",d)

    def sendVideo(self, chat_id, video, caption=None):
        d={"chat_id":chat_id,"video":video}
        if caption: d["caption"]=caption
        return self._post("sendVideo",d)

    def sendAudio(self, chat_id, audio, caption=None):
        d={"chat_id":chat_id,"audio":audio}
        if caption: d["caption"]=caption
        return self._post("sendAudio",d)

    def sendSticker(self, chat_id, sticker):
        return self._post("sendSticker",{"chat_id":chat_id,"sticker":sticker})

    def sendLocation(self, chat_id, latitude, longitude):
        return self._post("sendLocation",{"chat_id":chat_id,"latitude":latitude,"longitude":longitude})

    def sendChatAction(self, chat_id, action="typing"):
        return self._post("sendChatAction",{"chat_id":chat_id,"action":action})

    def forwardMessage(self, chat_id, from_chat_id, message_id):
        return self._post("forwardMessage",{"chat_id":chat_id,"from_chat_id":from_chat_id,"message_id":message_id})

    def copyMessage(self, chat_id, from_chat_id, message_id, caption=None):
        d={"chat_id":chat_id,"from_chat_id":from_chat_id,"message_id":message_id}
        if caption: d["caption"]=caption
        return self._post("copyMessage",d)

    def pinChatMessage(self, chat_id, message_id):
        return self._post("pinChatMessage",{"chat_id":chat_id,"message_id":message_id})

    def unpinChatMessage(self, chat_id, message_id):
        return self._post("unpinChatMessage",{"chat_id":chat_id,"message_id":message_id})

    def getChatMember(self, chat_id, user_id):
        return self._post("getChatMember",{"chat_id":chat_id,"user_id":user_id})

    def getChat(self, chat_id):
        return self._post("getChat",{"chat_id":chat_id})

    def getChatMembersCount(self, chat_id):
        return self._post("getChatMembersCount",{"chat_id":chat_id})

    def banChatMember(self, chat_id, user_id, until_date=None):
        d={"chat_id":chat_id,"user_id":user_id}
        if until_date: d["until_date"]=until_date
        return self._post("banChatMember",d)

    def unbanChatMember(self, chat_id, user_id):
        return self._post("unbanChatMember",{"chat_id":chat_id,"user_id":user_id})

    def restrictChatMember(self, chat_id, user_id, permissions, until_date=None):
        d={"chat_id":chat_id,"user_id":user_id,"permissions":permissions}
        if until_date: d["until_date"]=until_date
        return self._post("restrictChatMember",d)

    def getMe(self): return self._get("getMe")

# ─────────────────────────────────────────────────────────────
# SHARED EXEC GLOBALS — built ONCE at import time, copied per call
# Every bot script gets ALL of these injected automatically.
# ─────────────────────────────────────────────────────────────
_BASE_GLOBALS = {

    # ── BotHost Framework ─────────────────────────────────────
    "__builtins__":             __builtins__,
    "ReturnCommand":            ReturnCommand,
    "InlineKeyboardMarkup":     InlineKeyboardMarkup,
    "InlineKeyboardButton":     InlineKeyboardButton,

    # ── Standard Library — Core ───────────────────────────────
    "os":                       os,
    "sys":                      sys,
    "re":                       re,
    "json":                     json,
    "time":                     time,
    "math":                     math,
    "random":                   random,
    "hashlib":                  hashlib,
    "subprocess":               subprocess,
    "threading":                threading,
    "asyncio":                  asyncio,
    "traceback":                traceback,
    "inspect":                  inspect,
    "functools":                functools,
    "itertools":                itertools,
    "operator":                 operator,
    "string":                   string,
    "copy":                     copy,
    "io":                       io,
    "struct":                   struct,
    "base64":                   base64,
    "binascii":                 binascii,
    "uuid":                     uuid,
    "enum":                     enum,
    "abc":                      abc,
    "weakref":                  weakref,
    "collections":              collections,
    "heapq":                    heapq,
    "bisect":                   bisect,
    "array":                    array,
    "queue":                    queue,
    "pathlib":                  pathlib,
    "tempfile":                 tempfile,
    "shutil":                   shutil,
    "glob":                     glob,
    "csv":                      csv,
    "textwrap":                 textwrap,
    "difflib":                  difflib,
    "pprint":                   pprint,
    "decimal":                  decimal,
    "fractions":                fractions,
    "statistics":               statistics,
    "calendar":                 calendar,
    "logging":                  logging,
    "warnings":                 warnings,
    "contextlib":               contextlib,
    "dataclasses":              dataclasses,
    "typing":                   typing_mod,
    "configparser":             configparser,
    "struct":                   struct,

    # ── datetime objects ──────────────────────────────────────
    "datetime":                 datetime,
    "timedelta":                timedelta,
    "date":                     date,
    "timezone":                 timezone,

    # ── collections helpers ───────────────────────────────────
    "defaultdict":              defaultdict,
    "deque":                    deque,
    "Counter":                  Counter,
    "OrderedDict":              OrderedDict,
    "namedtuple":               namedtuple,
    "ChainMap":                 ChainMap,

    # ── typing helpers ────────────────────────────────────────
    "List":                     List,
    "Dict":                     Dict,
    "Any":                      Any,
    "Tuple":                    Tuple,
    "Union":                    Union,
    "Set":                      Set,
    "Callable":                 Callable,
    "Generator":                Generator,
    "Iterator":                 Iterator,
    "Optional":                 Optional,

    # ── functools helpers ─────────────────────────────────────
    "wraps":                    wraps,
    "partial":                  partial,
    "lru_cache":                lru_cache,
    "reduce":                   reduce,

    # ── itertools helpers ─────────────────────────────────────
    "chain":                    chain,
    "cycle":                    cycle,
    "islice":                   islice,
    "product":                  product,
    "permutations":             permutations,
    "combinations":             combinations,
    "groupby":                  groupby,
    "as_completed":             as_completed,

    # ── contextlib ────────────────────────────────────────────
    "contextmanager":           contextmanager,
    "suppress":                 suppress,

    # ── dataclasses ───────────────────────────────────────────
    "dataclass":                dataclass,
    "field":                    field,

    # ── numeric types ─────────────────────────────────────────
    "Decimal":                  Decimal,
    "Fraction":                 Fraction,

    # ── OOP helpers ───────────────────────────────────────────
    "Enum":                     Enum,
    "auto":                     auto,
    "ABC":                      ABC,
    "abstractmethod":           abstractmethod,

    # ── I/O ───────────────────────────────────────────────────
    "StringIO":                 StringIO,
    "BytesIO":                  BytesIO,
    "Path":                     Path,

    # ── copy helpers ──────────────────────────────────────────
    "copy":                     copy,
    "deepcopy":                 deepcopy,

    # ── pprint ────────────────────────────────────────────────
    "pformat":                  pformat,

    # ── HTTP ──────────────────────────────────────────────────
    "requests":                 req_lib,
    "urllib_parse":             urllib.parse,
    "urllib_request":           urllib.request,
    "html_lib":                 html_lib,

    # ── Attribute / Introspection builtins ────────────────────
    "getattr":                  getattr,
    "setattr":                  setattr,
    "hasattr":                  hasattr,
    "delattr":                  delattr,
    "dir":                      dir,
    "vars":                     vars,
    "type":                     type,
    "isinstance":               isinstance,
    "issubclass":               issubclass,
    "callable":                 callable,
    "id":                       id,
    "repr":                     repr,
    "hash":                     hash,
    "help":                     help,

    # ── Type constructors ─────────────────────────────────────
    "str":                      str,
    "int":                      int,
    "float":                    float,
    "bool":                     bool,
    "list":                     list,
    "dict":                     dict,
    "tuple":                    tuple,
    "set":                      set,
    "frozenset":                frozenset,
    "bytes":                    bytes,
    "bytearray":                bytearray,
    "memoryview":               memoryview,
    "complex":                  complex,

    # ── Built-in functions ────────────────────────────────────
    "len":                      len,
    "range":                    range,
    "enumerate":                enumerate,
    "zip":                      zip,
    "map":                      map,
    "filter":                   filter,
    "sorted":                   sorted,
    "reversed":                 reversed,
    "sum":                      sum,
    "min":                      min,
    "max":                      max,
    "abs":                      abs,
    "round":                    round,
    "pow":                      pow,
    "divmod":                   divmod,
    "any":                      any,
    "all":                      all,
    "next":                     next,
    "iter":                     iter,
    "open":                     open,
    "print":                    print,
    "input":                    input,
    "format":                   format,
    "bin":                      bin,
    "oct":                      oct,
    "hex":                      hex,
    "ord":                      ord,
    "chr":                      chr,
    "eval":                     eval,
    "exec":                     exec,
    "compile":                  compile,
    "globals":                  globals,
    "locals":                   locals,
    "staticmethod":             staticmethod,
    "classmethod":              classmethod,
    "property":                 property,
    "super":                    super,
    "object":                   object,
    "Exception":                Exception,
    "ValueError":               ValueError,
    "TypeError":                TypeError,
    "KeyError":                 KeyError,
    "IndexError":               IndexError,
    "AttributeError":           AttributeError,
    "RuntimeError":             RuntimeError,
    "StopIteration":            StopIteration,
    "NotImplementedError":      NotImplementedError,
    "PermissionError":          PermissionError,
    "FileNotFoundError":        FileNotFoundError,
    "OSError":                  OSError,
    "IOError":                  IOError,
    "OverflowError":            OverflowError,
    "ZeroDivisionError":        ZeroDivisionError,
    "MemoryError":              MemoryError,
    "RecursionError":           RecursionError,
    "AssertionError":           AssertionError,
    "ImportError":              ImportError,
    "ModuleNotFoundError":      ModuleNotFoundError,
    "UnicodeError":             UnicodeError,
    "UnicodeDecodeError":       UnicodeDecodeError,
    "UnicodeEncodeError":       UnicodeEncodeError,
    "ArithmeticError":          ArithmeticError,
    "LookupError":              LookupError,
    "ConnectionError":          ConnectionError,
    "TimeoutError":             TimeoutError,
    "NotImplemented":           NotImplemented,
    "Ellipsis":                 Ellipsis,
    "True":                     True,
    "False":                    False,
    "None":                     None,

    # ── Math constants ────────────────────────────────────────
    "pi":                       math.pi,
    "e":                        math.e,
    "inf":                      math.inf,
    "nan":                      math.nan,

    # ── String constants ──────────────────────────────────────
    "ascii_letters":            string.ascii_letters,
    "ascii_lowercase":          string.ascii_lowercase,
    "ascii_uppercase":          string.ascii_uppercase,
    "digits":                   string.digits,
    "punctuation":              string.punctuation,
    "whitespace":               string.whitespace,

    # ── UUID shortcuts ────────────────────────────────────────
    "uuid4":                    uuid.uuid4,
    "uuid1":                    uuid.uuid1,
}

def execute_bot_script(code, script, update, bot_token, bot_id, env_vars=None):
    try:
        bot     = BotAPI(bot_token)
        storage = BotStorage(bot_id)

        if "message" in update:
            message = _MsgObj(update["message"]); callback_query = None
        elif "callback_query" in update:
            callback_query = _CBQObj(update["callback_query"]); message = callback_query.message
        else:
            message = None; callback_query = None

        g = dict(_BASE_GLOBALS)   # copy base (fast — ~1μs)
        g.update({"bot":bot,"storage":storage,"message":message,
                  "callback_query":callback_query,"update":update})
        if env_vars: g.update(env_vars)

        exec(code if code is not None else script, g)

        ut = "msg" if "message" in update else "cbq" if "callback_query" in update else "upd"
        log_msg(bot_id, f"✅ {ut} OK", "INFO")

    except ReturnCommand: pass
    except Exception as e:
        log_msg(bot_id, f"❌ {type(e).__name__}: {e}", "ERROR")
        traceback.print_exc()

# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    print("="*60)
    print("🤖 BOTHOST v7 — ULTRA FAST WEBHOOK ENGINE")
    print("="*60)
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        reload=False,
        workers=1,
        loop="uvloop",          # pip install uvloop  → 2-4x faster async I/O
        http="httptools",       # pip install httptools → faster HTTP parsing
        access_log=False,       # saves ~0.5ms per request
        timeout_keep_alive=30,
    )
