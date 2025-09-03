#!/usr/bin/env python3
"""
AlertadorPY — Bot anti‑phishing (Telegram)

Stack: python-telegram-bot (v21+), aiohttp, aiosqlite, python-dotenv, tldextract, validators

Funciones clave:
- /start, /help: registro rápido y ayuda
- /subscribe y /unsubscribe: gestionar suscripción a alertas
- /report <url> o enviando un mensaje con links: valida contra listas negras (PhishTank, OpenPhish, URLhaus)
- /check <url>: verifica sin alertar a la comunidad
- /recent [n]: últimos n reportes
- Difusión a suscriptores si es sospechoso (con de‑dupe y rate‑limit)
- Histórico en SQLite

Variables de entorno (.env):
- TELEGRAM_BOT_TOKEN=... (obligatorio)
- ADMIN_IDS=12345,67890 (opcional, para /health y mensajes de sistema)
- PHISHTANK_API_KEY=... (opcional)
- USE_WEBHOOK=false (true/false)
- WEBHOOK_URL=https://ejemplo.tld/telegram (si USE_WEBHOOK=true)

Requisitos (requirements.txt):
python-telegram-bot==21.4
aiohttp
aiosqlite
python-dotenv
validators
tldextract

Ejecutar:
$ python3 bot.py
"""
import asyncio
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

import aiosqlite
import aiohttp
import tldextract
import validators
from dotenv import load_dotenv
from telegram import Update, MessageEntity
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    ApplicationBuilder,
    AIORateLimiter,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

# ----------------- Config & Logging -----------------
load_dotenv()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("alertadorpy")

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
if not BOT_TOKEN:
    raise SystemExit("Falta TELEGRAM_BOT_TOKEN en .env")

ADMIN_IDS = set()
if os.getenv("ADMIN_IDS"):
    try:
        ADMIN_IDS = {int(x.strip()) for x in os.getenv("ADMIN_IDS").split(",") if x.strip()}
    except Exception:
        log.warning("ADMIN_IDS inválido, ignorando")

PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY")
USE_WEBHOOK = os.getenv("USE_WEBHOOK", "false").lower() == "true"
WEBHOOK_URL = os.getenv("WEBHOOK_URL")

DB_PATH = os.getenv("DB_PATH", "alertador.db")
ALERT_DEDUP_WINDOW_H = int(os.getenv("ALERT_DEDUP_WINDOW_H", "24"))
MAX_RECENT = 25

# Rate‑limit por usuario (reportes): N por ventana de M segundos
USER_RATE_LIMIT_N = int(os.getenv("USER_RATE_LIMIT_N", "5"))
USER_RATE_LIMIT_WINDOW = int(os.getenv("USER_RATE_LIMIT_WINDOW", "60"))

# Broadcast chunking para no golpear límites de Telegram
BROADCAST_BATCH_SIZE = 25
BROADCAST_SLEEP = 0.3

# ----------------- Utils -----------------
URL_REGEX = re.compile(r"https?://[^\s]+", re.IGNORECASE)

STATUS_CLEAN = "clean"
STATUS_SUSPICIOUS = "suspicious"
STATUS_PHISH = "phish"
STATUS_UNKNOWN = "unknown"

UTC = timezone.utc

_rate_cache = {}


def now_utc() -> datetime:
    return datetime.now(tz=UTC)


def normalize_url(url: str) -> Optional[str]:
    url = url.strip().replace("[.]", ".")
    # Quitar trailing puntuación común
    url = url.rstrip(".),;>\"]}")
    if not (url.lower().startswith("http://") or url.lower().startswith("https://")):
        url = "http://" + url  # asumir http si no proveen esquema
    try:
        ok = validators.url(url)
    except Exception:
        ok = False
    return url if ok else None


def extract_urls(text: str, entities: Optional[List[MessageEntity]] = None) -> List[str]:
    found = set()
    if entities:
        for e in entities:
            if e.type in (MessageEntity.URL, MessageEntity.TEXT_LINK):
                try:
                    if e.type == MessageEntity.TEXT_LINK and e.url:
                        found.add(e.url)
                    else:
                        # slice por offsets de Telegram
                        pass
                except Exception:
                    pass
    # regex de respaldo
    for m in URL_REGEX.finditer(text or ""):
        found.add(m.group(0))
    # normalizar
    normed = []
    for u in found:
        nu = normalize_url(u)
        if nu:
            normed.append(nu)
    return list(dict.fromkeys(normed))  # de‑dupe preservando orden


# ----------------- DB -----------------
SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_id INTEGER UNIQUE NOT NULL,
  joined_at TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reporter_chat_id INTEGER NOT NULL,
  url TEXT NOT NULL,
  domain TEXT NOT NULL,
  status TEXT NOT NULL,
  source TEXT,
  details TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_url ON reports(url);
CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  report_id INTEGER NOT NULL,
  sent_to INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(report_id) REFERENCES reports(id)
);
"""


async def init_db() -> aiosqlite.Connection:
    conn = await aiosqlite.connect(DB_PATH)
    await conn.executescript(SCHEMA_SQL)
    await conn.commit()
    return conn


# ----------------- Blacklist Checkers -----------------
class BlacklistResult(Tuple[str, str, dict]):
    """(status, source, details)"""


async def fetch_json(session: aiohttp.ClientSession, url: str, **kwargs):
    async with session.get(url, timeout=12, **kwargs) as r:
        if r.status == 200:
            return await r.json(content_type=None)
        return None


async def check_phishtank(session: aiohttp.ClientSession, url: str) -> BlacklistResult:
    if not PHISHTANK_API_KEY:
        return (STATUS_UNKNOWN, "PhishTank", {"reason": "no_api_key"})
    api = "https://checkurl.phishtank.com/checkurl/"
    # API clásica de PhishTank acepta POST form-urlencoded; algunas instancias permiten JSON
    data = {
        "format": "json",
        "app_key": PHISHTANK_API_KEY,
        "url": url,
    }
    try:
        async with session.post(api, data=data, timeout=12) as r:
            if r.status != 200:
                return (STATUS_UNKNOWN, "PhishTank", {"http": r.status})
            j = await r.json(content_type=None)
            # Simplificación del parsing
            verified = (
                j.get("results", {})
                .get("in_database")
            )
            valid = (
                j.get("results", {})
                .get("valid")
            )
            if verified and valid:
                return (STATUS_PHISH, "PhishTank", j.get("results", {}))
            elif verified and not valid:
                return (STATUS_SUSPICIOUS, "PhishTank", j.get("results", {}))
            else:
                return (STATUS_CLEAN, "PhishTank", j.get("results", {}))
    except Exception as e:
        return (STATUS_UNKNOWN, "PhishTank", {"error": str(e)})


async def check_openphish(session: aiohttp.ClientSession, url: str) -> BlacklistResult:
    # OpenPhish publica feeds; para demo haremos una heurística simple (dominio en feed cacheado: TODO)
    # Aquí retornamos UNKNOWN; puedes implementar caching de su feed Enterprise/Community y lookup.
    return (STATUS_UNKNOWN, "OpenPhish", {"note": "feed_lookup_not_implemented"})


async def check_urlhaus(session: aiohttp.ClientSession, url: str) -> BlacklistResult:
    # URLhaus tiene API JSON por URL
    api = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        async with session.post(api, data={"url": url}, timeout=12) as r:
            if r.status != 200:
                return (STATUS_UNKNOWN, "URLhaus", {"http": r.status})
            j = await r.json(content_type=None)
            if j.get("query_status") == "ok":
                # status puede ser online/offline; lo tratamos como sospechoso
                return (STATUS_SUSPICIOUS, "URLhaus", j)
            elif j.get("query_status") == "no_results":
                return (STATUS_CLEAN, "URLhaus", j)
            else:
                return (STATUS_UNKNOWN, "URLhaus", j)
    except Exception as e:
        return (STATUS_UNKNOWN, "URLhaus", {"error": str(e)})


async def aggregate_checks(url: str) -> Tuple[str, str, dict]:
    """Corre múltiples verificadores y devuelve el peor estado observado."""
    async with aiohttp.ClientSession(headers={"User-Agent": "AlertadorPY/1.0"}) as session:
        results = await asyncio.gather(
            check_phishtank(session, url),
            check_urlhaus(session, url),
            check_openphish(session, url),
            return_exceptions=True,
        )
    status_order = {STATUS_CLEAN: 0, STATUS_UNKNOWN: 1, STATUS_SUSPICIOUS: 2, STATUS_PHISH: 3}
    best = (STATUS_UNKNOWN, "none", {})
    for res in results:
        if isinstance(res, Exception):
            continue
        s, src, det = res
        if status_order[s] > status_order[best[0]]:
            best = (s, src, det)
    return best


# ----------------- Rate Limiting -----------------
def user_allowed(chat_id: int) -> bool:
    now = time.time()
    bucket = _rate_cache.setdefault(chat_id, [])
    # drop expirados
    window_start = now - USER_RATE_LIMIT_WINDOW
    bucket = [t for t in bucket if t >= window_start]
    _rate_cache[chat_id] = bucket
    if len(bucket) >= USER_RATE_LIMIT_N:
        return False
    bucket.append(now)
    return True


# ----------------- Bot Handlers -----------------
WELCOME = (
    "👋 Bienvenido a <b>AlertadorPY</b> — bot anti‑phishing.\n\n"
    "• Envía cualquier <b>link</b> sospechoso o usa <code>/report &lt;url&gt;</code>.\n"
    "• Para recibir alertas comunitarias: <code>/subscribe</code>. Para salir: <code>/unsubscribe</code>.\n"
    "• Verificar sin alertar: <code>/check &lt;url&gt;</code>.\n"
    "• Últimos reportes: <code>/recent</code>.\n\n"
    "Privacidad: Guardamos url, dominio y metadatos mínimos para investigación."
)


async def ensure_user(conn: aiosqlite.Connection, chat_id: int, is_admin: bool = False):
    async with conn.execute("SELECT chat_id FROM users WHERE chat_id=?", (chat_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        await conn.execute(
            "INSERT INTO users (chat_id, joined_at, is_admin) VALUES (?,?,?)",
            (chat_id, now_utc().isoformat(), 1 if is_admin else 0),
        )
        await conn.commit()


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    conn: aiosqlite.Connection = context.bot_data["db"]
    chat_id = update.effective_chat.id
    await ensure_user(conn, chat_id, chat_id in ADMIN_IDS)
    await update.effective_message.reply_text(WELCOME, parse_mode=ParseMode.HTML, disable_web_page_preview=True)


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text(WELCOME, parse_mode=ParseMode.HTML, disable_web_page_preview=True)


async def cmd_subscribe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    conn: aiosqlite.Connection = context.bot_data["db"]
    chat_id = update.effective_chat.id
    await ensure_user(conn, chat_id, chat_id in ADMIN_IDS)
    await update.message.reply_text("✅ Suscripción activa. Recibirás alertas de phishing en tiempo real.")


async def cmd_unsubscribe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    conn: aiosqlite.Connection = context.bot_data["db"]
    chat_id = update.effective_chat.id
    await conn.execute("DELETE FROM users WHERE chat_id=?", (chat_id,))
    await conn.commit()
    await update.message.reply_text("🛑 Suscripción cancelada. Puedes volver con /subscribe cuando quieras.")


async def save_report(conn: aiosqlite.Connection, reporter: int, url: str, status: str, source: str, details: dict) -> int:
    domain = tldextract.extract(url)
    dom = ".".join([p for p in [domain.subdomain, domain.domain, domain.suffix] if p])
    await conn.execute(
        "INSERT INTO reports (reporter_chat_id, url, domain, status, source, details, created_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (reporter, url, dom, status, source, json.dumps(details)[:4000], now_utc().isoformat()),
    )
    await conn.commit()
    async with conn.execute("SELECT last_insert_rowid()") as cur:
        (rid,) = await cur.fetchone()
    return int(rid)


async def already_alerted_recently(conn: aiosqlite.Connection, url: str) -> bool:
    cutoff = (now_utc() - timedelta(hours=ALERT_DEDUP_WINDOW_H)).isoformat()
    async with conn.execute(
        "SELECT r.id FROM reports r JOIN alerts a ON a.report_id=r.id WHERE r.url=? AND r.created_at>=? LIMIT 1",
        (url, cutoff),
    ) as cur:
        row = await cur.fetchone()
        return row is not None


async def broadcast_alert(context: ContextTypes.DEFAULT_TYPE, report_id: int, text: str):
    conn: aiosqlite.Connection = context.bot_data["db"]
    # tomar lista de subs
    chat_ids = []
    async with conn.execute("SELECT chat_id FROM users") as cur:
        async for row in cur:
            chat_ids.append(int(row[0]))
    sent = 0
    for i in range(0, len(chat_ids), BROADCAST_BATCH_SIZE):
        batch = chat_ids[i:i + BROADCAST_BATCH_SIZE]
        tasks = []
        for chat_id in batch:
            tasks.append(context.bot.send_message(chat_id=chat_id, text=text, disable_web_page_preview=True))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        # guardar entregas
        ok_count = 0
        for idx, res in enumerate(results):
            if not isinstance(res, Exception):
                ok_count += 1
                await conn.execute(
                    "INSERT INTO alerts (report_id, sent_to, created_at) VALUES (?,?,?)",
                    (report_id, batch[idx], now_utc().isoformat()),
                )
        await conn.commit()
        sent += ok_count
        await asyncio.sleep(BROADCAST_SLEEP)
    log.info("Difusión completada: %s usuarios", sent)


async def handle_report(update: Update, context: ContextTypes.DEFAULT_TYPE, urls: List[str], silent: bool = False):
    if not urls:
        await update.effective_message.reply_text("⚠️ No encontré URLs válidas en tu mensaje.")
        return
    conn: aiosqlite.Connection = context.bot_data["db"]
    chat_id = update.effective_chat.id

    if not user_allowed(chat_id):
        await update.effective_message.reply_text("⏳ Estás enviando demasiados reportes. Intenta de nuevo en unos segundos.")
        return

    for url in urls:
        status, source, details = await aggregate_checks(url)
        report_id = await save_report(conn, chat_id, url, status, source, details)
        if status in (STATUS_SUSPICIOUS, STATUS_PHISH):
            # de‑dupe de alertas recientes
            if not await already_alerted_recently(conn, url) and not silent:
                alert_text = f"⚠️ <b>Phishing activo</b> detectado\n{url}\nOrigen: <i>{source}</i>"
                await broadcast_alert(context, report_id, alert_text)
            if silent:
                await update.effective_message.reply_text(
                    f"Resultado: <b>{status.upper()}</b> (fuente: {source}).", parse_mode=ParseMode.HTML, disable_web_page_preview=True
                )
        else:
            if silent:
                await update.effective_message.reply_text(
                    f"Resultado: {status}. (fuente: {source}).", disable_web_page_preview=True
                )


async def cmd_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if not args:
        await update.message.reply_text("Uso: /report <url>")
        return
    urls = [u for u in (normalize_url(a) for a in args) if u]
    await handle_report(update, context, urls, silent=False)


async def cmd_check(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if not args:
        await update.message.reply_text("Uso: /check <url>")
        return
    urls = [u for u in (normalize_url(a) for a in args) if u]
    await handle_report(update, context, urls, silent=True)


async def cmd_recent(update: Update, context: ContextTypes.DEFAULT_TYPE):
    conn: aiosqlite.Connection = context.bot_data["db"]
    try:
        n = int(context.args[0]) if context.args else 10
    except Exception:
        n = 10
    n = max(1, min(n, MAX_RECENT))
    rows = []
    async with conn.execute(
        "SELECT url, status, source, created_at FROM reports ORDER BY id DESC LIMIT ?",
        (n,),
    ) as cur:
        async for r in cur:
            rows.append(r)
    if not rows:
        await update.message.reply_text("Aún no hay reportes.")
        return
    lines = [
        f"{i+1}. [{r[1]}] {r[0]} — {r[2]} — {r[3]}" for i, r in enumerate(rows)
    ]
    await update.message.reply_text("\n".join(lines), disable_web_page_preview=True)


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.effective_message
    urls = extract_urls(msg.text or "", msg.entities)
    if urls:
        await handle_report(update, context, urls, silent=False)


async def cmd_health(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    if chat_id not in ADMIN_IDS:
        return
    conn: aiosqlite.Connection = context.bot_data["db"]
    async with conn.execute("SELECT COUNT(1) FROM users") as cur:
        (users_count,) = await cur.fetchone()
    async with conn.execute("SELECT COUNT(1) FROM reports") as cur:
        (reports_count,) = await cur.fetchone()
    await update.message.reply_text(
        f"OK — usuarios: {users_count}, reportes: {reports_count}, tz: UTC, ahora: {now_utc().isoformat()}"
    )


# ----------------- App bootstrap -----------------
async def main():
    rate_limiter = AIORateLimiter(max_retries=3)
    app: Application = (
        ApplicationBuilder()
        .token(BOT_TOKEN)
        .rate_limiter(rate_limiter)
        .concurrent_updates(True)
        .build()
    )

    # DB compartida
    conn = await init_db()
    app.bot_data["db"] = conn

    # Comandos
    app.add_handler(CommandHandler(["start", "help"], cmd_start))
    app.add_handler(CommandHandler("subscribe", cmd_subscribe))
    app.add_handler(CommandHandler("unsubscribe", cmd_unsubscribe))
    app.add_handler(CommandHandler("report", cmd_report))
    app.add_handler(CommandHandler("check", cmd_check))
    app.add_handler(CommandHandler("recent", cmd_recent))
    app.add_handler(CommandHandler("health", cmd_health))

    # Mensajes con texto/links
    app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), on_text))

    # Inicio
    if USE_WEBHOOK and WEBHOOK_URL:
        # Nota: detrás de reverse proxy que entregue HTTPS; configurar webhook externamente
        await app.bot.set_webhook(url=WEBHOOK_URL, allowed_updates=["message", "callback_query"])
        await app.initialize()
        await app.start()
        log.info("Webhook configurado en %s", WEBHOOK_URL)
        # Mantener vivo
        try:
            while True:
                await asyncio.sleep(3600)
        finally:
            await app.stop()
            await app.shutdown()
            await conn.close()
    else:
        log.info("Iniciando en modo long polling…")
        await app.initialize()
        await app.start()
        await app.updater.start_polling(allowed_updates=["message"])  # v21 mantiene updater para compat
        try:
            await asyncio.Event().wait()
        finally:
            await app.updater.stop()
            await app.stop()
            await app.shutdown()
            await conn.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        print("Saliendo…")
