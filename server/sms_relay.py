#!/usr/bin/env python3
"""
SMS Relay Server with Web UI for 服务器
配合 Air780EPM (YN076) USB Dongle（USB 虚拟串口 JSON 协议）

特点：
1. 纯 Python 3 标准库（零依赖、零 pip 包、零外部 CDN，完全脱机/内网可用）
2. 内置全功能现代响应式 Web 管理控制台（适配手机/平板/电脑）
3. 4G 蜂窝数据软硬双重开关控制（0 流量保护锁定 / 应急 4G 上网开启）
4. 蜂窝流量主动定向消耗功能（按需输入指定 KB 数，一键触发保号/计费数据包）
5. 蜂窝网络流量精确统计（实时 KB / MB 计量、上下行明细、一键清零、本地持久化）
6. 短信收发记录自动存入本地 SQLite
7. 后台自动拉取 780 短信并支持 Bark / Webhook 实时通知
8. 提供 REST API 供局域网第三方调用
"""

import os
import sys
import json
import time
import sqlite3
import threading
import urllib.request
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from serial_780 import serial_780, start_serial_worker
import sim_info
import tg_settings

# ==================== 配置区 ====================
CONFIG = {
    "SERVER_PORT": int(os.getenv("SERVER_PORT", "8088")),
    "SERIAL_PORT_HINT": os.getenv("SERIAL_PORT", "/dev/ttyACM2"),  # 探测起点，自动 fallback
    "POLL_INTERVAL": int(os.getenv("POLL_INTERVAL", "5")),
    "DB_PATH": os.getenv("DB_PATH", "/var/lib/sms-relay/sms.db"),
    "NOTIFY_URL": os.getenv("NOTIFY_URL", ""),
    # Bark 配置（与 X3 同款协议）：填了 BARK_KEY 即启用 Bark 推送
    "BARK_KEY": os.getenv("BARK_KEY", ""),
    "BARK_SERVER": os.getenv("BARK_SERVER", "https://api.day.app"),
    "BARK_SOUND": os.getenv("BARK_SOUND", ""),
    "BARK_GROUP": os.getenv("BARK_GROUP", "YN076短信"),
    # AES-128-CBC 端到端加密（可选，与 Bark App 内设置一致；都填才启用）
    "BARK_ENCRYPT_KEY": os.getenv("BARK_ENCRYPT_KEY", ""),
    "BARK_ENCRYPT_IV": os.getenv("BARK_ENCRYPT_IV", ""),
}

# ==================== 数据库管理 ====================
def init_db():
    os.makedirs(os.path.dirname(CONFIG["DB_PATH"]), exist_ok=True)
    conn = sqlite3.connect(CONFIG["DB_PATH"])
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS inbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            content TEXT,
            sms_time INTEGER,
            received_at INTEGER,
            notified INTEGER DEFAULT 0
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS outbox (
            id TEXT PRIMARY KEY,
            recipient TEXT,
            content TEXT,
            status TEXT,
            created_at INTEGER
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS bark_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            device_key TEXT NOT NULL DEFAULT '',
            server TEXT NOT NULL DEFAULT 'https://api.day.app',
            sound TEXT NOT NULL DEFAULT '',
            group_name TEXT NOT NULL DEFAULT 'YN076短信',
            enc_key TEXT NOT NULL DEFAULT '',
            enc_iv TEXT NOT NULL DEFAULT '',
            updated_at INTEGER
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS consume_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_kb REAL,
            actual_kb REAL,
            http_code INTEGER,
            consumed_at INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def save_inbox_sms(sender, content, sms_time):
    conn = sqlite3.connect(CONFIG["DB_PATH"])
    c = conn.cursor()
    now = int(time.time())
    c.execute(
        "INSERT INTO inbox (sender, content, sms_time, received_at, notified) VALUES (?, ?, ?, ?, 0)",
        (sender, content, sms_time, now)
    )
    sms_id = c.lastrowid
    conn.commit()
    conn.close()
    return sms_id

def save_outbox_sms(sms_id, recipient, content, status):
    conn = sqlite3.connect(CONFIG["DB_PATH"])
    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO outbox (id, recipient, content, status, created_at) VALUES (?, ?, ?, ?, ?)",
        (sms_id, recipient, content, status, int(time.time()))
    )
    conn.commit()
    conn.close()

def save_consume_log(target_kb, actual_kb, http_code):
    conn = sqlite3.connect(CONFIG["DB_PATH"])
    c = conn.cursor()
    c.execute(
        "INSERT INTO consume_logs (target_kb, actual_kb, http_code, consumed_at) VALUES (?, ?, ?, ?)",
        (target_kb, actual_kb, http_code, int(time.time()))
    )
    conn.commit()
    conn.close()

# ==================== 验证码提取（与 X3 同款算法） ====================
def extract_sms_code(body):
    """提取短信验证码：关键词上下文优先，独立数字兜底"""
    if not body:
        return None
    # 1. 关键词上下文：验证码/校验码/动态码/密码/CODE/OTP 附近 8 位内找 4-8 位数字
    import re
    kw = re.search(r'(?:验证码|校验码|动态码|动态密码|验证密码|登录码|CODE|Code|code|OTP|otp)[^\d]{0,8}(\d{4,8})', body)
    if kw:
        return kw.group(1)
    # 2. 兜底：独立出现的 4-6 位数字（前后非数字，排除手机号/金额/日期）
    bare = re.search(r'([^\d]|^)(\d{4,6})([^\d]|$)', body)
    if bare:
        num = bare.group(2)
        # 排除短号/特服号/常见干扰数字
        if not re.match(r'^(10086|10010|10000|955\d\d?|110|120|119|123\d\d|20\d\d)$', num):
            return num
    return None

# ==================== AES-128-CBC 加密（Bark 官方协议，纯标准库） ====================
def _pkcs7_pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len

def _aes128_cbc_encrypt_b64(key, iv, plaintext):
    """AES-128-CBC 加密返回 base64。优先 cryptography 库，无则降级用 openssl 命令行。"""
    import base64
    data = _pkcs7_pad(plaintext.encode("utf-8"))
    try:
        # 路线1：cryptography 库（若系统装有）
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        enc = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode())).encryptor()
        ct = enc.update(data) + enc.finalize()
        return base64.b64encode(ct).decode()
    except ImportError:
        pass
    try:
        # 路线2：openssl 命令行兜底（Debian 系自带；-nopad 因为输入已手工 PKCS7）
        import subprocess
        proc = subprocess.run(
            ["openssl", "enc", "-aes-128-cbc", "-nopad", "-K", key.encode().hex(), "-iv", iv.encode().hex()],
            input=data, capture_output=True, check=True)
        return base64.b64encode(proc.stdout).decode()
    except Exception as e:
        raise RuntimeError(f"AES 加密不可用（无 cryptography 库且 openssl 失败）: {e}")

# ==================== Bark 推送（与 X3 同款：明文/加密双模式） ====================
def get_bark_config():
    """读取 Bark 配置：DB 优先（WebUI 设置），无记录时回落环境变量"""
    try:
        conn = sqlite3.connect(CONFIG["DB_PATH"])
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT device_key, server, sound, group_name, enc_key, enc_iv FROM bark_config WHERE id=1").fetchone()
        conn.close()
        if row and row["device_key"]:
            return {"key": row["device_key"], "server": row["server"] or "https://api.day.app",
                    "sound": row["sound"] or "", "group": row["group_name"] or "YN076短信",
                    "enc_key": row["enc_key"] or "", "enc_iv": row["enc_iv"] or "", "source": "db"}
    except Exception:
        pass
    # 回落：环境变量
    if CONFIG["BARK_KEY"].strip():
        return {"key": CONFIG["BARK_KEY"].strip(), "server": CONFIG["BARK_SERVER"].strip(),
                "sound": CONFIG["BARK_SOUND"].strip(), "group": CONFIG["BARK_GROUP"].strip(),
                "enc_key": CONFIG["BARK_ENCRYPT_KEY"].strip(), "enc_iv": CONFIG["BARK_ENCRYPT_IV"].strip(),
                "source": "env"}
    return None

def send_bark(title, body, url=None, copy=None):
    """Bark 推送：支持明文 /push 与 AES-128-CBC 加密两种模式，返回 bool"""
    cfg = get_bark_config()
    if not cfg:
        return False
    # 自建 bark-server Basic Auth（环境变量 BARK_AUTH_USER/PASS 都设才启用）
    import base64 as _b64
    _au = os.getenv("BARK_AUTH_USER", "").strip()
    _ap = os.getenv("BARK_AUTH_PASS", "")
    _auth = {}
    if _au:
        _auth["Authorization"] = "Basic " + _b64.b64encode(f"{_au}:{_ap}".encode()).decode()
    key = cfg["key"]
    server = (cfg["server"] or "https://api.day.app").strip().rstrip("/")
    enc_key = cfg["enc_key"]
    enc_iv = cfg["enc_iv"]
    bark_group = cfg["group"]
    bark_sound = cfg["sound"]

    payload = {
        "title": title[:100],
        "body": body[:500],
        "group": bark_group,
    }
    if bark_sound:
        payload["sound"] = bark_sound
    if url:
        payload["url"] = url
    if copy:
        payload["copy"] = copy[:200]

    try:
        if len(enc_key) == 16 and len(enc_iv) == 16:
            # 加密模式：POST /{deviceKey}，Bark 服务器只见密文
            ciphertext = _aes128_cbc_encrypt_b64(enc_key, enc_iv, json.dumps(payload, ensure_ascii=False))
            form = urllib.parse.urlencode({"ciphertext": ciphertext, "iv": enc_iv}).encode()
            req = urllib.request.Request(
                f"{server}/{urllib.parse.quote(key)}",
                data=form,
                headers={**{"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "sms-relay/1.0"}, **_auth})
        else:
            # 明文模式：POST /push
            plain = {"device_key": key, **payload}
            req = urllib.request.Request(
                f"{server}/push",
                data=json.dumps(plain, ensure_ascii=False).encode("utf-8"),
                headers={**{"Content-Type": "application/json", "User-Agent": "sms-relay/1.0"}, **_auth})

        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            ok = result.get("code") == 200
            if not ok:
                print(f"[Bark] 推送被拒: {result.get('message')}", file=sys.stderr)
            return ok
    except Exception as e:
        print(f"[Bark Error] 推送失败: {e}", file=sys.stderr)
        return False

# ==================== Telegram 推送 ====================
TG_CFG_PATH = os.path.join(os.path.dirname(os.getenv("DB_PATH", "/var/lib/sms-relay/sms.db")), "telegram.json")
tg_cfg = tg_settings.Settings(TG_CFG_PATH)


def send_tg(title, body):
    try:
        c = tg_cfg.load()
        if not (c.get("enabled") and c.get("bot_token") and c.get("chat_id")):
            return False
        import subprocess, tempfile
        from urllib.parse import quote
        text = title + "\n" + body
        lines = ['url = ' + quote('https://api.telegram.org/bot' + c['bot_token'] + '/sendMessage', safe=':/?&='),
                 'silent = true', 'write-out = %{"ok":true}', '']
        if c.get('proxy_url'):
            lines.append('proxy = ' + c['proxy_url'])
        fd, name = tempfile.mkstemp(prefix='.tg-', dir=os.path.dirname(TG_CFG_PATH) or '/tmp')
        try:
            with os.fdopen(fd, 'w') as f:
                f.write('\n'.join(lines))
            cmd = ['curl', '-sS', '--config', name,
                   '--data-urlencode', 'chat_id=' + c['chat_id'],
                   '--data-urlencode', 'text=' + text,
                   '--data-urlencode', 'disable_web_page_preview=true']
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return '"ok":true' in r.stdout
        finally:
            try: os.unlink(name)
            except OSError: pass
    except Exception as e:
        print(f"[TG] 推送失败: {e}", file=sys.stderr)
        return False


# ==================== 通知推送模块 ====================
def send_notification(sender, content):
    # 1. Bark 通道（优先，支持加密+验证码副标题）
    if get_bark_config():
        code = extract_sms_code(content)
        title = f"💬 新短信 · {sender}" + (f" · 验证码 {code}" if code else "")
        send_bark(title, content[:80], copy=code)

    # 1.5 Telegram 通道
    try:
        c = tg_cfg.load()
        if c.get("enabled") and c.get("bot_token") and c.get("chat_id"):
            code2 = extract_sms_code(content)
            t2 = f"💬 新短信 · {sender}" + (f" · 验证码 {code2}" if code2 else "")
            send_tg(t2, content[:400])
    except Exception:
        pass

    # 2. 兼容旧 NOTIFY_URL webhook 通道（保留原有行为）
    notify_url = CONFIG["NOTIFY_URL"].strip()
    if not notify_url:
        return

    try:
        title = f"收到来自 {sender} 的短信"
        if "api.day.app" in notify_url:
            encoded_title = urllib.parse.quote(title)
            encoded_content = urllib.parse.quote(content)
            req_url = f"{notify_url.rstrip('/')}/{encoded_title}/{encoded_content}?group=SMS"
            req = urllib.request.Request(req_url, headers={"User-Agent": "sms-relay/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                print(f"[Notify] Bark push status: {resp.status}")
        else:
            payload = json.dumps({"sender": sender, "content": content, "title": title}).encode("utf-8")
            req = urllib.request.Request(
                notify_url,
                data=payload,
                headers={**{"Content-Type": "application/json", "User-Agent": "sms-relay/1.0"}, **_auth}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                print(f"[Notify] Webhook status: {resp.status}")
    except Exception as e:
        print(f"[Notify Error] 推送失败: {e}", file=sys.stderr)

# ==================== 后台收信轮询线程 ====================
def on_sms_received(sender, text, timestr):
    """串口推送回调：新短信落库 + Bark通知（替代旧 HTTP 轮询）"""
    print(f"[Serial] 收到新短信: {sender} -> {text}")
    save_inbox_sms(sender, text, timestr or int(time.time()))
    send_notification(sender, text)

def serial_worker():
    print("[Worker] 启动串口工作线程（780 推送模式，无需轮询）")
    start_serial_worker(on_sms=on_sms_received)

# ==================== 前端 HTML 静态资源 (零外部依赖) ====================
HTML_PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>YN076 短信网关</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg: #F9FAFC; --side: #FFFFFF; --card: #FFFFFF;
  --text: #1D2129; --text-2: #4E5969; --text-3: #86909C;
  --border: #E5E6EB; --accent: #3F67BC; --accent-2: #EAF0FB;
  --ok: #00B42A; --warn: #FF7D00; --bad: #F53F3F; --violet: #7C5CFC;
  --radius: 10px; --side-w: 224px;
}
body[data-theme="dark"] {
  --bg: #17181C; --side: #1E1F24; --card: #1E1F24;
  --text: #F2F3F5; --text-2: #C0C6CF; --text-3: #8A919C;
  --border: #2B2C31; --accent: #5C84E0; --accent-2: #232B3D;
}
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif; background: var(--bg); color: var(--text); font-size: 15px; -webkit-font-smoothing: antialiased; }
.layout { display: flex; min-height: 100vh; }
aside { width: var(--side-w); flex-shrink: 0; background: var(--side); border-right: 1px solid var(--border); display: flex; flex-direction: column; position: sticky; top: 0; height: 100vh; }
.main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
.topbar { height: 54px; display: flex; align-items: center; gap: 10px; padding: 0 26px; background: var(--side); border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 20; }
.content { padding: 22px 26px 48px; max-width: 1040px; width: 100%; margin: 0 auto; }

.brand { display: flex; align-items: center; gap: 10px; padding: 15px 16px 12px; }
.brand .logo { width: 34px; height: 34px; border-radius: 9px; background: linear-gradient(135deg, var(--accent), var(--violet)); display: flex; align-items: center; justify-content: center; font-size: 16px; flex-shrink: 0; }
.brand h1 { font-size: .92rem; font-weight: 700; line-height: 1.25; color: var(--text); }
.brand small { display: block; font-size: .66rem; color: var(--text-3); font-weight: 400; }
nav { flex: 1; padding: 4px 10px; overflow-y: auto; }
.nav-sec { font-size: .66rem; color: var(--text-3); padding: 13px 10px 5px; letter-spacing: .06em; }
.nav-item { display: flex; align-items: center; gap: 10px; padding: 8px 12px; border-radius: 8px; color: var(--text-2); font-size: .85rem; cursor: pointer; user-select: none; border: none; background: none; width: 100%; text-align: left; font-family: inherit; transition: background .15s, color .15s; }
.nav-item:hover { background: var(--bg); color: var(--text); }
.nav-item.active { background: var(--accent-2); color: var(--accent); font-weight: 600; }
.nav-item .nico { width: 20px; text-align: center; font-size: 14px; }
.side-foot { padding: 10px; border-top: 1px solid var(--border); }
.side-user { display: flex; align-items: center; gap: 10px; padding: 7px 9px; border-radius: 8px; }
.side-user .avatar { width: 30px; height: 30px; border-radius: 50%; background: linear-gradient(135deg, #7C5CFC, #3F67BC); color: #fff; font-size: 13px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
.side-user .sun { font-size: .78rem; font-weight: 600; }
.side-user .seu { font-size: .66rem; color: var(--text-3); }

.page { display: none; }
.page.active { display: block; animation: fadeIn .18s ease; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: none; } }

.card { background: var(--card); border: 1px solid var(--border); border-radius: var(--radius); padding: 18px 20px; margin-bottom: 16px; }
.card-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 13px; }
.card-title { font-size: .9rem; font-weight: 700; display: flex; align-items: center; gap: 7px; }
.ticon { font-size: 15px; }
.hint { font-size: .73rem; color: var(--text-3); }

.stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 13px; margin-bottom: 16px; }
.stat { background: var(--card); border: 1px solid var(--border); border-radius: var(--radius); padding: 13px 15px; }
.stat-label { font-size: .72rem; color: var(--text-3); margin-bottom: 6px; display: flex; align-items: center; justify-content: space-between; gap: 6px; }
.stat-value { font-size: 1.4rem; font-weight: 700; font-variant-numeric: tabular-nums; }
.stat-sub { font-size: .74rem; color: var(--text-3); margin-top: 4px; }
.sim-line { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

.fg { margin-bottom: 12px; }
.fl { display: block; font-size: .77rem; color: var(--text-2); margin-bottom: 5px; font-weight: 500; }
input, textarea, select { width: 100%; padding: 9px 12px; border: 1px solid var(--border); border-radius: 8px; font-size: .85rem; font-family: inherit; background: var(--card); color: var(--text); transition: border-color .15s, box-shadow .15s; }
input:focus, textarea:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 14%, transparent); }
textarea { resize: vertical; }
.chips { display: flex; gap: 6px; margin-top: 6px; flex-wrap: wrap; }
.chip { font-size: .71rem; padding: 3px 10px; border-radius: 99px; border: 1px solid var(--border); color: var(--text-2); cursor: pointer; background: none; }
.chip:hover { border-color: var(--accent); color: var(--accent); }
.check { display: flex; align-items: center; gap: 8px; font-size: .81rem; color: var(--text-2); cursor: pointer; }
.check input { width: auto; }

.btn { padding: 9px 18px; border-radius: 8px; border: none; background: var(--accent); color: #fff; font-size: .85rem; font-weight: 500; cursor: pointer; font-family: inherit; transition: filter .15s; }
.btn:hover { filter: brightness(1.08); }
.btn:disabled { opacity: .6; cursor: not-allowed; }
.btn-sm { padding: 5px 12px; font-size: .75rem; border-radius: 7px; }
.btn-ghost { background: none; border: 1px solid var(--border); color: var(--text-2); cursor: pointer; font-family: inherit; font-size: .78rem; border-radius: 7px; }
.btn-ghost:hover { border-color: var(--accent); color: var(--accent); }
.btn-ok { background: var(--ok); color: #fff; border: none; cursor: pointer; }
.btn-bad { background: var(--bad); color: #fff; border: none; cursor: pointer; }
.btn-violet { background: var(--violet); color: #fff; border: none; cursor: pointer; padding: 8px 16px; font-size: .8rem; border-radius: 8px; }
.icon-btn { background: none; border: 1px solid var(--border); border-radius: 8px; width: 32px; height: 32px; cursor: pointer; font-size: 14px; color: var(--text-2); }
.icon-btn:hover { border-color: var(--accent); color: var(--accent); }

.badge { font-size: .69rem; padding: 3px 10px; border-radius: 99px; font-weight: 500; display: inline-flex; align-items: center; gap: 5px; white-space: nowrap; }
.badge .dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.badge-online { background: color-mix(in srgb, var(--ok) 12%, transparent); color: var(--ok); }
.badge-offline { background: color-mix(in srgb, var(--bad) 12%, transparent); color: var(--bad); }
.badge-lock { background: color-mix(in srgb, var(--accent) 12%, transparent); color: var(--accent); }
.badge-unlock { background: color-mix(in srgb, var(--warn) 14%, transparent); color: var(--warn); }

.sms-list { display: flex; flex-direction: column; gap: 10px; max-height: 580px; overflow-y: auto; }
.sms { border: 1px solid var(--border); border-radius: 9px; padding: 12px 14px; background: var(--card); }
.sms-meta { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; gap: 8px; }
.sms-from { font-size: .83rem; font-weight: 600; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.sms-time { font-size: .69rem; color: var(--text-3); white-space: nowrap; }
.sms-body { font-size: .83rem; color: var(--text-2); line-height: 1.55; word-break: break-all; }
.sms-foot { display: flex; gap: 8px; margin-top: 9px; }
.code-chip { background: color-mix(in srgb, var(--accent) 10%, transparent); color: var(--accent); font-weight: 700; font-size: .79rem; padding: 2px 10px; border-radius: 6px; cursor: pointer; font-family: ui-monospace, Menlo, monospace; letter-spacing: .03em; }
.empty { text-align: center; color: var(--text-3); font-size: .8rem; padding: 34px 0; }

.result { font-size: .77rem; color: var(--text-2); margin-top: 10px; min-height: 1.2em; }
.result.ok { color: var(--ok); }
.result.bad { color: var(--warn); }
.mode-tip { font-size: .78rem; color: var(--text-3); background: var(--bg); border-radius: 8px; padding: 10px 12px; margin-bottom: 12px; }
.tg-row { display: flex; justify-content: space-between; align-items: center; gap: 10px; padding: 12px 14px; border: 1px solid var(--border); border-radius: 9px; margin-bottom: 12px; }
.tt { font-size: .83rem; font-weight: 600; }
.td { font-size: .73rem; color: var(--text-3); margin-top: 2px; }
#toast { position: fixed; left: 50%; bottom: 28px; transform: translateX(-50%) translateY(20px); background: var(--text); color: var(--bg); padding: 10px 20px; border-radius: 99px; font-size: .8rem; opacity: 0; pointer-events: none; transition: all .25s; z-index: 99; box-shadow: 0 6px 20px rgba(0,0,0,.18); }
#toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
.push-col > .card { margin-bottom: 0; }
.push-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }

@media (max-width: 900px) {
  .layout { flex-direction: column; }
  aside { width: 100%; height: auto; position: static; flex-direction: row; align-items: center; padding: 0 10px; border-right: none; border-bottom: 1px solid var(--border); overflow-x: auto; }
  .brand { padding: 10px 8px; } .brand small { display: none; }
  nav { display: flex; padding: 0 4px; overflow-x: auto; }
  .nav-sec, .side-foot { display: none; }
  .nav-item { white-space: nowrap; width: auto; padding: 8px 10px; }
  .content { padding: 14px 12px 40px; }
  .stats { grid-template-columns: 1fr 1fr; }
  .push-grid { grid-template-columns: 1fr; }
}
</style>
</head>
<body data-theme="light"><div class="layout">

<aside>
  <div class="brand">
    <div class="logo">📶</div>
    <h1>YN076 短信网关<small>SMS Gateway · Serial</small></h1>
  </div>
  <nav>
    <div class="nav-sec">主菜单</div>
    <button class="nav-item active" data-page="pg-home" onclick="switchPage('pg-home', this)"><span class="nico">🏠</span>概览</button>
    <div class="nav-sec">管理</div>
    <button class="nav-item" data-page="pg-push" onclick="switchPage('pg-push', this)"><span class="nico">🔔</span>推送通知</button>
    <button class="nav-item" data-page="pg-traffic" onclick="switchPage('pg-traffic', this)"><span class="nico">📡</span>流量管理</button>
  </nav>
  <div class="side-foot">
    <div class="side-user">
      <div class="avatar">S</div>
      <div style="min-width:0"><div class="sun">SIM 网关</div><div class="seu sim-line" id="stat-sim">SIM: 检查中…</div></div>
    </div>
  </div>
</aside>

<div class="main">
  <div class="topbar">
    <span class="badge badge-offline" id="dongle-badge"><span class="dot"></span>780 检测中</span>
    <span class="badge badge-lock" id="data-badge">🛡️ 0 流量保护</span>
    <span style="flex:1"></span>
    <button class="icon-btn" id="theme-btn" onclick="toggleTheme()" title="切换主题">🌙</button>
  </div>

  <div class="content">

    <div class="page active" id="pg-home">
<div class="stats">
  <div class="stat">
    <div class="stat-label">Dongle 状态 <span id="stat-mode" class="hint" style="margin:0"></span></div>
    <div class="stat-value" id="stat-status">离线</div>
    <div class="stat-sub sim-line" id="stat-number" style="cursor:pointer;font-weight:700" onclick="editNumber()" title="点击修改号码">📱 点击设置号码</div>
                </div>
  <div class="stat g">
    <div class="stat-label">蜂窝累计流量 <button class="btn-ghost btn-sm" style="padding:1px 8px;font-size:.68rem" onclick="resetTraffic()">清零</button></div>
    <div class="stat-value" id="stat-traffic-total" style="color:var(--ok)">0 KB</div>
    <div class="stat-sub" id="stat-traffic-detail">上行 0 KB · 下行 0 KB</div>
  </div>
  <div class="stat o">
    <div class="stat-label">蜂窝信号 (CSQ)</div>
    <div class="stat-value" id="stat-csq">--</div>
    <div class="stat-sub" id="stat-sim-sub">SIM 状态待设备接入</div>
  </div>
  <div class="stat v">
    <div class="stat-label">短信计数（收 / 发）</div>
    <div class="stat-value" id="stat-sms-counts">0 / 0</div>
    <div class="stat-sub">收件箱 / 发件箱</div>
  </div>
</div>
<div class="card">
      <div class="card-head">
        <span class="card-title"><span class="ticon">📥</span>收件箱</span>
        <span class="hint" id="inbox-update-time" style="margin:0">自动更新中</span>
      </div>
      <div id="inbox-list" class="sms-list"><div class="empty">加载中…</div></div>
    </div>
    </div>

    <div class="page" id="pg-push">
<div class="card" style="padding:16px;border-color:color-mix(in srgb, var(--violet) 30%, var(--border))">
        <div class="card-head" style="margin-bottom:10px"><span class="card-title" style="font-size:.88rem">🍎 Bark (iOS)</span><span class="badge badge-unlock" id="bark-state">读取中</span></div>
        <label class="check" style="margin-bottom:11px"><input type="checkbox" id="bark-enabled">启用新短信自动推送</label>
        <div class="fg"><label class="fl" for="bark-key">DeviceKey</label><input id="bark-key" type="password" autocomplete="new-password" placeholder="Bark App 内复制的 Key"><div class="hint" id="bark-key-hint">留空保留已保存值，不回显明文。</div></div>
        <div class="fg"><label class="fl" for="bark-server">服务器</label><input id="bark-server" placeholder="https://api.day.app"><div class="hint">自建 Bark 服务可改此项；留空用官方。</div></div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
          <div class="fg"><label class="fl" for="bark-group">消息分组</label><input id="bark-group" placeholder="SMS网关"></div>
          <div class="fg"><label class="fl" for="bark-sound">提示音（可选）</label><input id="bark-sound" placeholder="如 minuet"></div>
        </div>
        <div class="fg"><label class="fl" for="bark-enc-key">AES 加密 Key（可选，16 字符）</label><input id="bark-enc-key" type="password" autocomplete="new-password" placeholder="与 Bark App 内一致"><div class="hint" id="bark-enc-hint">填写后推送端到端加密，服务器只见密文。</div></div>
        <div class="fg"><label class="fl" for="bark-enc-iv">AES 加密 IV（16 字符）</label><input id="bark-enc-iv" type="password" autocomplete="new-password" placeholder="与 Bark App 内一致"></div>
        <div class="fg"><label class="fl" for="bark-proxy">推送代理（可选）</label><input id="bark-proxy" placeholder="socks5h://192.168.1.10:7891"></div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
          <div class="fg"><label class="fl" for="bark-user">HTTP Basic 用户名</label><input id="bark-user" autocomplete="off" placeholder="公网防蹭用，可留空"></div>
          <div class="fg"><label class="fl" for="bark-pass">HTTP Basic 密码</label><input id="bark-pass" type="password" autocomplete="new-password" placeholder="留空保留"></div>
        </div>
        <label class="check" style="margin-bottom:11px"><input type="checkbox" id="bark-clear-key">清除已存 DeviceKey</label>
        <label class="check" style="margin-bottom:11px"><input type="checkbox" id="bark-clear-enc">清除已存加密配置</label>
        <label class="check" style="margin-bottom:13px"><input type="checkbox" id="bark-clear-auth">清除已存 Basic Auth</label>
        <div style="display:flex;gap:9px;flex-wrap:wrap">
          <button id="bark-save" class="btn" onclick="saveBark()">保存配置</button>
          <button id="bark-test" class="btn-violet" onclick="testBark()">发送测试</button>
        </div>
        <div class="result" id="bark-result">尚未测试；自动推送默认关闭。</div>
      </div>
    
<div class="card">
      <div class="card-head"><span class="card-title"><span class="ticon">✈️</span>Telegram 推送</span><span class="badge badge-unlock" id="tg-state">未配置</span></div>
      <div class="fg"><label class="fl" for="tg-token">Bot Token</label><input id="tg-token" type="password" autocomplete="new-password" placeholder="123456789:AAA...（@BotFather 创建）"><div class="hint" id="tg-token-hint">留空保留已保存值，不回显明文。</div></div>
      <div class="fg"><label class="fl" for="tg-chat">Chat ID</label><input id="tg-chat" placeholder="你的用户 ID（@userinfobot 查询）"><div class="hint" id="tg-chat-hint"></div></div>
      <label class="check" style="margin-bottom:11px"><input type="checkbox" id="tg-enabled">启用新短信自动推送</label>
      <div style="display:flex;gap:8px">
        <button class="btn" onclick="saveTg()">保存配置</button>
        <button class="btn-violet" onclick="testTg()">发送测试</button>
      </div>
      <div class="result" id="tg-result">尚未配置。</div>
    </div>
    </div>

    <div class="page" id="pg-traffic">
<div class="card">
      <div class="card-head"><span class="card-title"><span class="ticon">📡</span>蜂窝流量管理</span></div>
      <div class="tg-row">
        <div><div class="tt" id="toggle-title">0 流量保护：已开启</div><div class="td" id="toggle-desc">独立 IP 模式物理阻断 4G 数据，仅走短信信令</div></div>
        <button id="btn-toggle-data" class="btn-bad btn-sm" onclick="toggleDataSwitch()">4G 共享(暂不支持)</button>
      </div>
      <div style="background:color-mix(in srgb, var(--violet) 8%, var(--card-2));border:1px solid color-mix(in srgb, var(--violet) 20%, transparent);border-radius:12px;padding:14px">
        <div style="font-size:.83rem;font-weight:700;margin-bottom:3px">⚡ 定量消耗流量（保号）</div>
        <div class="hint" style="margin:0 0 9px">指令 780 经蜂窝网卡直接拉取指定大小数据，精准产生计费流量</div>
        <div class="fg"><input type="number" id="consume-kb" value="10" min="1" max="51200"></div>
        <div class="chips">
          <span class="chip" onclick="setConsumeKb(10)">10 KB</span><span class="chip" onclick="setConsumeKb(50)">50 KB</span>
          <span class="chip" onclick="setConsumeKb(100)">100 KB</span><span class="chip" onclick="setConsumeKb(500)">500 KB</span>
          <span class="chip" onclick="setConsumeKb(1024)">1 MB</span>
        </div>
        <button id="btn-consume" class="btn-violet" style="width:100%;margin-top:10px" onclick="handleConsume()">🚀 立即消耗</button>
        <div class="result" id="consume-result" style="display:none"></div>
      </div>
    </div>
    </div>

  </div>
</div>


<div id="toast"></div>
<script>
let currentDataEnabled = false;
const $ = id => document.getElementById(id);

/* 主题 */
function toggleTheme() {
  const b = document.body, btn = $('theme-btn');
  const dark = b.dataset.theme === 'light';
  b.dataset.theme = dark ? 'dark' : 'light';
  btn.textContent = dark ? '☀️' : '🌙';
  try { localStorage.setItem('sms-theme', b.dataset.theme); } catch(e) {}
}
try { const t = localStorage.getItem('sms-theme'); if (t) { document.body.dataset.theme = t; $('theme-btn').textContent = t === 'dark' ? '☀️' : '🌙'; } } catch(e) {}

function showToast(msg) {
  const t = $('toast'); t.textContent = msg; t.classList.add('show');
  clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove('show'), 3200);
}
function fmtTime(ts) { if (!ts) return '--'; return new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false }); }
function fmtBytes(b) {
  if (!b || b <= 0) return '0 KB';
  const kb = b / 1024;
  return kb < 1024 ? kb.toFixed(2) + ' KB' : (kb / 1024).toFixed(2) + ' MB';
}
function setNum(n, t) { $('send-num').value = n; if (t) $('send-text').value = t; }
function setConsumeKb(v) { $('consume-kb').value = v; }
function copyText(text) {
  navigator.clipboard.writeText(text).then(() => showToast('已复制到剪贴板')).catch(() => showToast('复制失败，请手动复制'));
}
function escHtml(s) { if (!s) return ''; return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function escJs(s) { if (!s) return ''; return s.replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/\n/g,'\\n').replace(/\r/g,''); }

/* ===== 状态 ===== */
async function editNumber() {
            const cur = $('stat-number').textContent.replace('📱 ', '');
            const v = prompt('设置此 SIM 卡的号码备注：', cur === '点击设置号码' ? '' : cur);
            if (v === null) return;
            try {
                await fetch('/api/sim_number', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({number: v})});
                showToast('号码已保存'); fetchStatus();
            } catch (e) { showToast('保存失败'); }
        }
        async function loadSimNumber() {}

        async function fetchStatus() {
  try {
    const d = await (await fetch('/api/status')).json();
    if (!d.ok) return;
    const g = d.dongle || {};
    const online = !!g.online;
    const badge = $('dongle-badge'), st = $('stat-status');
    if (online) {
      badge.className = 'badge badge-online'; badge.innerHTML = '<span class="dot"></span>780 在线';
      st.textContent = '在线'; st.style.color = 'var(--ok)';
      $('stat-csq').textContent = (g.csq != null ? g.csq : '--');
      // SIM 归属地
      const simEl = $('stat-sim'), subEl = $('stat-sim-sub');
      if (d.sim && d.sim.label) {
        // 国旗在下方按 iso 统一渲染
        subEl.textContent = d.iccid ? ('ICCID …' + String(d.iccid).slice(-6)) : 'SIM 就绪';
        if (d.display_number) { $('stat-number').textContent = '📱 ' + d.display_number; }
        // 按国家显示对应旗帜
        if (d.sim.iso && d.sim.iso.length === 2) {
          const flag = d.sim.iso.toUpperCase().replace(/./g, c => String.fromCodePoint(127397 + c.charCodeAt(0)));
          simEl.textContent = d.sim.label;
        }
      } else {
        simEl.textContent = 'SIM: 未识别';
        if (d.display_number) { $('stat-number').textContent = '📱 ' + d.display_number; }
        subEl.textContent = g.iccid ? ('ICCID …' + String(g.iccid).slice(-6)) : 'SIM 在线';
      }
      if (g.traffic) {
        $('stat-traffic-total').textContent = fmtBytes(g.traffic.total_bytes || 0);
        $('stat-traffic-detail').textContent = '上行 ' + fmtBytes((g.traffic.uplink_kb||0)*1024) + ' · 下行 ' + fmtBytes((g.traffic.downlink_kb||0)*1024);
      }
      currentDataEnabled = !!g.data_enabled;
      renderDataSwitch(currentDataEnabled);
    } else {
      badge.className = 'badge badge-offline'; badge.innerHTML = '<span class="dot"></span>780 离线';
      st.textContent = '未连接'; st.style.color = 'var(--bad)';
      $('stat-csq').textContent = '--';
      $('stat-sim').textContent = d.polling_enabled === false ? 'SIM: 仅面板模式' : 'SIM: 未接入';
      $('stat-sim-sub').textContent = '请检查 USB 直通与网络';
    }
    $('stat-mode').textContent = d.polling_enabled === false ? '仅面板' : '';
    $('stat-sms-counts').textContent = (d.inbox_total||0) + ' / ' + (d.outbox_total||0);
  } catch (e) { console.error(e); }
}
function renderDataSwitch(on) {
  const b = $('data-badge'), t = $('toggle-title'), d = $('toggle-desc'), btn = $('btn-toggle-data');
  if (on) {
    b.className = 'badge badge-unlock'; b.textContent = '⚡ 4G 已开启';
    t.textContent = '4G 蜂窝数据共享：已开启';
    d.textContent = '⚠️ 主机正通过 780 的 SIM 卡流量上网';
    btn.className = 'btn-ok btn-sm'; btn.textContent = '关闭 4G';
  } else {
    b.className = 'badge badge-lock'; b.textContent = '🛡️ 0 流量保护';
    t.textContent = '0 流量保护：已开启';
    d.textContent = '独立 IP 模式物理阻断 4G 数据，仅走短信信令';
    btn.className = 'btn-bad btn-sm'; btn.textContent = '4G 共享(暂不支持)';
  }
}
async function toggleDataSwitch() {
  const will = !currentDataEnabled;
  const msg = will ? '确定4G 共享(暂不支持) 上网吗？\n开启后主机将通过 SIM 卡流量访问外网！' : '确定关闭 4G 吗？\n关闭后恢复 0 流量短信网关模式。';
  if (!confirm(msg)) return;
  try {
    showToast('正在下发模式切换指令…');
    const d = await (await fetch('/api/data/switch', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ enabled: will }) })).json();
    if (d.ok) { showToast(d.msg || '切换成功'); currentDataEnabled = will; renderDataSwitch(will); setTimeout(fetchStatus, 2500); }
    else showToast('切换失败: ' + (d.msg || '未知原因'));
  } catch (e) { showToast('网络请求异常'); }
}

/* ===== 流量消耗 ===== */
async function handleConsume() {
  const kb = parseFloat($('consume-kb').value);
  if (!kb || kb <= 0) return showToast('请输入有效的 KB 数');
  if (!confirm('确定指令 780 通过蜂窝网络消耗 ' + kb + ' KB 流量吗？')) return;
  const btn = $('btn-consume'), res = $('consume-result');
  btn.disabled = true; btn.textContent = '消耗中…'; res.style.display = 'block'; res.className = 'result'; res.textContent = '⏳ 正在通过蜂窝网卡拉取数据包…';
  try {
    const d = await (await fetch('/api/data/consume', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ kb }) })).json();
    if (d.ok) { res.className = 'result ok'; res.textContent = '✅ 请求 ' + d.requested_kb + ' KB · 实际 ' + d.actual_consumed_kb + ' KB（累计 ' + d.current_total_kb + ' KB）'; showToast('成功消耗 ' + d.actual_consumed_kb + ' KB'); fetchStatus(); }
    else { res.className = 'result bad'; res.textContent = '❌ 消耗失败: ' + (d.msg || ('HTTP ' + d.http_code)); }
  } catch (e) { res.className = 'result bad'; res.textContent = '❌ 请求异常: ' + e; }
  finally { btn.disabled = false; btn.textContent = '🚀 立即消耗'; }
}
async function resetTraffic() {
  if (!confirm('确定将蜂窝流量统计清零吗？')) return;
  try {
    const d = await (await fetch('/api/data/traffic/reset', { method: 'POST' })).json();
    d.ok ? (showToast('统计已清零'), fetchStatus()) : showToast('重置失败');
  } catch (e) { showToast('请求异常'); }
}

/* ===== 收件箱/发件 ===== */
async function fetchInbox() {
  try {
    const r = await (await fetch('/api/sms/inbox?limit=50')).json();
    const box = $('inbox-list');
    if (r.ok && r.data && r.data.length) {
      box.innerHTML = r.data.map(m => {
        let codeChip = '';
        const mm = (m.content || '').match(/(?:验证码|校验码|动态码|动态密码|登录码|CODE|Code|code|OTP|otp)[^\d]{0,8}(\d{4,8})/);
        if (mm) codeChip = '<span class="code-chip" title="点击复制验证码" onclick="copyText(\'' + mm[1] + '\')">' + mm[1] + '</span>';
        return '<div class="sms"><div class="sms-meta"><span class="sms-from">📞 ' + escHtml(m.sender) + codeChip + '</span><span class="sms-time">' + fmtTime(m.received_at || m.sms_time) + '</span></div><div class="sms-body">' + escHtml(m.content) + '</div><div class="sms-foot"><button class="btn-ghost btn-sm" onclick="copyText(\'' + escJs(m.content) + '\')">复制</button></div></div>';
      }).join('');
    } else box.innerHTML = '<div class="empty">收件箱为空</div>';
    $('inbox-update-time').textContent = '同步于 ' + new Date().toLocaleTimeString('zh-CN', { hour12: false });
  } catch (e) { $('inbox-list').innerHTML = '<div class="empty" style="color:var(--bad)">拉取收件箱失败</div>'; }
}
async function fetchOutbox() {}
async function handleSend(e) { if (e) e.preventDefault(); showToast('发送已移至 API'); }

/* ===== (已移除) ===== */

/* ===== Bark 推送 ===== */
function barkFeedback(text, ok) { const el = $('bark-result'); el.textContent = text; el.className = 'result ' + (ok ? 'ok' : 'bad'); }
function applyBark(c) {
  $('bark-enabled').checked = c.enabled; $('bark-server').value = c.server || ''; $('bark-group').value = c.group || ''; $('bark-sound').value = c.sound || ''; $('bark-proxy').value = c.proxy_url || '';
  $('bark-user').value = c.auth_user || ''; $('bark-pass').value = '';
  $('bark-key').value = ''; $('bark-enc-key').value = ''; $('bark-enc-iv').value = '';
  $('bark-clear-key').checked = false; $('bark-clear-enc').checked = false; $('bark-clear-auth').checked = false;
  $('bark-pass').placeholder = c.auth_configured ? '已保存；留空保留' : '未设置，可留空';
  $('bark-key-hint').textContent = c.device_key_configured ? 'Key 已保存；留空保留。' : '尚未配置 Key。';
  $('bark-enc-hint').textContent = c.encrypt_configured ? '加密已配置；留空保留，勾选下方可清除。' : '填写后推送端到端加密，服务器只见密文。';
  const st = $('bark-state');
  st.textContent = c.enabled ? '已启用' : '未启用'; st.className = 'badge ' + (c.enabled ? 'badge-online' : 'badge-unlock');
}
async function loadBark() {
  try {
    const d = await (await fetch('/api/bark', { cache: 'no-store' })).json();
    if (d.error) throw Error(d.error);
    // v2 API → v1 UI 字段映射
    applyBark({
      enabled: !!d.configured,
      server: d.server || '',
      group: d.group || '',
      sound: d.sound || '',
      device_key_configured: !!d.configured,
      encrypt_configured: !!d.encrypted,
      auth_configured: false,
    });
  } catch (e) { barkFeedback('读取失败: ' + e.message, false); }
}
async function saveBark() {
  const btn = $('bark-save'); btn.disabled = true;
  try {
    const payload = {
      key: $('bark-key').value.trim(),
      server: $('bark-server').value.trim() || 'http://127.0.0.1:8090',
      group: $('bark-group').value.trim() || 'SMS网关',
      sound: $('bark-sound').value.trim(),
    };
    const d = await (await fetch('/api/bark', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) })).json();
    if (d.error) throw Error(d.error);
    barkFeedback('配置已保存', true);
    $('bark-key').value = '';
    loadBark();
  } catch (e) { barkFeedback('保存失败: ' + e.message, false); } finally { btn.disabled = false; }
}
async function testBark() {
  if (!confirm('用已保存的配置发送一条 Bark 测试推送？')) return;
  const btn = $('bark-test'); btn.disabled = true; barkFeedback('正在测试…', false);
  try {
    const d = await (await fetch('/api/bark/test', { method: 'POST' })).json();
    barkFeedback(d.msg, d.ok);
  } catch (e) { barkFeedback('测试请求失败，请检查网络。', false); } finally { btn.disabled = false; }
}
/* ===== Telegram 推送 ===== */
async function loadTg() {
  try {
    const d = await (await fetch('/api/tg', { cache: 'no-store' })).json();
    if (d.error) throw Error(d.error);
    const c = d.config || {};
    $('tg-enabled').checked = !!c.enabled;
    $('tg-chat').value = c.chat_id || '';
    $('tg-token-hint').textContent = c.token_configured ? 'Token 已保存；留空保留。' : '尚未配置 Token。';
    const st = $('tg-state');
    st.textContent = c.enabled && c.token_configured ? '已启用' : '未配置';
    st.className = 'badge ' + (c.enabled && c.token_configured ? 'badge-online' : 'badge-unlock');
  } catch (e) { $('tg-result').textContent = '读取失败: ' + e.message; }
}
async function saveTg() {
  try {
    const payload = { token: $('tg-token').value.trim(), chat_id: $('tg-chat').value.trim(), enabled: $('tg-enabled').checked };
    const d = await (await fetch('/api/tg', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) })).json();
    if (d.error) throw Error(d.error);
    $('tg-result').textContent = '配置已保存'; $('tg-result').className = 'result ok';
    $('tg-token').value = '';
    loadTg();
  } catch (e) { $('tg-result').textContent = '保存失败: ' + e.message; $('tg-result').className = 'result bad'; }
}
async function testTg() {
  try {
    const d = await (await fetch('/api/tg/test', { method: 'POST' })).json();
    $('tg-result').textContent = d.msg; $('tg-result').className = 'result ' + (d.ok ? 'ok' : 'bad');
  } catch (e) { $('tg-result').textContent = '测试请求失败'; $('tg-result').className = 'result bad'; }
}


/* ===== 启动 ===== */
fetchStatus(); fetchInbox(); loadBark(); loadTg();
setInterval(() => { fetchStatus(); fetchInbox(); }, 6000);

/* ===== SPA 导航 ===== */
function switchPage(pid, btn) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
  $(pid).classList.add('active');
  if (btn) btn.classList.add('active');
  try { localStorage.setItem('sms-page', pid); } catch(e) {}
}
try { const sp = localStorage.getItem('sms-page'); if (sp && $(sp)) switchPage(sp, document.querySelector('[data-page="'+sp+'"]')); } catch(e) {}
</script>
</body>
</html>
"""

# ==================== HTTP 请求处理器 ====================
class SMSRequestHandler(BaseHTTPRequestHandler):
    def _json_resp(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def _html_resp(self, code, html_text):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html_text.encode("utf-8"))

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html", "/ui"):
            self._html_resp(200, HTML_PAGE)
            return

        elif path == "/health":
            self._json_resp(200, {"status": "ok", "service": "sms-relay"})
            return

        elif path == "/api/sim_number":
            conn0 = sqlite3.connect(CONFIG["DB_PATH"])
            try:
                conn0.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)")
                row = conn0.execute("SELECT v FROM kv WHERE k='sim_number'").fetchone()
                custom = row[0] if row else ""
            finally:
                conn0.close()
            self._json_resp(200, {"ok": True, "number": custom})
            return

        elif path == "/api/status":
            r = serial_780.command("get_status", timeout=4)
            hb = serial_780.heartbeat_data() or {}
            hb_traffic = hb.get("traffic") or {}
            st_traffic = r.get("traffic") or {}
            total_kb = st_traffic.get("total_kb") or hb_traffic.get("total_kb") or 0
            # 兼容 v1 前端字段：uplink/downlink 拆分暂无（780 v2 只报总量），置为总量估算
            dongle_status = {
                "online": bool(r.get("ok")),
                "csq": r.get("csq") or hb.get("csq"),
                "iccid": r.get("iccid"),
                "number": r.get("number") or "",
                "version": r.get("version"),
                "net_status": r.get("net_status"),
                "queue_len": r.get("queue_len"),
                "serial_port": serial_780.port,
                # v1 前端兼容字段
                "usb_ip": serial_780.port,          # v2 无网络 IP，显示串口路径
                "data_enabled": False,              # v2 串口版无 4G 共享开关
                "traffic": {
                    "uplink_kb": 0,
                    "downlink_kb": total_kb,
                    "total_kb": total_kb,
                    "total_bytes": st_traffic.get("total_bytes", 0),
                },
            }

            conn = sqlite3.connect(CONFIG["DB_PATH"])
            c = conn.cursor()
            inbox_count = c.execute("SELECT COUNT(*) FROM inbox").fetchone()[0]
            outbox_count = c.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]
            conn.close()

            # 展示号码: 设备真实号码(取到) > 自定义备注
            display_number = dongle_status.get("number") or ""
            if not display_number:
                try:
                    conn0 = sqlite3.connect(CONFIG["DB_PATH"])
                    row = conn0.execute("SELECT v FROM kv WHERE k='sim_number'").fetchone()
                    display_number = row[0] if row else ""
                    conn0.close()
                except Exception:
                    pass

            sim_info_obj = None
            if dongle_status.get("online"):
                sim_info_obj = sim_info.brief({
                    "imsi": dongle_status.get("imsi") or "",
                    "iccid": dongle_status.get("iccid") or "",
                })

            self._json_resp(200, {
                "ok": True,
                "server_time": int(time.time()),
                "display_number": display_number,
                "sim": sim_info_obj,
                "inbox_total": inbox_count,
                "outbox_total": outbox_count,
                "dongle": dongle_status
            })
            return

        elif path == "/api/sms/inbox":
            qs = urllib.parse.parse_qs(parsed.query)
            limit = int(qs.get("limit", ["20"])[0])
            offset = int(qs.get("offset", ["0"])[0])

            conn = sqlite3.connect(CONFIG["DB_PATH"])
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            rows = c.execute(
                "SELECT id, sender, content, sms_time, received_at FROM inbox ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset)
            ).fetchall()
            items = [dict(r) for r in rows]
            conn.close()

            self._json_resp(200, {"ok": True, "count": len(items), "data": items})
            return

        elif path == "/api/tg":
            try:
                self._json_resp(200, {"ok": True, "config": tg_cfg.public()})
            except Exception as e:
                self._json_resp(200, {"error": str(e)})
            return
        elif path == "/api/tg/test":
            ok = send_tg("📱 YN076 测试", "Telegram 推送通道正常 ✅")
            self._json_resp(200, {"ok": ok, "msg": "推送成功" if ok else "推送失败（检查 Token/ChatID/网络）"})
            return
        if path == "/api/bark":
            cfg = get_bark_config()
            if not cfg:
                self._json_resp(200, {"configured": False})
                return
            else:
                # 脱敏返回
                masked = cfg["key"][:4] + "****" + cfg["key"][-4:] if len(cfg["key"]) > 8 else "****"
                self._json_resp(200, {
                    "configured": True,
                    "device_key": masked,
                    "server": cfg["server"],
                    "sound": cfg["sound"],
                    "group": cfg["group"],
                    "encrypted": bool(cfg["enc_key"] and cfg["enc_iv"]),
                })
                return

        elif path == "/api/sms/outbox":
            qs = urllib.parse.parse_qs(parsed.query)
            limit = int(qs.get("limit", ["20"])[0])
            offset = int(qs.get("offset", ["0"])[0])

            conn = sqlite3.connect(CONFIG["DB_PATH"])
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            rows = c.execute(
                "SELECT id, recipient, content, status, created_at FROM outbox ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset)
            ).fetchall()
            items = [dict(r) for r in rows]
            conn.close()

            self._json_resp(200, {"ok": True, "count": len(items), "data": items})
            return

        else:
            self._json_resp(404, {"error": "Not Found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/api/sim_number":
            try:
                length = int(self.headers.get("Content-Length", 0))
                data = json.loads(self.rfile.read(length).decode("utf-8"))
                custom = str(data.get("number", ""))[:32]
                conn0 = sqlite3.connect(CONFIG["DB_PATH"])
                conn0.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)")
                conn0.execute("INSERT OR REPLACE INTO kv (k, v) VALUES (\"sim_number\", ?)", (custom,))
                conn0.commit()
                conn0.close()
                self._json_resp(200, {"ok": True, "number": custom})
            except Exception as e:
                self._json_resp(500, {"ok": False, "msg": str(e)})
            return

        # 发短信
        if path == "/api/tg":
            data = json.loads(self._read_body() or "{}")
            try:
                clean = {}
                if str(data.get("token", "")).strip(): clean["bot_token"] = str(data["token"]).strip()
                if "chat_id" in data: clean["chat_id"] = str(data.get("chat_id", "")).strip()
                if "enabled" in data: clean["enabled"] = bool(data["enabled"])
                if data.get("clear_token"): clean["clear_token"] = True
                tg_cfg.save(clean)
                self._json_resp(200, {"ok": True})
            except Exception as e:
                self._json_resp(200, {"error": str(e)})
                return
        if path == "/api/bark":
            # 保存 Bark 配置
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length).decode("utf-8"))
            except Exception as e:
                self._json_resp(400, {"ok": False, "msg": f"请求体解析失败: {e}"})
                return
            key = (body.get("device_key") or "").strip()
            if not key:
                self._json_resp(400, {"ok": False, "msg": "device_key 必填"})
                return
            server = (body.get("server") or "https://api.day.app").strip().rstrip("/")
            sound = (body.get("sound") or "").strip()
            group = (body.get("group") or "YN076短信").strip()
            enc_key = (body.get("enc_key") or "").strip()
            enc_iv = (body.get("enc_iv") or "").strip()
            if (enc_key and not enc_iv) or (not enc_key and enc_iv):
                self._json_resp(400, {"ok": False, "msg": "加密 Key 和 IV 必须同时填写或同时留空"})
                return
            if enc_key and (len(enc_key) != 16 or len(enc_iv) != 16):
                self._json_resp(400, {"ok": False, "msg": "加密 Key 和 IV 都必须是 16 位"})
                return
            if enc_key == "********" or enc_iv == "********":
                # 占位符：保持原值不变
                prev = get_bark_config() or {}
                if enc_key == "********":
                    enc_key = prev.get("enc_key", "")
                if enc_iv == "********":
                    enc_iv = prev.get("enc_iv", "")
            conn = sqlite3.connect(CONFIG["DB_PATH"])
            conn.execute(
                "INSERT INTO bark_config(id, device_key, server, sound, group_name, enc_key, enc_iv, updated_at) "
                "VALUES(1,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                "device_key=excluded.device_key, server=excluded.server, sound=excluded.sound, "
                "group_name=excluded.group_name, enc_key=excluded.enc_key, enc_iv=excluded.enc_iv, updated_at=excluded.updated_at",
                (key, server, sound, group, enc_key, enc_iv, int(time.time())))
            conn.commit()
            conn.close()
            print(f"[Bark] 配置已保存（server={server}, enc={'on' if enc_key else 'off'}）")
            self._json_resp(200, {"ok": True, "msg": "Bark 配置已保存"})
            return

        elif path == "/api/bark/test":
            ok = send_bark("🔔 YN076 测试通知", "Bark 推送通道正常 ✅", copy="123456")
            self._json_resp(200, {"ok": ok, "msg": "推送成功" if ok else "推送失败（检查 Key/网络）"})
            return

        elif path == "/api/sms/send":
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode("utf-8")
                req_data = json.loads(body)
                num = str(req_data.get("num", "")).strip()
                text = str(req_data.get("text", "")).strip()

                if not num or not text:
                    self._json_resp(400, {"ok": False, "msg": "参数缺少 num 或 text"})
                    return

                sms_id = str(time.time())
                r = serial_780.command("send_sms", timeout=8, id=sms_id, num=num, text=text)
                if r.get("ok"):
                    save_outbox_sms(sms_id, num, text, r.get("status", "queued"))
                    self._json_resp(200, {"ok": True, "id": sms_id, "msg": "已提交给 780 发送"})
                    return
                else:
                    save_outbox_sms(sms_id, num, text, "failed")
                    self._json_resp(502, {"ok": False, "msg": f"780 拒绝: {r.get('error', r.get('status'))}"})

            except Exception as e:
                self._json_resp(500, {"ok": False, "msg": f"服务端异常: {e}"})

        # 主动定向消耗 4G 流量保号
        elif path == "/api/data/consume":
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode("utf-8")
                req_data = json.loads(body)
                kb = req_data.get("kb", 10)

                r = serial_780.command("consume", timeout=35, kb=kb)
                inner = r.get("result", {})
                if r.get("ok"):
                    save_consume_log(inner.get("requested_kb", kb), inner.get("consumed_kb", 0), inner.get("http_code", 200))
                self._json_resp(200, {"ok": r.get("ok"), **inner})
            except Exception as e:
                self._json_resp(500, {"ok": False, "msg": str(e)})

        # 4G 流量数据开关
        elif path == "/api/data/switch":
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode("utf-8")
                req_data = json.loads(body)

                # v2 串口版暂不提供 4G NAT 开关（RNDIS 已弃用），保留接口兼容
                self._json_resp(200, {"ok": False, "msg": "v2 串口版暂不支持 4G 共享开关"})
            except Exception as e:
                self._json_resp(500, {"ok": False, "msg": str(e)})

        # 流量统计清零
        elif path == "/api/data/traffic/reset":
            try:
                # v2 串口版：流量统计由 780 侧上报，清零暂不提供，返回当前值
                r = serial_780.command("get_traffic", timeout=5)
                self._json_resp(200, {"ok": bool(r.get("ok")), "msg": "v2 串口版暂不支持清零", "traffic": r.get("traffic")})
            except Exception as e:
                self._json_resp(500, {"ok": False, "msg": str(e)})
                return

        else:
            self._json_resp(404, {"error": "Not Found"})

    def log_message(self, fmt, *args):
        if "/api/status" not in self.path and "/api/sms/inbox" not in self.path:
            print(f"[HTTP] {self.client_address[0]} - {fmt % args}")

def main():
    init_db()
    t = threading.Thread(target=serial_worker, daemon=True)
    t.start()

    port = CONFIG["SERVER_PORT"]
    server = HTTPServer(("0.0.0.0", port), SMSRequestHandler)
    print(f"[Server] SMS Relay & Web UI 已启动在 http://0.0.0.0:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Server] 正在退出...")
        server.server_close()

if __name__ == "__main__":
    main()
