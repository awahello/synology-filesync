#!/usr/bin/python3
# Copyright (c) 2026 AWA <https://www.akkdiy.cn>. All rights reserved.
"""FileSync 公共模块：路径常量、SQLite 状态库、DSM 会话认证、通用工具。

设计要点
--------
* 状态库放在 /var/packages/FileSync/var，权限 0700，仅套件账号可读。
* CGI 与 worker 两个进程共用同一个 SQLite（WAL 模式 + busy_timeout）。
* 认证完全复用 DSM 的 authenticate.cgi，套件不保存任何登录口令。
"""

import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

try:  # grp/pwd 是 Unix 专有模块，缺失时仅影响本地调试
    import grp
    import pwd
except ImportError:  # pragma: no cover
    grp = None
    pwd = None

PKG = "FileSync"
PKG_VAR = Path("/var/packages/FileSync/var")
DB_PATH = PKG_VAR / "state.sqlite3"
KEYS_DIR = PKG_VAR / "keys"
KNOWN_HOSTS = PKG_VAR / "known_hosts"
CSRF_PATH = PKG_VAR / "csrf.key"
PID_PATH = PKG_VAR / "worker.pid"
LOG_PATH = PKG_VAR / "worker.log"

APP_VERSION = "0.3.14-0001"
AUTH_CGI = "/usr/syno/synoman/webman/modules/authenticate.cgi"
AUTH_DIAGNOSTIC = "DSM 会话验证未完成。"
MAX_BODY = 262144

# 回收站目录名：删除跟随产生的删除会先移到这里，而不是直接抹掉。
TRASH_NAME = ".filesync-trash"
# 群晖自身产生的缩略图/回收站目录必须默认排除，否则会产生海量无意义传输。
DEFAULT_EXCLUDES = [
    "@eaDir",
    "#recycle",
    "#snapshot",
    "#recycle/*",
    "@tmp",
    "@download",
    TRASH_NAME,
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    "*.tmp",
    "*.part",
    "~$*",
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS sites (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    kind          TEXT NOT NULL DEFAULT 'linux',
    host          TEXT NOT NULL DEFAULT '',
    port          INTEGER NOT NULL DEFAULT 22,
    ssh_user      TEXT NOT NULL DEFAULT 'root',
    key_id        TEXT NOT NULL DEFAULT '',
    remote_prefix TEXT NOT NULL DEFAULT '',
    note          TEXT NOT NULL DEFAULT '',
    last_check    TEXT NOT NULL DEFAULT '',
    last_ok       INTEGER NOT NULL DEFAULT 0,
    last_check_msg TEXT NOT NULL DEFAULT '',
    caps_json     TEXT NOT NULL DEFAULT '{}',
    created       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS keys (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    public_line TEXT NOT NULL,
    created     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    site_a        TEXT NOT NULL,
    dir_a         TEXT NOT NULL,
    site_b        TEXT NOT NULL,
    dir_b         TEXT NOT NULL,
    mode          TEXT NOT NULL DEFAULT 'both',
    delete_policy TEXT NOT NULL DEFAULT 'trash',
    excludes      TEXT NOT NULL DEFAULT '',
    interval_min  INTEGER NOT NULL DEFAULT 10,
    start_delay_min INTEGER NOT NULL DEFAULT 0,
    retry_min     INTEGER NOT NULL DEFAULT 60,
    backup_enabled INTEGER NOT NULL DEFAULT 0,
    backup_dir    TEXT NOT NULL DEFAULT '',
    backup_keep   INTEGER NOT NULL DEFAULT 7,
    backup_interval_hour INTEGER NOT NULL DEFAULT 24,
    backup_delay_min INTEGER NOT NULL DEFAULT 5,
    backup_due_at TEXT NOT NULL DEFAULT '',
    backup_last   TEXT NOT NULL DEFAULT '',
    backup_msg    TEXT NOT NULL DEFAULT '',
    enabled       INTEGER NOT NULL DEFAULT 1,
    next_run      TEXT NOT NULL DEFAULT '',
    last_run      TEXT NOT NULL DEFAULT '',
    last_status   TEXT NOT NULL DEFAULT '',
    last_message  TEXT NOT NULL DEFAULT '',
    created       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS baseline (
    rule_id  TEXT NOT NULL,
    rel      TEXT NOT NULL,
    a_size   INTEGER NOT NULL,
    a_mtime  REAL NOT NULL,
    b_size   INTEGER NOT NULL,
    b_mtime  REAL NOT NULL,
    PRIMARY KEY (rule_id, rel)
);

CREATE TABLE IF NOT EXISTS runs (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id  TEXT NOT NULL,
    started  TEXT NOT NULL,
    finished TEXT NOT NULL DEFAULT '',
    status   TEXT NOT NULL DEFAULT 'running',
    up_count INTEGER NOT NULL DEFAULT 0,
    down_count INTEGER NOT NULL DEFAULT 0,
    del_count  INTEGER NOT NULL DEFAULT 0,
    bytes      INTEGER NOT NULL DEFAULT 0,
    message    TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- 多站互备：一组 3 个以上站点，逐路径选出最新版本后统一收敛
CREATE TABLE IF NOT EXISTS groups (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    delete_policy TEXT NOT NULL DEFAULT 'trash',
    excludes      TEXT NOT NULL DEFAULT '',
    interval_min  INTEGER NOT NULL DEFAULT 10,
    start_delay_min INTEGER NOT NULL DEFAULT 0,
    retry_min     INTEGER NOT NULL DEFAULT 60,
    backup_enabled INTEGER NOT NULL DEFAULT 0,
    backup_dir    TEXT NOT NULL DEFAULT '',
    backup_keep   INTEGER NOT NULL DEFAULT 7,
    backup_interval_hour INTEGER NOT NULL DEFAULT 24,
    backup_delay_min INTEGER NOT NULL DEFAULT 5,
    backup_due_at TEXT NOT NULL DEFAULT '',
    backup_last   TEXT NOT NULL DEFAULT '',
    backup_msg    TEXT NOT NULL DEFAULT '',
    enabled       INTEGER NOT NULL DEFAULT 1,
    next_run      TEXT NOT NULL DEFAULT '',
    last_run      TEXT NOT NULL DEFAULT '',
    last_status   TEXT NOT NULL DEFAULT '',
    last_message  TEXT NOT NULL DEFAULT '',
    created       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    id       TEXT PRIMARY KEY,
    group_id TEXT NOT NULL,
    site_id  TEXT NOT NULL,
    dir      TEXT NOT NULL,
    position INTEGER NOT NULL DEFAULT 0
);

-- 多站基线只记"上次同步后的权威版本"，同步完成后所有成员应当一致
CREATE TABLE IF NOT EXISTS group_baseline (
    group_id TEXT NOT NULL,
    rel      TEXT NOT NULL,
    size     INTEGER NOT NULL,
    mtime    REAL NOT NULL,
    PRIMARY KEY (group_id, rel)
);

CREATE INDEX IF NOT EXISTS idx_members_group ON group_members(group_id);
CREATE INDEX IF NOT EXISTS idx_gbaseline_group ON group_baseline(group_id);
CREATE INDEX IF NOT EXISTS idx_runs_rule ON runs(rule_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_baseline_rule ON baseline(rule_id);
"""

DEFAULT_SETTINGS = {
    "trash_days": "30",        # 回收站保留天数，0 表示永久保留
    "conflict_copy": "0",      # 冲突时直接覆盖（0）；覆盖前保留败方副本（1）
    "worker_paused": "0",      # 全局暂停调度
}

# 0.3.8 新增列：老库（CREATE TABLE IF NOT EXISTS 不会补列）在这里补上，
# 否则升级后 SELECT * 读不到新字段，保存规则会直接报错。
MIGRATIONS = {
    "rules": {
        "start_delay_min": "INTEGER NOT NULL DEFAULT 0",
        "retry_min": "INTEGER NOT NULL DEFAULT 60",
        "backup_enabled": "INTEGER NOT NULL DEFAULT 0",
        "backup_dir": "TEXT NOT NULL DEFAULT ''",
        "backup_keep": "INTEGER NOT NULL DEFAULT 7",
        "backup_interval_hour": "INTEGER NOT NULL DEFAULT 24",
        "backup_delay_min": "INTEGER NOT NULL DEFAULT 5",
        "backup_due_at": "TEXT NOT NULL DEFAULT ''",
        "backup_last": "TEXT NOT NULL DEFAULT ''",
        "backup_msg": "TEXT NOT NULL DEFAULT ''",
    },
    "groups": {
        "start_delay_min": "INTEGER NOT NULL DEFAULT 0",
        "retry_min": "INTEGER NOT NULL DEFAULT 60",
        "backup_enabled": "INTEGER NOT NULL DEFAULT 0",
        "backup_dir": "TEXT NOT NULL DEFAULT ''",
        "backup_keep": "INTEGER NOT NULL DEFAULT 7",
        "backup_interval_hour": "INTEGER NOT NULL DEFAULT 24",
        "backup_delay_min": "INTEGER NOT NULL DEFAULT 5",
        "backup_due_at": "TEXT NOT NULL DEFAULT ''",
        "backup_last": "TEXT NOT NULL DEFAULT ''",
        "backup_msg": "TEXT NOT NULL DEFAULT ''",
    },
}


# --------------------------------------------------------------------------
# 目录与数据库
# --------------------------------------------------------------------------
def ensure_private_dir():
    PKG_VAR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(PKG_VAR, 0o700)
    except OSError:
        pass


def connect_db():
    ensure_private_dir()
    db = sqlite3.connect(str(DB_PATH), timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=30000")
    db.executescript(SCHEMA)
    ensure_columns(db)
    relax_db_permissions()
    seed_local_site(db)
    seed_settings(db)
    return db


def relax_db_permissions():
    """调度进程是 root、网页端是套件账号，两边都要写同一个库。

    不放开的话，谁先建库谁就是属主，另一个进程直接写不进去（readonly database）。
    目录本身是 0700，只有套件账号和 root 能进，所以库文件放开到 0666 不会多出暴露面。
    """
    for suffix in ("", "-wal", "-shm"):
        path = Path(str(DB_PATH) + suffix)
        if not path.exists():
            continue
        try:
            os.chmod(path, 0o666)
        except OSError:
            pass


def ensure_columns(db):
    """给老库补新增的列。SQLite 的 ADD COLUMN 是常数时间操作，重复执行无害。"""
    for table, columns in MIGRATIONS.items():
        existing = {row["name"] for row in db.execute("PRAGMA table_info(%s)" % table)}
        for name, decl in columns.items():
            if name not in existing:
                db.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, name, decl))
    db.commit()


def seed_settings(db):
    for key, value in DEFAULT_SETTINGS.items():
        db.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (key, value))
    db.commit()


def get_settings(db):
    result = dict(DEFAULT_SETTINGS)
    for row in db.execute("SELECT key,value FROM settings"):
        result[row["key"]] = row["value"]
    return result


def set_setting(db, key, value):
    if key not in DEFAULT_SETTINGS:
        raise ValueError("不支持的设置项")
    db.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
               (key, str(value)))
    db.commit()


def seed_local_site(db):
    """本机站点固定存在，不可删除，作为同步的一端。"""
    row = db.execute("SELECT id FROM sites WHERE id='local'").fetchone()
    if row:
        return
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = "本机"
    db.execute(
        "INSERT OR IGNORE INTO sites(id,name,kind,host,port,ssh_user,created) "
        "VALUES('local',?,'local','',22,'','%s')" % now_iso(),
        ("本机 · " + hostname,),
    )
    db.commit()


# --------------------------------------------------------------------------
# 时间
# --------------------------------------------------------------------------
def now_local():
    return dt.datetime.now().astimezone()


def now_iso():
    return now_local().isoformat(timespec="seconds")


def parse_iso(value):
    if not value:
        return None
    try:
        result = dt.datetime.fromisoformat(value)
        return result.astimezone() if result.tzinfo else result.astimezone()
    except (ValueError, TypeError):
        return None


def human_size(num):
    try:
        num = float(num)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0 or unit == "TB":
            return ("%d %s" % (num, unit)) if unit == "B" else ("%.1f %s" % (num, unit))
        num /= 1024.0
    return "%.1f TB" % num


# --------------------------------------------------------------------------
# DSM 会话认证（与 DSM 官方第三方套件做法一致）
# --------------------------------------------------------------------------
def authenticate():
    global AUTH_DIAGNOSTIC
    cookie_present = bool(os.environ.get("HTTP_COOKIE", "").strip())
    from urllib.parse import parse_qs

    query_token = parse_qs(os.environ.get("QUERY_STRING", ""), keep_blank_values=False).get("SynoToken", [""])[0]
    header_token = os.environ.get("HTTP_X_SYNO_TOKEN", "").strip()
    syno_token = header_token or query_token.strip()
    token_present = bool(syno_token and len(syno_token) <= 512 and re.fullmatch(r"[A-Za-z0-9._-]+", syno_token))

    user = os.environ.get("REMOTE_USER", "").strip()
    if user and len(user) <= 128 and not any(ord(c) < 32 for c in user):
        AUTH_DIAGNOSTIC = ""
        return user

    # 启动器是 setuid 到套件账号的；调用 DSM 认证程序时要临时降回 CGI 身份，
    # 否则认证程序自身的执行权限校验会失败。
    real_uid = os.getuid()
    drop_euid = None
    if hasattr(os, "geteuid") and os.geteuid() != real_uid:
        def drop_to_cgi_user():
            os.seteuid(real_uid)
        drop_euid = drop_to_cgi_user

    proc = None
    try:
        auth_env = os.environ.copy()
        if token_present:
            auth_env["HTTP_X_SYNO_TOKEN"] = syno_token
            if not query_token:
                current_query = auth_env.get("QUERY_STRING", "")
                auth_env["QUERY_STRING"] = current_query + ("&" if current_query else "") + "SynoToken=" + syno_token
        proc = subprocess.run(
            [AUTH_CGI], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=5, check=False, close_fds=True,
            preexec_fn=drop_euid, env=auth_env,
        )
        lines = proc.stdout.decode("utf-8", "replace").replace("\x00", "").splitlines() if proc.stdout else []
        user = next(
            (line.strip() for line in lines
             if line.strip() and not line.lstrip().lower().startswith(("content-type:", "status:"))),
            "",
        )
    except PermissionError:
        user = ""
        AUTH_DIAGNOSTIC = "DSM Cookie 已到达：" + ("有" if cookie_present else "无") + "；DSM 认证程序拒绝以 CGI 身份执行（权限不足）。"
    except subprocess.TimeoutExpired:
        user = ""
        AUTH_DIAGNOSTIC = "DSM 认证程序响应超时。"
    except OSError as exc:
        user = ""
        AUTH_DIAGNOSTIC = "DSM 认证程序无法启动（系统错误 " + str(exc.errno or 0) + "）。"
    except Exception as exc:  # noqa: BLE001
        user = ""
        AUTH_DIAGNOSTIC = "DSM 认证检查失败（" + type(exc).__name__ + "）。"

    if not user or len(user) > 128 or any(ord(c) < 32 for c in user):
        if not AUTH_DIAGNOSTIC or AUTH_DIAGNOSTIC == "DSM 会话验证未完成。":
            if not cookie_present:
                AUTH_DIAGNOSTIC = "请求没有收到 DSM 会话 Cookie。"
            elif proc is not None and proc.returncode != 0:
                AUTH_DIAGNOSTIC = ("已收到 DSM Cookie；SynoToken" + ("已" if token_present else "未")
                                   + "传入认证程序，但 DSM 认证程序返回错误代码 " + str(proc.returncode) + "。")
            else:
                AUTH_DIAGNOSTIC = "已收到 DSM Cookie，但 DSM 认证程序未返回用户名。"
        return None
    AUTH_DIAGNOSTIC = ""
    return user


def application_authorized(user):
    """本套件只允许 DSM administrators 群组成员使用。"""
    if grp is None or pwd is None:
        return True  # 非 Unix 环境（仅本地调试）
    try:
        admin_gid = grp.getgrnam("administrators").gr_gid
        account = pwd.getpwnam(user)
        return admin_gid in os.getgrouplist(user, account.pw_gid)
    except (KeyError, OSError, AttributeError):
        return False


# --------------------------------------------------------------------------
# CSRF / 输出
# --------------------------------------------------------------------------
def csrf_key():
    ensure_private_dir()
    try:
        fd = os.open(str(CSRF_PATH), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(secrets.token_bytes(32))
    except FileExistsError:
        pass
    except OSError:
        pass
    try:
        os.chmod(CSRF_PATH, 0o600)
        data = CSRF_PATH.read_bytes()
        if len(data) == 32:
            return data
    except OSError:
        pass
    raise RuntimeError("无法建立套件私有 CSRF 密钥")


def new_csrf(owner):
    payload = str(int(time.time())) + "." + secrets.token_urlsafe(16)
    sig = hmac.new(csrf_key(), (owner + "\n" + payload).encode(), hashlib.sha256).hexdigest()
    return payload + "." + sig


def valid_csrf(owner, token):
    try:
        ts, nonce, sig = token.split(".", 2)
        if abs(int(time.time()) - int(ts)) > 3600 or len(nonce) < 16:
            return False
        payload = ts + "." + nonce
        expected = hmac.new(csrf_key(), (owner + "\n" + payload).encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)
    except Exception:  # noqa: BLE001
        return False


def same_origin():
    origin = os.environ.get("HTTP_ORIGIN", "")
    host = os.environ.get("HTTP_HOST", "")
    if not origin or not host or len(host) > 255 or any(c in host for c in "\r\n/\\"):
        return False
    scheme = "https" if os.environ.get("HTTPS", "").lower() in ("on", "1", "https") else "http"
    try:
        from urllib.parse import urlsplit
        parsed = urlsplit(origin)
        return (parsed.scheme == scheme and parsed.netloc.lower() == host.lower()
                and parsed.path in ("", "/") and not parsed.query and not parsed.fragment)
    except Exception:  # noqa: BLE001
        return False


def json_out(data, status="200 OK"):
    body = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write((
        "Status: " + status + "\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: SAMEORIGIN\r\n\r\n"
    ).encode())
    sys.stdout.buffer.write(body)


def text_out(text, status="200 OK", ctype="text/html; charset=utf-8", nonce=""):
    csp = ("default-src 'self'; connect-src 'self'; img-src 'self' data:; "
           "style-src 'nonce-" + nonce + "'; script-src 'nonce-" + nonce + "'; "
           "object-src 'none'; base-uri 'none'; frame-ancestors 'self'")
    sys.stdout.write(
        "Status: " + status + "\r\n"
        "Content-Type: " + ctype + "\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: SAMEORIGIN\r\n"
        "Content-Security-Policy: " + csp + "\r\n"
        "Referrer-Policy: same-origin\r\n\r\n"
    )
    sys.stdout.write(text)


# --------------------------------------------------------------------------
# 校验工具
# --------------------------------------------------------------------------
def clean_text(value, max_len=120, allow_empty=True):
    if not isinstance(value, str):
        return "" if allow_empty else None
    value = value.strip()
    if len(value) > max_len:
        return None
    if any(ord(c) < 32 for c in value):
        return None
    if not value and not allow_empty:
        return None
    return value


ABS_PATH_RE = re.compile(r"^/[^\x00-\x1f]{0,1023}$")


def clean_abs_path(value):
    """绝对路径校验：必须以 / 开头，不含控制字符，不允许 .. 穿越。"""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > 1024 or not ABS_PATH_RE.match(value):
        return None
    parts = [p for p in value.split("/") if p]
    if any(p in (".", "..") for p in parts):
        return None
    return "/" + "/".join(parts) if parts else "/"


def norm_rel(path):
    """把扫描结果规整成统一的相对路径：去掉 ./ 前缀、统一分隔符。"""
    if not isinstance(path, str):
        return ""
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path.lstrip("/")


def paths_overlap(a, b):
    """两个绝对路径是否相同或互为父子。

    备份目录一旦落在同步目录里面，备份文件本身会被当成新文件同步到别的站，
    下一轮再打包一次，很快就把盘写满，所以必须挡掉。
    """
    if not a or not b:
        return False

    def norm(path):
        # 统一分隔符：DSM 上是 /，本地调试时可能是 \
        return (path or "").replace("\\", "/").rstrip("/") or "/"

    left, right = norm(a), norm(b)
    if left == right:
        return True
    return left.startswith(right + "/") or right.startswith(left + "/")