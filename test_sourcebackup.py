"""源码备份测试：本机打包与轮转、远程流式打包、四种备份方式排期、接口校验。"""

import datetime as dt
import io
import json
import os
import sys
import tempfile
import time
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "pkg" / "share"))

import common

SANDBOX = Path(tempfile.mkdtemp(prefix="filesync-src-"))
common.PKG_VAR = SANDBOX / "var"
common.DB_PATH = common.PKG_VAR / "state.sqlite3"
common.KEYS_DIR = common.PKG_VAR / "keys"
common.KNOWN_HOSTS = common.PKG_VAR / "known_hosts"
common.CSRF_PATH = common.PKG_VAR / "csrf.key"

import cgi_app
import sourcebackup


class FakeStdout:
    def __init__(self):
        self.buf = io.BytesIO()
        self.buffer = self

    def write(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.buf.write(data)
        return len(data)

    def flush(self):
        pass

    def value(self):
        return self.buf.getvalue().decode("utf-8", "replace")


def run(argv, method="GET", query="", body=None, extra_env=None):
    os.environ["REMOTE_USER"] = "admin"
    os.environ["REQUEST_METHOD"] = method
    os.environ["QUERY_STRING"] = query
    os.environ["HTTP_COOKIE"] = "id=abc"
    os.environ["HTTP_HOST"] = "nas:5000"
    for key in ("HTTP_X_CSRF_TOKEN", "HTTP_ORIGIN", "CONTENT_LENGTH"):
        os.environ.pop(key, None)
    if extra_env:
        os.environ.update(extra_env)
    if body is not None:
        raw = json.dumps(body).encode("utf-8")
        os.environ["CONTENT_LENGTH"] = str(len(raw))
        sys.stdin = type("S", (), {"buffer": io.BytesIO(raw)})()
    old, old_argv = sys.stdout, sys.argv
    sys.argv = list(argv)
    sys.stdout = FakeStdout()
    try:
        cgi_app.main()
        output = sys.stdout.value()
    finally:
        sys.stdout, sys.argv = old, old_argv
    head, _, payload = output.partition("\r\n\r\n")
    return head, payload


def check(label, cond, detail=""):
    print(("  PASS  " if cond else "  FAIL  ") + label + ("  " + str(detail)[:160] if detail else ""))
    if not cond:
        raise SystemExit("测试失败：" + label)


def make_tree(root):
    """造一棵典型网站目录：正常文件 + 日志 + 缓存 + @eaDir 缩略图。"""
    (root / "sub").mkdir(parents=True)
    (root / "cache").mkdir()
    (root / "@eaDir").mkdir()
    (root / "index.php").write_text("<?php echo 1;", encoding="utf-8")
    (root / "sub" / "app.js").write_text("console.log(1)", encoding="utf-8")
    (root / "debug.log").write_text("noise", encoding="utf-8")
    (root / "cache" / "page.html").write_text("cached", encoding="utf-8")
    (root / "@eaDir" / "thumb.jpg").write_bytes(b"thumb")
    return root


def make_db():
    db = common.connect_db()
    return db


def insert_task(db, **fields):
    task = {
        "name": "博客源码", "site_id": "local",
        "src_dir": "/volume1/web/blog", "target_dir": "/volume1/backup/source",
        "schedule_kind": "daily", "run_time": "02:00", "weekday": 0,
        "interval_hour": 24, "keep": 7, "excludes": "*.log\ncache/", "enabled": 1,
    }
    task.update(fields)
    import uuid
    task_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO source_backups(id,name,site_id,src_dir,target_dir,schedule_kind,run_time,"
        "weekday,interval_hour,keep,excludes,enabled,next_run,created) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (task_id, task["name"], task["site_id"], task["src_dir"], task["target_dir"],
         task["schedule_kind"], task["run_time"], task["weekday"], task["interval_hour"],
         task["keep"], task["excludes"], task["enabled"], "", common.now_iso()),
    )
    db.commit()
    return db.execute("SELECT * FROM source_backups WHERE id=?", (task_id,)).fetchone()


# ---------------------------------------------------------------- 页面
print("=== 页面 ===")
head, html = run(["cgi_app.py", "index"])
check("返回 200", "200 OK" in head, head.splitlines()[0])
check("含源码备份表单", 'id="srcName"' in html and 'id="srcKind"' in html)
check("含源码备份列表", 'id="sourceList"' in html)
check("备份方式四种", all(v in html for v in ('value="daily"', 'value="weekly"', 'value="interval"', 'value="boot"')))
check("保留份数可填 0", 'id="srcKeep" type="number" min="0"' in html)

head, body = run(["cgi_app.py"], query="action=bootstrap")
data = json.loads(body)
check("bootstrap 含 source_backups", isinstance(data.get("source_backups"), list), data.get("source_backups"))
check("新库默认没有源码备份任务", data["source_backups"] == [])

csrf = "unused"  # 后面用页面里的 token
head, html = run(["cgi_app.py", "index"])
csrf = html.split("const CSRF = '")[1].split("'")[0]

# ---------------------------------------------------------------- 接口校验
print("\n=== 接口校验 ===")
base = {"action": "save_source_backup", "name": "博客源码", "site_id": "local",
        "src_dir": "/volume1/web/blog", "target_dir": "/volume1/backup/source",
        "schedule_kind": "daily", "run_time": "02:00", "keep": 7}


def post(payload):
    head, body = run(["cgi_app.py"], method="POST", body=payload,
                     extra_env={"HTTP_X_CSRF_TOKEN": csrf})
    return head, json.loads(body)


head, res = post(dict(base, name=""))
check("缺名称被拒", res["ok"] is False and "任务名称" in res["error"], res)
head, res = post(dict(base, src_dir="relative/path"))
check("相对路径被拒", res["ok"] is False and "绝对路径" in res["error"], res)
head, res = post(dict(base, run_time="25:00"))
check("时间格式被拒", res["ok"] is False and "HH:MM" in res["error"], res)
head, res = post(dict(base, schedule_kind="hourly"))
check("未知备份方式被拒", res["ok"] is False and "备份方式" in res["error"], res)
head, res = post(dict(base, target_dir="/volume1/web/blog/backup"))
check("备份目录在源目录里被拒", res["ok"] is False and "源目录里面" in res["error"], res)

head, res = post(base)
check("合法任务保存成功", res["ok"] is True and res["id"], res)
saved_id = res["id"]
check("返回下次执行时间", bool(res.get("next_run")), res.get("next_run"))

head, body = run(["cgi_app.py"], query="action=bootstrap")
task = [t for t in json.loads(body)["source_backups"] if t["id"] == saved_id][0]
check("任务回到 bootstrap", task["name"] == "博客源码" and task["keep"] == 7, task["name"])
check("默认保留 7 份", task["keep"] == 7)

# ---------------------------------------------------------------- 本机打包
print("\n=== 本机打包与轮转 ===")
src = make_tree(SANDBOX / "web" / "blog")
target = SANDBOX / "backup" / "source"
db = make_db()
row = insert_task(db, src_dir=str(src), target_dir=str(target), keep=2)

info = sourcebackup.run_task(db, row)
check("生成 zip 包", info["name"].endswith(".zip") and os.path.exists(info["path"]), info["name"])
check("包名带任务名前缀", info["name"].startswith("博客源码-"), info["name"])

with zipfile.ZipFile(info["path"]) as zf:
    names = zf.namelist()
check("包含源码文件", "blog/index.php" in names and "blog/sub/app.js" in names, names)
check("排除 @eaDir", not any("@eaDir" in n for n in names), names)
check("排除 cache/", not any("/cache/" in n for n in names), names)
check("排除 *.log", not any(n.endswith(".log") for n in names), names)

row = db.execute("SELECT * FROM source_backups WHERE id=?", (row["id"],)).fetchone()
check("状态写回成功", row["last_status"] == "ok" and "成功" in row["last_msg"], row["last_msg"])

# 再打两份，keep=2 只留最新两份
for _ in range(2):
    time.sleep(1.05)
    sourcebackup.run_task(db, row)
packs = sourcebackup.list_packs(row)
check("按份数轮转只留 2 份", len(packs) == 2, [p["name"] for p in packs])

# keep=0 表示不限
row0 = db.execute("SELECT * FROM source_backups WHERE id=?", (row["id"],)).fetchone()
db.execute("UPDATE source_backups SET keep=0 WHERE id=?", (row["id"],))
db.commit()
row0 = db.execute("SELECT * FROM source_backups WHERE id=?", (row["id"],)).fetchone()
time.sleep(1.05)
sourcebackup.run_task(db, row0)
packs = sourcebackup.list_packs(row0)
check("保留 0 份=不限，不清理", len(packs) == 3, len(packs))

# 日志写进 runs 表
runs = db.execute("SELECT status,message FROM runs WHERE rule_id=?", ("srcbak:" + row["id"],)).fetchall()
check("写入备份日志", len(runs) >= 3 and runs[0]["status"] == "ok", len(runs))

head, body = run(["cgi_app.py"], query="action=logs&id=srcbak:" + row["id"])
check("日志接口支持 srcbak 前缀", json.loads(body)["ok"] is True, body[:120])

# ---------------------------------------------------------------- 远程打包
print("\n=== 远程打包（模拟 ssh 流）===")
remote_target = SANDBOX / "backup" / "remote"
db.execute("INSERT INTO sites(id,name,kind,host,port,ssh_user,key_id,created) "
           "VALUES('vps','VPS 站点','linux','jp.example.com',22,'root','',?)",
           (common.now_iso(),))
db.commit()
row_r = insert_task(db, name="VPS 源码", site_id="vps", src_dir="/var/www/site",
                    target_dir=str(remote_target), schedule_kind="weekly",
                    run_time="03:30", weekday=5, keep=1)
original = sourcebackup._run_ssh_to_file


def fake_ssh(site, command, output, timeout=None):
    Path(output).write_bytes(b"fake-tar-stream")
    return 0, ""


sourcebackup._run_ssh_to_file = fake_ssh
try:
    info = sourcebackup.run_task(db, row_r)
finally:
    sourcebackup._run_ssh_to_file = original
check("远程包为 tar.gz", info["name"].endswith(".tar.gz"), info["name"])
check("远程包落盘", os.path.exists(info["path"]))
check("远程包大小正确", info["size"] == len(b"fake-tar-stream"), info["size"])

# ---------------------------------------------------------------- 排期
print("\n=== 排期 ===")
base_time = dt.datetime(2026, 10, 31, 23, 0).astimezone()  # 周六 23:00

daily = {"schedule_kind": "daily", "run_time": "02:00", "weekday": 0, "interval_hour": 24}
check("每天：过了 02:00 排到明天", sourcebackup.scheduled_after(daily, base_time).day == 1,
      sourcebackup.scheduled_after(daily, base_time))

weekly = {"schedule_kind": "weekly", "run_time": "03:30", "weekday": 0, "interval_hour": 24}
nxt = sourcebackup.scheduled_after(weekly, base_time)
check("每周：排到下周一 03:30", nxt.weekday() == 0 and (nxt.hour, nxt.minute) == (3, 30), nxt)

interval = {"schedule_kind": "interval", "run_time": "02:00", "weekday": 0, "interval_hour": 6}
check("按间隔：+6 小时", sourcebackup.scheduled_after(interval, base_time) == base_time + dt.timedelta(hours=6))

boot = {"schedule_kind": "boot", "run_time": "02:00", "weekday": 0, "interval_hour": 24,
        "boot_delay_min": 30}
check("开机后：+30 分钟", sourcebackup.scheduled_after(boot, base_time) == base_time + dt.timedelta(minutes=30))
boot90 = dict(boot, boot_delay_min=90)
check("开机后：按配置的延迟", sourcebackup.scheduled_after(boot90, base_time) == base_time + dt.timedelta(minutes=90))

check("失败后 30 分钟重试",
      abs((common.parse_iso(sourcebackup.next_run_after(False, daily)) - common.now_local()).total_seconds() - 1800) < 30)

# ---------------------------------------------------------------- 开机排期
print("\n=== 开机后备份 ===")
db.execute("UPDATE source_backups SET schedule_kind='boot', next_run='', enabled=1 WHERE id=?", (row["id"],))
db.execute("DELETE FROM settings WHERE key='srcbak_boot'")
db.commit()
sourcebackup.initialize_schedule(db)
boot_row = db.execute("SELECT next_run FROM source_backups WHERE id=?", (row["id"],)).fetchone()
first = boot_row["next_run"]
check("开机任务按延迟排期（默认 30 分钟）", bool(first), first)

# 开机任务跑完必须清空 next_run，否则会变成「每 N 分钟备份一次」
task_row = db.execute("SELECT * FROM source_backups WHERE id=?", (row["id"],)).fetchone()
check("开机任务成功后清空下次执行", sourcebackup.next_run_after(True, task_row) == "",
      sourcebackup.next_run_after(True, task_row))
check("开机任务失败仍会重试", bool(sourcebackup.next_run_after(False, task_row)),
      sourcebackup.next_run_after(False, task_row))
sourcebackup.initialize_schedule(db)  # 同一次开机再启动一次（套件重启）
boot_row = db.execute("SELECT next_run FROM source_backups WHERE id=?", (row["id"],)).fetchone()
check("同一次开机不重复排期", boot_row["next_run"] == first, boot_row["next_run"])

# ---------------------------------------------------------------- 开关与删除
print("\n=== 启用 / 停用 / 删除 ===")
head, res = post({"action": "toggle_source_backup", "id": saved_id, "enabled": False})
check("可以停用", res["ok"] is True, res)
head, body = run(["cgi_app.py"], query="action=bootstrap")
task = [t for t in json.loads(body)["source_backups"] if t["id"] == saved_id][0]
check("停用后 enabled=0", task["enabled"] == 0)
check("停用后清空下次执行", task["next_run"] == "", task["next_run"])

head, res = post({"action": "toggle_source_backup", "id": saved_id, "enabled": True})
check("可以重新启用", res["ok"] is True and res.get("ok"), res)

head, res = post({"action": "run_source_backup", "id": saved_id})
check("立即备份排入队列", res["ok"] is True and res["scheduled"] is True, res)

head, res = post({"action": "delete_source_backup", "id": saved_id})
check("删除任务成功", res["ok"] is True, res)
head, body = run(["cgi_app.py"], query="action=bootstrap")
check("删除后不再出现", all(t["id"] != saved_id for t in json.loads(body)["source_backups"]))

print("\n源码备份全部测试通过")
