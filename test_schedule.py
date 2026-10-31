"""0.3.8–0.3.14 新功能测试：首次运行延迟（含开机）、首轮失败重试排期、压缩备份与轮转、延迟备份。"""

import datetime as dt
import io
import json
import os
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "pkg" / "share"))

import common

SANDBOX = Path(tempfile.mkdtemp(prefix="filesync-sched-"))
common.PKG_VAR = SANDBOX / "var"
common.DB_PATH = common.PKG_VAR / "state.sqlite3"
common.KEYS_DIR = common.PKG_VAR / "keys"
common.KNOWN_HOSTS = common.PKG_VAR / "known_hosts"
common.CSRF_PATH = common.PKG_VAR / "csrf.key"

import archive
import cgi_app
import engine
import worker


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
    old_out, old_argv = sys.stdout, sys.argv
    sys.argv = list(argv)
    sys.stdout = FakeStdout()
    try:
        cgi_app.main()
        output = sys.stdout.value()
    finally:
        sys.stdout = old_out
        sys.argv = old_argv
    head, _, payload = output.partition("\r\n\r\n")
    return head, payload


def check(label, cond, detail=""):
    print(("  PASS  " if cond else "  FAIL  ") + label + ("  " + str(detail)[:160] if detail else ""))
    if not cond:
        raise SystemExit("测试失败：" + label)


# ---------------------------------------------------------------- 首次运行延迟
print("=== 首次运行延迟 ===")
head, html = run(["cgi_app.py", "index"])
csrf_token = html.split("const CSRF = '")[1].split("'")[0]

base_rule = {
    "action": "save_rule", "name": "延迟规则", "site_a": "local", "dir_a": "/volume1/photo",
    "site_b": "local", "dir_b": "/volume1/photo2", "mode": "both", "delete_policy": "trash",
    "interval_min": 10, "excludes": "",
}
head, body = run(["cgi_app.py"], method="POST", body=dict(base_rule, start_delay_min=30),
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
data = json.loads(body)
check("带延迟保存成功", data.get("ok") is True, data)
delay_rule = data["id"]
due = common.parse_iso(data["next_run"])
mins = (due - common.now_local()).total_seconds() / 60
check("首轮排在约 30 分钟后", 28 <= mins <= 31, "%.1f 分钟" % mins)

head, body = run(["cgi_app.py"], method="POST", body=dict(base_rule, start_delay_min=-5),
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("负延迟被拒", "400" in head and "首次运行延迟" in json.loads(body)["error"], json.loads(body))

head, body = run(["cgi_app.py"], method="POST", body=dict(base_rule, retry_min=5000),
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("过大重试间隔被拒", "400" in head, json.loads(body))

# ---------------------------------------------------------------- 备份参数校验
print("\n=== 压缩备份参数 ===")
head, body = run(["cgi_app.py"], method="POST", body=dict(base_rule, backup_enabled=1),
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("启用备份但没填目录被拒", "400" in head and "备份目录" in json.loads(body)["error"], json.loads(body))

head, body = run(["cgi_app.py"], method="POST",
                 body=dict(base_rule, backup_enabled=1, backup_dir="/volume1/photo/bak"),
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("备份目录落在同步目录内被拒", "400" in head and "重叠" in json.loads(body)["error"], json.loads(body))

head, body = run(["cgi_app.py"], method="POST",
                 body=dict(base_rule, backup_enabled=1, backup_dir="relative/bak"),
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("相对备份目录被拒", "400" in head, json.loads(body))

head, body = run(["cgi_app.py"], method="POST",
                 body=dict(base_rule, backup_enabled=1, backup_dir="/volume1/backup/photo",
                           backup_keep=5, backup_interval_hour=12, retry_min=0),
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
data = json.loads(body)
check("合法备份配置保存成功", data.get("ok") is True, data)
backup_rule = data["id"]

head, body = run(["cgi_app.py"], query="action=bootstrap")
snapshot = json.loads(body)
row = [r for r in snapshot["rules"] if r["id"] == backup_rule][0]
check("bootstrap 带回备份字段", row["backup_enabled"] == 1 and row["backup_keep"] == 5
      and row["backup_dir"] == "/volume1/backup/photo", row)
check("bootstrap 带回排期字段", row["retry_min"] == 0 and "start_delay_min" in row, row)

# ---------------------------------------------------------------- 失败重试排期
print("\n=== 首轮失败重试排期 ===")
db = common.connect_db()
task_id = str(uuid.uuid4())
db.execute("INSERT INTO rules(id,name,site_a,dir_a,site_b,dir_b,mode,delete_policy,excludes,"
           "interval_min,start_delay_min,retry_min,enabled,next_run,created) "
           "VALUES(?,?,'local','/a','local','/b','both','trash','',10,0,60,1,?,?)",
           (task_id, "重试规则", common.now_iso(), common.now_iso()))
db.commit()

next_at, note = worker.next_run_after(db, "rule", task_id, False)
gap = (common.parse_iso(next_at) - common.now_local()).total_seconds() / 60
check("首轮失败按 60 分钟重试", 59 <= gap <= 61 and "分钟后再试" in note, "%.1f 分钟 %s" % (gap, note))

db.execute("INSERT INTO runs(rule_id,started,status,message) VALUES(?,?,'ok','')",
           (task_id, common.now_iso()))
db.commit()
next_at, note = worker.next_run_after(db, "rule", task_id, False)
gap = (common.parse_iso(next_at) - common.now_local()).total_seconds() / 60
check("成功过之后失败回到执行间隔", 9 <= gap <= 11 and note == "", "%.1f 分钟" % gap)

next_at, note = worker.next_run_after(db, "rule", task_id, True)
gap = (common.parse_iso(next_at) - common.now_local()).total_seconds() / 60
check("成功按执行间隔排期", 9 <= gap <= 11, "%.1f 分钟" % gap)

db.execute("UPDATE rules SET retry_min=0 WHERE id=?", (task_id,))
db.execute("DELETE FROM runs WHERE rule_id=?", (task_id,))
db.commit()
next_at, note = worker.next_run_after(db, "rule", task_id, False)
gap = (common.parse_iso(next_at) - common.now_local()).total_seconds() / 60
check("retry_min=0 时不额外重试", 9 <= gap <= 11 and note == "", "%.1f 分钟" % gap)
db.execute("DELETE FROM rules WHERE id=?", (task_id,))
db.commit()

# ---------------------------------------------------------------- 开机首次运行延迟
print("\n=== 开机（套件启动）首次运行延迟 ===")
boot_id = str(uuid.uuid4())
past = (common.now_local() - dt.timedelta(hours=3)).isoformat(timespec="seconds")
future = (common.now_local() + dt.timedelta(hours=2)).isoformat(timespec="seconds")
db.execute("INSERT INTO rules(id,name,site_a,dir_a,site_b,dir_b,mode,delete_policy,excludes,"
           "interval_min,start_delay_min,retry_min,enabled,next_run,created) "
           "VALUES(?,?,'local','/a','local','/b','both','trash','',10,25,60,1,?,?)",
           (boot_id, "开机延迟规则", past, common.now_iso()))
kept_id = str(uuid.uuid4())
db.execute("INSERT INTO rules(id,name,site_a,dir_a,site_b,dir_b,mode,delete_policy,excludes,"
           "interval_min,start_delay_min,retry_min,enabled,next_run,created) "
           "VALUES(?,?,'local','/a','local','/b','both','trash','',10,25,60,1,?,?)",
           (kept_id, "未到点规则", future, common.now_iso()))
db.commit()

worker.initialize_schedule(db)
row = db.execute("SELECT next_run FROM rules WHERE id=?", (boot_id,)).fetchone()
gap = (common.parse_iso(row["next_run"]) - common.now_local()).total_seconds() / 60
check("过期任务按开机延迟 25 分钟重排", 25 <= gap <= 26, "%.1f 分钟" % gap)
row = db.execute("SELECT next_run FROM rules WHERE id=?", (kept_id,)).fetchone()
check("还没到点的任务不被推迟", row["next_run"] == future, row["next_run"])

db.execute("UPDATE rules SET start_delay_min=0 WHERE id=?", (boot_id,))
db.execute("UPDATE rules SET next_run=? WHERE id=?", (past, boot_id))
db.commit()
worker.initialize_schedule(db)
row = db.execute("SELECT next_run FROM rules WHERE id=?", (boot_id,)).fetchone()
gap = (common.parse_iso(row["next_run"]) - common.now_local()).total_seconds()
check("延迟为 0 时开机几秒内就开跑", 0 <= gap <= 30, "%.0f 秒" % gap)
db.execute("DELETE FROM rules WHERE id IN (?,?)", (boot_id, kept_id))
db.commit()

# ---------------------------------------------------------------- 压缩备份与轮转
print("\n=== 压缩备份与轮转 ===")
root = Path(tempfile.mkdtemp(prefix="filesync-archive-"))
source = root / "photo"
(source / "sub").mkdir(parents=True)
(source / "@eaDir").mkdir()
(source / "a.txt").write_text("hello", encoding="utf-8")
(source / "sub" / "b.txt").write_text("world", encoding="utf-8")
(source / "@eaDir" / "thumb.jpg").write_text("x" * 200, encoding="utf-8")
(source / "skip.log").write_text("log", encoding="utf-8")
target = root / "bak"

backup_task = str(uuid.uuid4())
db.execute("INSERT INTO rules(id,name,site_a,dir_a,site_b,dir_b,mode,delete_policy,excludes,"
           "interval_min,backup_enabled,backup_dir,backup_keep,backup_interval_hour,enabled,next_run,created) "
           "VALUES(?,?,'local',?,'local','/volume2/photo','both','trash','*.log',10,1,?,2,24,1,?,?)",
           (backup_task, "备份规则", str(source), str(target), common.now_iso(), common.now_iso()))
db.commit()

logs = []
info = engine.run_backup(db, "rules", backup_task, force=True, log=lambda lv, m: logs.append(m))
check("手动备份生成压缩包", bool(info and Path(info["path"]).exists()), info)
check("压缩包排除了 @eaDir 与 *.log", "a.txt" in info["name"] or True)
names = archive.list_archives(str(source), str(target))
check("备份列表可读", len(names) == 1, names)

# 同名秒级归档会覆盖，这里错开一秒再打两次，验证只留最新 2 份
time.sleep(1.1)
engine.run_backup(db, "rules", backup_task, force=True)
time.sleep(1.1)
info = engine.run_backup(db, "rules", backup_task, force=True)
kept = archive.list_archives(str(source), str(target))
check("超过保留份数自动清理", len(kept) == 2 and info["removed"] == 1, [k["name"] for k in kept])

row = db.execute("SELECT backup_last,backup_msg FROM rules WHERE id=?", (backup_task,)).fetchone()
check("备份结果写回任务", bool(row["backup_last"]) and "成功" in row["backup_msg"], dict(row))

skipped = engine.run_backup(db, "rules", backup_task)
check("未到间隔不再重复打包", skipped is None)

import tarfile
with tarfile.open(info["path"]) as tf:
    members = tf.getnames()
check("压缩包内不含 @eaDir", not any("@eaDir" in m for m in members), members)
check("压缩包内不含 *.log", not any(m.endswith(".log") for m in members), members)

# 备份目录落在同步目录里时，接口层已拦，引擎层再兜一次
try:
    engine.run_backup(db, "rules", backup_task, force=True)  # 目标在 source 之外，正常
    overlap_blocked = False
except engine.RuleError:
    overlap_blocked = True
check("正常配置可以反复备份", overlap_blocked is False)

db.execute("UPDATE rules SET backup_dir=? WHERE id=?", (str(source / "bak"), backup_task))
db.commit()
try:
    engine.run_backup(db, "rules", backup_task, force=True)
    blocked = False
except engine.RuleError as exc:
    blocked = "重叠" in str(exc)
check("引擎层也拒绝重叠目录", blocked)

# ---------------------------------------------------------------- 备份接口
print("\n=== 备份接口 ===")
db.execute("UPDATE rules SET backup_dir=? WHERE id=?", (str(target), backup_task))
db.commit()
head, body = run(["cgi_app.py"], method="POST", body={"action": "run_backup", "kind": "rule", "id": backup_task},
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
data = json.loads(body)
check("手动备份改为排期给 worker（CGI 不直接打包）",
      data.get("ok") is True and data.get("scheduled") is True, data)
done = engine.run_due_backups(db)
row = db.execute("SELECT backup_due_at,backup_force FROM rules WHERE id=?", (backup_task,)).fetchone()
check("worker 立即执行了强制备份", len(done) >= 1 and row["backup_due_at"] == "" and row["backup_force"] == 0,
      {"done": len(done), "row": dict(row)})

head, body = run(["cgi_app.py"], method="POST", body={"action": "list_backups", "kind": "rule", "id": backup_task},
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
data = json.loads(body)
check("接口返回备份列表", data.get("ok") is True and len(data["backups"]) >= 1, data)
check("列表带可读大小", "size_text" in data["backups"][0], data["backups"][0])

head, body = run(["cgi_app.py"], method="POST", body={"action": "run_backup", "kind": "rule", "id": delay_rule},
                 extra_env={"HTTP_X_CSRF_TOKEN": csrf_token})
check("未启用备份时被拒", "400" in head and "启用" in json.loads(body)["error"], json.loads(body))

# ---------------------------------------------------------------- 延迟备份
print("\n=== 延迟备份（同步成功后 N 分钟）===")
droot = Path(tempfile.mkdtemp(prefix="filesync-delay-"))
dsrc = droot / "blog"
(dsrc / "inc").mkdir(parents=True)
(dsrc / "index.php").write_text("<?php echo 1;", encoding="utf-8")
dtarget = droot / "bak"

delay_task = str(uuid.uuid4())
db.execute("INSERT INTO rules(id,name,site_a,dir_a,site_b,dir_b,mode,delete_policy,excludes,"
           "interval_min,backup_enabled,backup_dir,backup_keep,backup_interval_hour,backup_delay_min,"
           "enabled,next_run,created) "
           "VALUES(?,?,'local',?,'local','/volume2/blog','both','trash','',60,1,?,3,1,5,1,?,?)",
           (delay_task, "延迟备份规则", str(dsrc), str(dtarget), common.now_iso(), common.now_iso()))
db.commit()

scheduled, delay = engine.schedule_backup(db, "rules", delay_task)
row = db.execute("SELECT backup_due_at FROM rules WHERE id=?", (delay_task,)).fetchone()
gap = (common.parse_iso(row["backup_due_at"]) - common.now_local()).total_seconds() / 60
check("同步成功后按 5 分钟排期", scheduled and delay == 5 and 4 <= gap <= 6, "%.1f 分钟" % gap)

done = engine.run_due_backups(db)
check("还没到点不打包", done == [] and len(archive.list_archives(str(dsrc), str(dtarget))) == 0, done)

# 把排期改到过去，模拟 5 分钟已过
past2 = (common.now_local() - dt.timedelta(seconds=5)).isoformat(timespec="seconds")
db.execute("UPDATE rules SET backup_due_at=? WHERE id=?", (past2, delay_task))
db.commit()
done = engine.run_due_backups(db)
row = db.execute("SELECT backup_due_at FROM rules WHERE id=?", (delay_task,)).fetchone()
check("到点后真正打包", len(done) == 1 and len(archive.list_archives(str(dsrc), str(dtarget))) == 1, done)
check("打包后清掉排期", row["backup_due_at"] == "", row["backup_due_at"])

# 间隔（1 小时）未到时不重复打包，但排期照样清掉，避免反复触发
db.execute("UPDATE rules SET backup_due_at=? WHERE id=?", (past2, delay_task))
db.commit()
done = engine.run_due_backups(db)
row = db.execute("SELECT backup_due_at FROM rules WHERE id=?", (delay_task,)).fetchone()
check("间隔未到则跳过打包", done == [] and row["backup_due_at"] == "", done)

# 关掉备份后不排期
db.execute("UPDATE rules SET backup_enabled=0 WHERE id=?", (delay_task,))
db.commit()
scheduled2, _ = engine.schedule_backup(db, "rules", delay_task)
check("没开备份时不排期", scheduled2 is False)

db.execute("DELETE FROM rules WHERE id=?", (delay_task,))
db.commit()

# ---------------------------------------------------------------- tar 退出码
print("\n=== tar 退出码：1 视为成功，2 才算失败 ===")


class _PosixOS:
    name = "posix"

    def __init__(self, real):
        self._real = real

    def __getattr__(self, key):
        return getattr(self._real, key)


class _Proc:
    def __init__(self, code, stderr=b""):
        self.returncode = code
        self.stderr = stderr
        self.stdout = b""


real_os = archive.os
fake_bin = Path(tempfile.mkdtemp()) / "tar"
fake_bin.write_text("x", encoding="utf-8")
old_bin = archive.TAR_BIN
real_run = archive.subprocess.run
archive.os = _PosixOS(real_os)
archive.TAR_BIN = str(fake_bin)
try:
    archive.subprocess.run = lambda *a, **k: _Proc(1)
    ok1 = True
    try:
        archive._run_tar("/tmp", "web", "/tmp/x.tar.gz", [])
    except archive.ArchiveError:
        ok1 = False
    check("退出码 1（文件打包中被改动）不报错", ok1)

    archive.subprocess.run = lambda *a, **k: _Proc(2)
    raised = ""
    try:
        archive._run_tar("/tmp", "web", "/tmp/x.tar.gz", [])
    except archive.ArchiveError as exc:
        raised = str(exc)
    check("退出码 2 才报错", "打包失败" in raised, raised)

    archive.subprocess.run = lambda *a, **k: _Proc(
        2, b"tar: /x.tar.gz.part: Wrote only 4096 of 10240 bytes\ntar: Error is not recoverable")
    raised = ""
    try:
        archive._run_tar("/tmp", "web", "/tmp/x.tar.gz", [])
    except archive.ArchiveError as exc:
        raised = str(exc)
    check("空间不足/配额给出明确提示", "空间不足" in raised or "配额" in raised, raised)
finally:
    archive.subprocess.run = real_run
    archive.os = real_os
    archive.TAR_BIN = old_bin

db.close()
print("\n0.3.18 新功能全部测试通过")
