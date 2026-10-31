"""一个组多组目录：同 slot 互相同步、不同 slot 各管各的，基线不串。

顺带验证「执行方式」排期：每天 / 每周 / 开机后。
"""

import datetime as dt
import io
import json
import os
import sys
import tempfile
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "pkg" / "share"))

import common

SANDBOX = Path(tempfile.mkdtemp(prefix="filesync-multidir-"))
common.PKG_VAR = SANDBOX / "var"
common.DB_PATH = common.PKG_VAR / "state.sqlite3"
common.KEYS_DIR = common.PKG_VAR / "keys"
common.KNOWN_HOSTS = common.PKG_VAR / "known_hosts"
common.CSRF_PATH = common.PKG_VAR / "csrf.key"

import cgi_app
import engine


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
    print(("  PASS  " if cond else "  FAIL  ") + label + ("  " + str(detail)[:200] if detail else ""))
    if not cond:
        raise SystemExit("测试失败：" + label)


def post(payload, csrf):
    head, body = run(["cgi_app.py"], method="POST", body=payload,
                     extra_env={"HTTP_X_CSRF_TOKEN": csrf})
    return head, json.loads(body)


# ---------------------------------------------------------------- 搭环境
db = common.connect_db()
# 三个「站点」都用本机路径模拟：scan_side 对 kind=local 直接读盘
for sid, name in (("s1local", "本机"), ("s1a", "web"), ("s1b", "openwrt")):
    db.execute("INSERT OR IGNORE INTO sites(id,name,kind,host,port,ssh_user,created) "
               "VALUES(?,?,'local','',22,'',?)", (sid, name, common.now_iso()))
db.commit()

roots = {}
for tag in ("g1local", "g1a", "g1b", "g2local", "g2a", "g2b"):
    path = SANDBOX / tag
    path.mkdir(parents=True)
    roots[tag] = path

# 第 1 组：a.txt 只在 web 上有；第 2 组：b.txt 只在 openwrt 上有
(roots["g1a"] / "a.txt").write_text("来自 web", encoding="utf-8")
(roots["g2b"] / "b.txt").write_text("来自 openwrt", encoding="utf-8")
# 两组都有 index.php 但内容不同：基线必须分开记，否则会互相覆盖
(roots["g1local"] / "index.php").write_text("第一组", encoding="utf-8")
(roots["g2local"] / "index.php").write_text("第二组", encoding="utf-8")

group_id = str(uuid.uuid4())
db.execute("INSERT INTO groups(id,name,delete_policy,excludes,schedule_kind,run_time,weekday,"
           "interval_min,start_delay_min,retry_min,enabled,next_run,created) "
           "VALUES(?,?,'purge','','interval','02:00',0,10,0,60,1,'',?)",
           (group_id, "博客多目录", common.now_iso()))
members = [
    ("s1local", roots["g1local"], 1),
    ("s1a", roots["g1a"], 1),
    ("s1b", roots["g1b"], 1),
    ("s1local", roots["g2local"], 2),
    ("s1a", roots["g2a"], 2),
    ("s1b", roots["g2b"], 2),
]
for position, (site_id, path, slot) in enumerate(members):
    db.execute("INSERT INTO group_members(id,group_id,site_id,dir,slot,position) VALUES(?,?,?,?,?,?)",
               (str(uuid.uuid4()), group_id, site_id, str(path), slot, position))
db.commit()

# ---------------------------------------------------------------- 执行
print("=== 多组目录各自同步 ===")
stats = engine.run_group(db, group_id)
check("执行成功", stats["pulled"] >= 1 or stats["pushed"] >= 1, stats)

check("第 1 组：a.txt 传到了本机",
      (roots["g1local"] / "a.txt").exists() and (roots["g1b"] / "a.txt").exists())
check("第 1 组：a.txt 没串到第 2 组",
      not (roots["g2local"] / "a.txt").exists() and not (roots["g2a"] / "a.txt").exists())
check("第 2 组：b.txt 传到了本机",
      (roots["g2local"] / "b.txt").exists() and (roots["g2a"] / "b.txt").exists())
check("第 2 组：b.txt 没串到第 1 组",
      not (roots["g1local"] / "b.txt").exists() and not (roots["g1a"] / "b.txt").exists())

check("同名 index.php 各自保持原内容",
      (roots["g1local"] / "index.php").read_text(encoding="utf-8") == "第一组"
      and (roots["g2local"] / "index.php").read_text(encoding="utf-8") == "第二组")
check("index.php 也同步到了各自组的成员",
      (roots["g1a"] / "index.php").read_text(encoding="utf-8") == "第一组"
      and (roots["g2b"] / "index.php").read_text(encoding="utf-8") == "第二组")

rows = db.execute("SELECT slot,rel FROM group_baseline WHERE group_id=? ORDER BY slot,rel",
                  (group_id,)).fetchall()
baseline = [(r["slot"], r["rel"]) for r in rows]
check("基线按 slot 分开记", (1, "index.php") in baseline and (2, "index.php") in baseline, baseline)

# 第二轮应该「全部已一致」，不再传输
print("\n=== 第二轮：不应重复传输 ===")
stats2 = engine.run_group(db, group_id)
check("第二轮没有拉取/推送", stats2["pulled"] == 0 and stats2["pushed"] == 0, stats2)

# ---------------------------------------------------------------- 接口
print("\n=== 接口：保存多组目录 ===")
head, html = run(["cgi_app.py", "index"])
csrf = html.split("const CSRF = '")[1].split("'")[0]

base = {
    "action": "save_group", "name": "接口多目录", "delete_policy": "purge",
    "schedule_kind": "daily", "run_time": "03:15", "weekday": 0, "interval_min": 10,
    "members": [
        {"site_id": "s1local", "dir": "/volume1/web/usr", "slot": 1},
        {"site_id": "s1a", "dir": "/var/www/usr", "slot": 1},
        {"site_id": "s1local", "dir": "/volume1/web/tu", "slot": 2},
        {"site_id": "s1a", "dir": "/var/www/tu", "slot": 2},
    ],
}
head, res = post(base, csrf)
check("两组目录保存成功", res["ok"] is True, res)
new_id = res["id"]

head, body = run(["cgi_app.py"], query="action=bootstrap")
group = [g for g in json.loads(body)["groups"] if g["id"] == new_id][0]
check("成员带回 slot", sorted(m["slot"] for m in group["members"]) == [1, 1, 2, 2],
      [(m["site_id"], m["slot"]) for m in group["members"]])
check("执行方式已保存", group["schedule_kind"] == "daily" and group["run_time"] == "03:15", group["schedule_kind"])
nxt = common.parse_iso(group["next_run"])
check("每天 03:15 排期正确", (nxt.hour, nxt.minute) == (3, 15) and nxt > common.now_local(), group["next_run"])

head, res = post(dict(base, members=[
    {"site_id": "s1local", "dir": "/volume1/web/usr", "slot": 1},
    {"site_id": "s1a", "dir": "/var/www/usr", "slot": 1},
    {"site_id": "s1a", "dir": "/var/www/tu", "slot": 2},
]), csrf)
check("第 2 组只有 1 个成员被拒", res["ok"] is False and "第 2 组" in res["error"], res)

for sid in ("remote1", "remote2"):
    db.execute("INSERT OR IGNORE INTO sites(id,name,kind,host,port,ssh_user,created) "
               "VALUES(?,?,'linux','127.0.0.1',22,'root',?)", (sid, sid, common.now_iso()))
db.commit()
head, res = post(dict(base, members=[
    {"site_id": "s1local", "dir": "/volume1/web/usr", "slot": 1},
    {"site_id": "s1a", "dir": "/var/www/usr", "slot": 1},
    {"site_id": "remote1", "dir": "/var/www/tu", "slot": 2},
    {"site_id": "remote2", "dir": "/www/tu", "slot": 2},
]), csrf)
check("第 2 组没有本机被拒", res["ok"] is False and "第 2 组" in res["error"], res)

head, res = post(dict(base, members=[
    {"site_id": "s1local", "dir": "/volume1/web/usr", "slot": 1},
    {"site_id": "s1local", "dir": "/volume1/web/usr", "slot": 1},
    {"site_id": "s1a", "dir": "/var/www/usr", "slot": 1},
]), csrf)
check("同组重复目录被拒", res["ok"] is False and "重复" in res["error"], res)

# 3 组目录 × 3 站点 = 9 个成员，必须能保存（老的 8 个上限会挡住）
nine = []
for slot, tag in ((1, "usr"), (2, "tu"), (3, "rules")):
    nine += [
        {"site_id": "s1local", "dir": "/volume1/web/" + tag, "slot": slot},
        {"site_id": "s1a", "dir": "/var/www/" + tag, "slot": slot},
        {"site_id": "s1b", "dir": "/www/" + tag, "slot": slot},
    ]
head, res = post(dict(base, name="三组九成员", members=nine), csrf)
check("3 组 × 3 站 = 9 个成员可以保存", res["ok"] is True, res)

# ---------------------------------------------------------------- 排期
print("\n=== 执行方式 ===")
now = common.now_local()
daily = common.schedule_next({"schedule_kind": "daily", "run_time": "02:00"})
check("每天：下一次是 02:00", (daily.hour, daily.minute) == (2, 0) and daily > now, daily)

weekly = common.schedule_next({"schedule_kind": "weekly", "run_time": "03:30", "weekday": 0})
check("每周：下一次是周一 03:30", weekly.weekday() == 0 and (weekly.hour, weekly.minute) == (3, 30), weekly)

interval = common.schedule_next({"schedule_kind": "interval", "interval_min": 15}, now)
check("按间隔：+15 分钟", abs((interval - now).total_seconds() - 900) < 2, interval)

boot = common.schedule_next({"schedule_kind": "boot"}, now)
check("开机后：默认 +30 分钟", abs((boot - now).total_seconds() - 1800) < 2, boot)
boot20 = common.schedule_next({"schedule_kind": "boot", "boot_delay_min": 120}, now)
check("开机后：按配置的延迟", abs((boot20 - now).total_seconds() - 7200) < 2, boot20)

# ---------------------------------------------------------------- 开机延迟
print("\n=== 开机后执行：按配置延迟排期 ===")
import worker

gid = str(uuid.uuid4())
db.execute(
    "INSERT INTO groups(id,name,delete_policy,excludes,schedule_kind,run_time,weekday,"
    "boot_delay_min,interval_min,start_delay_min,retry_min,enabled,next_run,created) "
    "VALUES(?,?,'purge','','boot','02:00',0,45,10,0,60,1,'',?)",
    (gid, "开机组", common.now_iso()))
db.execute("DELETE FROM settings WHERE key='sync_boot'")
db.commit()
worker.initialize_schedule(db)
row = db.execute("SELECT next_run FROM groups WHERE id=?", (gid,)).fetchone()
gap = (common.parse_iso(row["next_run"]) - common.now_local()).total_seconds() / 60
check("开机组按 45 分钟延迟排期", 44 <= gap <= 46, "%.1f 分钟" % gap)

worker.initialize_schedule(db)  # 同一次开机再启动，不应重排
row2 = db.execute("SELECT next_run FROM groups WHERE id=?", (gid,)).fetchone()
check("同一次开机不重复排期", row2["next_run"] == row["next_run"], row2["next_run"])

print("\n多组目录与执行方式测试全部通过")
