"""老库升级测试：缺列、缺表、基线没有 slot 时都能自动补齐，bootstrap 不能挂。

0.3.27 踩过的坑：source_backups 表是 0.3.23 建的，0.3.27 又加了 boot_delay_min，
老库没有这一列 → 读它就抛 IndexError → 整个 bootstrap 500 → 界面显示
「服务器响应格式错误」。
"""

import io
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "pkg" / "share"))

import common

SANDBOX = Path(tempfile.mkdtemp(prefix="filesync-upgrade-"))
common.PKG_VAR = SANDBOX / "var"
common.DB_PATH = common.PKG_VAR / "state.sqlite3"
common.KEYS_DIR = common.PKG_VAR / "keys"
common.KNOWN_HOSTS = common.PKG_VAR / "known_hosts"
common.CSRF_PATH = common.PKG_VAR / "csrf.key"
SANDBOX.joinpath("var").mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------- 造一个 0.3.22 的库
LEGACY = """
CREATE TABLE sites (id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'linux',
  host TEXT NOT NULL DEFAULT '', port INTEGER NOT NULL DEFAULT 22, ssh_user TEXT NOT NULL DEFAULT 'root',
  key_id TEXT NOT NULL DEFAULT '', remote_prefix TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
  last_check TEXT NOT NULL DEFAULT '', last_ok INTEGER NOT NULL DEFAULT 0,
  last_check_msg TEXT NOT NULL DEFAULT '', caps_json TEXT NOT NULL DEFAULT '{}', created TEXT NOT NULL);

CREATE TABLE rules (id TEXT PRIMARY KEY, name TEXT NOT NULL, site_a TEXT NOT NULL, dir_a TEXT NOT NULL,
  site_b TEXT NOT NULL, dir_b TEXT NOT NULL, mode TEXT NOT NULL DEFAULT 'both',
  delete_policy TEXT NOT NULL DEFAULT 'trash', excludes TEXT NOT NULL DEFAULT '',
  interval_min INTEGER NOT NULL DEFAULT 10, backup_enabled INTEGER NOT NULL DEFAULT 0,
  backup_dir TEXT NOT NULL DEFAULT '', backup_keep INTEGER NOT NULL DEFAULT 7,
  backup_interval_hour INTEGER NOT NULL DEFAULT 24, backup_delay_min INTEGER NOT NULL DEFAULT 5,
  backup_due_at TEXT NOT NULL DEFAULT '', backup_force INTEGER NOT NULL DEFAULT 0,
  backup_last TEXT NOT NULL DEFAULT '', backup_msg TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1, next_run TEXT NOT NULL DEFAULT '',
  last_run TEXT NOT NULL DEFAULT '', last_status TEXT NOT NULL DEFAULT '',
  last_message TEXT NOT NULL DEFAULT '', created TEXT NOT NULL);

CREATE TABLE groups (id TEXT PRIMARY KEY, name TEXT NOT NULL, delete_policy TEXT NOT NULL DEFAULT 'trash',
  excludes TEXT NOT NULL DEFAULT '', interval_min INTEGER NOT NULL DEFAULT 10,
  backup_enabled INTEGER NOT NULL DEFAULT 0, backup_dir TEXT NOT NULL DEFAULT '',
  backup_keep INTEGER NOT NULL DEFAULT 7, backup_interval_hour INTEGER NOT NULL DEFAULT 24,
  backup_delay_min INTEGER NOT NULL DEFAULT 5, backup_due_at TEXT NOT NULL DEFAULT '',
  backup_force INTEGER NOT NULL DEFAULT 0, backup_last TEXT NOT NULL DEFAULT '',
  backup_msg TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
  next_run TEXT NOT NULL DEFAULT '', last_run TEXT NOT NULL DEFAULT '',
  last_status TEXT NOT NULL DEFAULT '', last_message TEXT NOT NULL DEFAULT '', created TEXT NOT NULL);

CREATE TABLE group_members (id TEXT PRIMARY KEY, group_id TEXT NOT NULL, site_id TEXT NOT NULL,
  dir TEXT NOT NULL, position INTEGER NOT NULL DEFAULT 0);

CREATE TABLE group_baseline (group_id TEXT NOT NULL, rel TEXT NOT NULL,
  size INTEGER NOT NULL, mtime REAL NOT NULL, PRIMARY KEY (group_id, rel));

CREATE TABLE baseline (rule_id TEXT NOT NULL, rel TEXT NOT NULL, a_size INTEGER NOT NULL,
  a_mtime REAL NOT NULL, b_size INTEGER NOT NULL, b_mtime REAL NOT NULL,
  PRIMARY KEY (rule_id, rel));

CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT NOT NULL, started TEXT NOT NULL,
  finished TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'running',
  up_count INTEGER NOT NULL DEFAULT 0, down_count INTEGER NOT NULL DEFAULT 0,
  del_count INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0,
  message TEXT NOT NULL DEFAULT '');

CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

legacy = sqlite3.connect(str(common.DB_PATH))
legacy.executescript(LEGACY)
legacy.execute("INSERT INTO sites(id,name,kind,created) VALUES('local','本机 · NAS','local','2026-10-01')")
legacy.execute("INSERT INTO rules(id,name,site_a,dir_a,site_b,dir_b,created) "
               "VALUES('r-old','老规则','local','/volume1/a','local','/volume1/b','2026-10-01')")
legacy.execute("INSERT INTO groups(id,name,created) VALUES('g-old','老同步组','2026-10-01')")
legacy.execute("INSERT INTO group_baseline(group_id,rel,size,mtime) VALUES('g-old','a.txt',10,1000)")
legacy.commit()
legacy.close()

import cgi_app


def check(label, cond, detail=""):
    print(("  PASS  " if cond else "  FAIL  ") + label + ("  " + str(detail)[:200] if detail else ""))
    if not cond:
        raise SystemExit("测试失败：" + label)


print("=== 老库自动补列 ===")
db = common.connect_db()

rule_cols = {r["name"] for r in db.execute("PRAGMA table_info(rules)")}
check("rules 补上执行方式三列",
      {"schedule_kind", "run_time", "weekday"} <= rule_cols, sorted(rule_cols))
check("rules 补上开机延迟", "boot_delay_min" in rule_cols)
check("rules 保留老字段", {"start_delay_min", "retry_min"} <= rule_cols)

group_cols = {r["name"] for r in db.execute("PRAGMA table_info(groups)")}
check("groups 补上执行方式与开机延迟",
      {"schedule_kind", "run_time", "weekday", "boot_delay_min"} <= group_cols, sorted(group_cols))

member_cols = {r["name"] for r in db.execute("PRAGMA table_info(group_members)")}
check("group_members 补上 slot", "slot" in member_cols, sorted(member_cols))

base_cols = {r["name"] for r in db.execute("PRAGMA table_info(group_baseline)")}
check("group_baseline 重建后带 slot", "slot" in base_cols, sorted(base_cols))
row = db.execute("SELECT slot,rel,size FROM group_baseline WHERE group_id='g-old'").fetchone()
check("老基线归到第 1 组", row and row["slot"] == 1 and row["rel"] == "a.txt", dict(row) if row else None)

check("source_backups 表已创建",
      bool({r["name"] for r in db.execute("PRAGMA table_info(source_backups)")}))

print("\n=== 老数据仍可读 ===")
data = cgi_app.api_bootstrap(db)
check("bootstrap 不报错", data["ok"] is True)
check("老规则还在", [r["name"] for r in data["rules"]] == ["老规则"], data["rules"])
check("老规则默认按间隔执行", data["rules"][0]["schedule_kind"] == "interval", data["rules"][0])
check("老规则开机延迟默认 30", data["rules"][0]["boot_delay_min"] == 30, data["rules"][0]["boot_delay_min"])
check("老同步组还在", [g["name"] for g in data["groups"]] == ["老同步组"], data["groups"])
check("源码备份列表为空", data["source_backups"] == [])

print("\n=== 模拟 0.3.23 的源码备份老表（缺 boot_delay_min）===")
db.close()
common.DB_PATH.unlink()
legacy = sqlite3.connect(str(common.DB_PATH))
legacy.executescript(LEGACY)
legacy.executescript("""
CREATE TABLE source_backups (id TEXT PRIMARY KEY, name TEXT NOT NULL, site_id TEXT NOT NULL,
  src_dir TEXT NOT NULL, target_dir TEXT NOT NULL, schedule_kind TEXT NOT NULL DEFAULT 'daily',
  run_time TEXT NOT NULL DEFAULT '02:00', weekday INTEGER NOT NULL DEFAULT 0,
  interval_hour INTEGER NOT NULL DEFAULT 24, keep INTEGER NOT NULL DEFAULT 7,
  excludes TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
  next_run TEXT NOT NULL DEFAULT '', last_run TEXT NOT NULL DEFAULT '',
  last_status TEXT NOT NULL DEFAULT '', last_msg TEXT NOT NULL DEFAULT '', created TEXT NOT NULL);
INSERT INTO source_backups(id,name,site_id,src_dir,target_dir,created)
VALUES('s-old','老备份任务','local','/volume1/web','/volume1/backup','2026-10-31');
""")
legacy.commit()
legacy.close()

db = common.connect_db()
cols = {r["name"] for r in db.execute("PRAGMA table_info(source_backups)")}
check("源码备份补上 boot_delay_min", "boot_delay_min" in cols, sorted(cols))
data = cgi_app.api_bootstrap(db)
check("bootstrap 仍不报错", data["ok"] is True)
check("老备份任务读得出来", [t["name"] for t in data["source_backups"]] == ["老备份任务"],
      data["source_backups"])
check("老备份任务开机延迟默认 30", data["source_backups"][0]["boot_delay_min"] == 30)

print("\n老库升级测试全部通过")
