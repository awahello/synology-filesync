"""多站互备测试：N 路决策 + 三阶段执行（拉回→推送→删除）。"""
import os
import shutil
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "pkg" / "share"))

import common

SANDBOX = Path(tempfile.mkdtemp(prefix="filesync-group-"))
common.PKG_VAR = SANDBOX / "var"
common.DB_PATH = common.PKG_VAR / "state.sqlite3"
common.KEYS_DIR = common.PKG_VAR / "keys"
common.KNOWN_HOSTS = common.PKG_VAR / "known_hosts"

import engine
import remote


def check(label, cond, detail=""):
    print(("  PASS  " if cond else "  FAIL  ") + label + ("  " + str(detail)[:180] if detail else ""))
    if not cond:
        raise SystemExit("测试失败：" + label)


# ==========================================================================
# 纯函数：N 路决策
# ==========================================================================
print("=== N 路决策 ===")

# 1. 三站只有一个有该文件 → 以它为准
plan = engine.decide_group({
    "a": {"x.txt": (100, 1000)},
    "b": {},
    "c": {},
}, {}, True)
check("单站新增 → 该站胜出", plan["winners"] == {"x.txt": "a"}, plan)

# 2. 三站版本不同 → mtime 最大者胜
plan = engine.decide_group({
    "a": {"x.txt": (100, 1000)},
    "b": {"x.txt": (100, 3000)},
    "c": {"x.txt": (100, 2000)},
}, {}, True)
check("mtime 最新者胜", plan["winners"] == {"x.txt": "b"}, plan)
check("落败方被记录为冲突", sorted(m for _, m in plan["conflicts"]) == ["a", "c"], plan["conflicts"])

# 3. 删除多数决：两站删、一站保留 → 删除
plan = engine.decide_group({
    "a": {"x.txt": (100, 1000)},
    "b": {},
    "c": {},
}, {"x.txt": (100, 1000)}, True)
check("2 删 1 存 → 跟随删除", plan["delete"] == ["x.txt"] and not plan["winners"], plan)

# 4. 一站删、两站保留 → 保留并推回去
plan = engine.decide_group({
    "a": {},
    "b": {"x.txt": (100, 1000)},
    "c": {"x.txt": (100, 1000)},
}, {"x.txt": (100, 1000)}, True)
check("1 删 2 存 → 保留并回推", plan["winners"] == {"x.txt": "b"} and not plan["delete"], plan)

# 5. 关闭删除跟随后永不删除
plan = engine.decide_group({
    "a": {"x.txt": (100, 1000)},
    "b": {},
    "c": {},
}, {"x.txt": (100, 1000)}, False)
check("不跟随删除 → 保留", plan["winners"] == {"x.txt": "a"} and not plan["delete"], plan)

# 6. 三站完全一致
plan = engine.decide_group({
    "a": {"x.txt": (100, 1000)},
    "b": {"x.txt": (100, 1000)},
    "c": {"x.txt": (100, 1000)},
}, {}, True)
check("三站一致 → 无操作", plan["same"] == 1 and not plan["winners"], plan)

# 7. 两站有、一站缺（基线有）→ 推给缺的那个
plan = engine.decide_group({
    "a": {"x.txt": (100, 1000)},
    "b": {"x.txt": (100, 1000)},
    "c": {},
}, {"x.txt": (100, 1000)}, True)
check("2 存 1 缺 → 推给缺失成员", plan["winners"] == {"x.txt": "a"} and not plan["delete"], plan)

# 8. 两站场景下 1:1 平局 → 保守保留
plan = engine.decide_group({
    "a": {"x.txt": (100, 1000)},
    "b": {},
}, {"x.txt": (100, 1000)}, True)
check("两站 1:1 平局 → 保留", plan["winners"] == {"x.txt": "a"} and not plan["delete"], plan)

# 9. 三站都删了 → 基线自然清除
plan = engine.decide_group({"a": {}, "b": {}, "c": {}}, {"x.txt": (100, 1000)}, True)
check("三站都删 → 无需操作", not plan["winners"] and not plan["delete"], plan)


# ==========================================================================
# 端到端：三个本地目录模拟三站
# ==========================================================================
print("\n=== 端到端（三个目录模拟三站）===")

DIRS = {}
for name in ("nas", "siteA", "siteC"):
    d = SANDBOX / name
    d.mkdir()
    DIRS[name] = d


def write(path, content, mtime=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if mtime:
        os.utime(path, (mtime, mtime))


def tree(name):
    root = DIRS[name]
    result = {}
    for p in sorted(Path(root).rglob("*")):
        if p.is_file():
            rel = str(p.relative_to(root)).replace("\\", "/")
            if rel.startswith(".filesync-trash/"):
                continue
            result[rel] = p.read_text(encoding="utf-8")
    return result


db = common.connect_db()
now = common.now_iso()
site_ids = {}
for name in ("nas", "siteA", "siteC"):
    sid = str(uuid.uuid4())
    site_ids[name] = sid
    # 测试里三个都用 local 类型，避免真的去连 SSH
    db.execute("INSERT INTO sites(id,name,kind,host,port,ssh_user,created) VALUES(?,?,'local','',22,'',?)",
               (sid, name, now))
db.execute("UPDATE sites SET kind='local' WHERE id=?", (site_ids["nas"],))
db.commit()

group_id = str(uuid.uuid4())
db.execute("INSERT INTO groups(id,name,delete_policy,excludes,interval_min,enabled,next_run,created)"
           " VALUES(?,?,'trash','',10,1,?,?)", (group_id, "三站测试", now, now))
for pos, name in enumerate(("nas", "siteA", "siteC")):
    db.execute("INSERT INTO group_members(id,group_id,site_id,dir,position) VALUES(?,?,?,?,?)",
               (str(uuid.uuid4()), group_id, site_ids[name], str(DIRS[name]), pos))
db.commit()

logs = []


def sync(tag):
    print("\n--- " + tag + " ---")
    logs.clear()
    stats = engine.run_group(db, group_id, trigger="test", log=lambda lv, m: logs.append((lv, m)))
    for level, msg in logs:
        if level in ("warn", "error", "good"):
            print("   [" + level + "] " + msg)
    return stats


# --- 场景 1：A 站有新文件，应经本机推给 C
print("\n场景 1：A 站新增文件 → 拉回本机 → 推给 C")
t0 = time.time() - 300
write(DIRS["siteA"] / "from_a.txt", "A 的内容", t0)
stats = sync("第一轮")
check("本机拿到 A 的文件", tree("nas").get("from_a.txt") == "A 的内容", tree("nas"))
check("C 站也拿到了", tree("siteC").get("from_a.txt") == "A 的内容", tree("siteC"))
check("统计 pulled=1 pushed=1", stats["pulled"] == 1 and stats["pushed"] == 1, stats)

# --- 场景 2：C 站改成更新版本 → 应以 C 为准覆盖本机和 A
print("\n场景 2：C 站改成更新版本 → C 的版本胜出")
write(DIRS["siteC"] / "from_a.txt", "C 改过的新版本", time.time() - 10)
stats = sync("第二轮")
check("本机被更新成 C 的版本", tree("nas")["from_a.txt"] == "C 改过的新版本", tree("nas"))
check("A 站也被更新", tree("siteA")["from_a.txt"] == "C 改过的新版本", tree("siteA"))

# --- 场景 3：三站同时改同一文件 → mtime 最新者胜，其他进冲突副本
print("\n场景 3：三站各改一版 → 最新者胜，其余留副本")
base_t = time.time()
write(DIRS["siteA"] / "race.txt", "A 版本", base_t - 300)
write(DIRS["siteC"] / "race.txt", "C 版本", base_t - 200)
write(DIRS["nas"] / "race.txt", "NAS 版本", base_t - 100)   # 最新
stats = sync("第三轮")
check("本机（最新）胜出", tree("nas")["race.txt"] == "NAS 版本", tree("nas"))
check("A 站被覆盖为最新", tree("siteA")["race.txt"] == "NAS 版本", tree("siteA"))
check("C 站被覆盖为最新", tree("siteC")["race.txt"] == "NAS 版本", tree("siteC"))
check("记录到 2 个冲突", stats["conflicts"] == 2, stats)
copies = list(DIRS["siteA"].glob(".filesync-trash/conflicts/*/race.txt"))
check("落败版本已留副本", len(copies) == 1, copies)

# --- 场景 4：两个站删除、一个站保留 → 多数决，全部删除
print("\n场景 4：A 和 C 都删了 race.txt，本机还留着 → 多数决删除")
os.unlink(DIRS["siteA"] / "race.txt")
os.unlink(DIRS["siteC"] / "race.txt")
stats = sync("第四轮")
check("本机的也被删掉", "race.txt" not in tree("nas"), tree("nas"))
check("统计 deleted=1", stats["deleted"] == 1, stats)

# --- 场景 5：只有一站删除，另两站保留 → 保留并推回去
print("\n场景 5：只有 A 删了 from_a.txt → 少数删除，推回去")
os.unlink(DIRS["siteA"] / "from_a.txt")
stats = sync("第五轮")
check("本机保留文件", "from_a.txt" in tree("nas"), tree("nas"))
check("A 站被恢复", tree("siteA").get("from_a.txt") == "C 改过的新版本", tree("siteA"))
check("没有发生删除", stats["deleted"] == 0, stats)

# --- 场景 6：幂等
print("\n场景 6：没有变化时不产生任何传输")
stats = sync("第六轮")
check("零传输", stats["pulled"] == 0 and stats["pushed"] == 0 and stats["deleted"] == 0, stats)
check("三站完全一致", tree("nas") == tree("siteA") == tree("siteC"),
      (tree("nas"), tree("siteA"), tree("siteC")))

# --- 场景 7：预演不产生任何改动
print("\n场景 7：预演只读")
write(DIRS["siteC"] / "preview_only.txt", "不该被同步", time.time() - 5)
before = tree("nas")
result = engine.test_group(db, group_id)
after = tree("nas")
check("预演没有改动本机", before == after, after)
check("预演统计正确", result["update"] >= 1, result)

print("\n全部多站测试通过")
shutil.rmtree(SANDBOX, ignore_errors=True)
