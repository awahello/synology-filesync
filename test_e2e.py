"""端到端测试：用两个本地目录模拟两个站点，跑完整的 engine.run_rule 流程。"""
import os
import shutil
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "pkg" / "share"))

import common

# 把状态库重定向到临时目录，避免依赖 /var/packages
SANDBOX = Path(tempfile.mkdtemp(prefix="filesync-test-"))
common.PKG_VAR = SANDBOX / "var"
common.DB_PATH = common.PKG_VAR / "state.sqlite3"
common.KEYS_DIR = common.PKG_VAR / "keys"
common.KNOWN_HOSTS = common.PKG_VAR / "known_hosts"
common.CSRF_PATH = common.PKG_VAR / "csrf.key"

import engine
import remote

DIR_A = SANDBOX / "siteA"
DIR_B = SANDBOX / "siteB"
DIR_A.mkdir()
DIR_B.mkdir()


def write(path, content, mtime=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if mtime:
        os.utime(path, (mtime, mtime))


def tree(root):
    result = {}
    for p in sorted(Path(root).rglob("*")):
        if p.is_file():
            rel = str(p.relative_to(root)).replace("\\", "/")
            if rel.startswith(".filesync-trash/"):
                continue  # 回收站不参与一致性比较
            result[rel] = p.read_text(encoding="utf-8")
    return result


def check(label, condition, detail=""):
    print(("  PASS  " if condition else "  FAIL  ") + label + ("  " + detail if detail else ""))
    if not condition:
        raise SystemExit("测试失败：" + label)


db = common.connect_db()
# 本测试验证「冲突保留副本」，显式开启（产品默认已改为直接覆盖）
common.set_setting(db, "conflict_copy", "1")
now = common.now_iso()
db.execute("INSERT INTO sites(id,name,kind,host,port,ssh_user,created) VALUES('siteB','B站','local','',22,'',?)", (now,))
db.commit()

rule_id = str(uuid.uuid4())
db.execute(
    "INSERT INTO rules(id,name,site_a,dir_a,site_b,dir_b,mode,delete_policy,excludes,interval_min,enabled,next_run,created)"
    " VALUES(?,?,'local',?,'siteB',?,'both','trash','',10,1,?,?)",
    (rule_id, "测试双向", str(DIR_A), str(DIR_B), now, now),
)
db.commit()

logs = []
log = lambda level, msg: logs.append((level, msg))


def sync(tag):
    print("\n=== " + tag + " ===")
    stats = engine.run_rule(db, rule_id, trigger="test", log=log)
    for level, msg in logs[-6:]:
        print("   [" + level + "] " + msg)
    return stats


# ---------------------------------------------------------------- 场景 1
print("\n场景 1：A 端新增文件，应单向传到 B")
t0 = time.time() - 300
write(DIR_A / "photo1.txt", "hello A", t0)
write(DIR_A / "sub" / "photo2.txt", "nested A", t0)
stats = sync("第一次同步")
check("A 的 2 个文件传到 B", tree(DIR_B) == {"photo1.txt": "hello A", "sub/photo2.txt": "nested A"}, str(tree(DIR_B)))
check("统计 up=2", stats["up"] == 2, str(stats))

# ---------------------------------------------------------------- 场景 2
print("\n场景 2：B 端新增文件，应回流到 A（双向）")
write(DIR_B / "note.txt", "from B", time.time() - 200)
stats = sync("第二次同步")
check("B 的新文件回流到 A", tree(DIR_A).get("note.txt") == "from B")
check("统计 down=1", stats["down"] == 1, str(stats))

# ---------------------------------------------------------------- 场景 3
print("\n场景 3：A 修改文件且时间更新，B 应被覆盖为最新")
newer = time.time() - 10
write(DIR_A / "photo1.txt", "hello A v2", newer)
stats = sync("第三次同步")
check("B 收到最新版本", tree(DIR_B)["photo1.txt"] == "hello A v2", str(tree(DIR_B)))
check("统计 up=1", stats["up"] == 1, str(stats))

# ---------------------------------------------------------------- 场景 4
print("\n场景 4：删除跟随——B 删掉文件，A 也删（进回收站）")
os.unlink(DIR_B / "sub" / "photo2.txt")
stats = sync("第四次同步")
check("A 端文件被跟随删除", "sub/photo2.txt" not in tree(DIR_A), str(tree(DIR_A)))
check("统计 deleted=1", stats["deleted"] == 1, str(stats))
trash_files = list((DIR_A / ".filesync-trash").rglob("photo2.txt"))
check("删除的文件进了回收站", len(trash_files) == 1, str(trash_files))

# ---------------------------------------------------------------- 场景 5
print("\n场景 5：两端都改同一文件，mtime 新的胜出，旧版进冲突副本")
write(DIR_A / "note.txt", "A edited old", time.time() - 100)
write(DIR_B / "note.txt", "B edited new", time.time() - 5)
stats = sync("第五次同步")
check("新版本胜出并同步到 A", tree(DIR_A)["note.txt"] == "B edited new", str(tree(DIR_A)))
check("统计 conflicts=1", stats["conflicts"] == 1, str(stats))
conflict_copies = list((DIR_A / ".filesync-trash").rglob("note.txt"))
check("败方副本已保留", len(conflict_copies) >= 1, str(conflict_copies))

# ---------------------------------------------------------------- 场景 6
print("\n场景 6：幂等性——没有变化时不应产生任何传输")
stats = sync("第六次同步")
check("无传输", stats["up"] == 0 and stats["down"] == 0 and stats["deleted"] == 0, str(stats))
check("两端一致", tree(DIR_A) == tree(DIR_B))

# ---------------------------------------------------------------- 场景 7
print("\n场景 7：排除规则生效（@eaDir 与 *.log 不应同步）")
db.execute("UPDATE rules SET excludes='*.log' WHERE id=?", (rule_id,))
db.commit()
write(DIR_A / "debug.log", "log", time.time() - 10)
write(DIR_A / "@eaDir" / "thumb.jpg", "thumb", time.time() - 10)
stats = sync("第七次同步")
check("*.log 被排除", "debug.log" not in tree(DIR_B))
check("@eaDir 被排除", not any("@eaDir" in k for k in tree(DIR_B)))

print("\n全部端到端场景通过")
print("测试目录：" + str(SANDBOX))
shutil.rmtree(SANDBOX, ignore_errors=True)
