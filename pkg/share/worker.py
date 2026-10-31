#!/usr/bin/python3
# Copyright (c) 2026 AWA <https://www.akkdiy.cn>. All rights reserved.
"""FileSync 调度守护：按每条规则的间隔执行同步。

运行模型
--------
单进程常驻，每 20 秒扫一次待执行规则。规则执行是同步阻塞的（一条跑完再跑
下一条），因为文件同步本身是 IO/带宽密集型任务，并行只会互相拖慢并且让
带宽统计失真。单条规则内部由 engine 的文件锁保证不会被重复进入。
"""

import datetime as dt
import os
import signal
import sys
import time
import traceback

try:  # Windows 上没有 fcntl，仅影响本地调试，DSM 上始终可用
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

import common
import engine

STOP = False
TICK_SECONDS = 20
STARTUP_STAGGER = 12  # 开机后多条规则错开启动，避免同时抢带宽


def stop_handler(_signum, _frame):
    global STOP
    STOP = True


def log(message):
    sys.stdout.write("[%s] %s\n" % (common.now_iso(), message))
    sys.stdout.flush()


def compute_next(minutes, base=None):
    base = base or common.now_local()
    minutes = max(1, int(minutes or 10))
    return (base + dt.timedelta(minutes=minutes)).isoformat(timespec="seconds")


def acquire_singleton():
    """保证只有一个 worker 在跑。"""
    common.ensure_private_dir()
    if fcntl is None:
        return None
    fd = os.open(str(common.PKG_VAR / "worker.singleton"), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    os.ftruncate(fd, 0)
    os.write(fd, str(os.getpid()).encode())
    return fd


def write_pid():
    common.PID_PATH.write_text(str(os.getpid()), encoding="utf-8")
    try:
        os.chmod(common.PID_PATH, 0o600)
    except OSError:
        pass


def clear_pid():
    try:
        common.PID_PATH.unlink()
    except OSError:
        pass


def initialize_schedule(db):
    """启动时修正过期计划：已过期的规则错开几秒后执行，而不是一起冲上去。"""
    now = common.now_local()
    offset = 0
    for table in ("rules", "groups"):
        for row in db.execute("SELECT * FROM %s WHERE enabled=1 ORDER BY created" % table).fetchall():
            due = common.parse_iso(row["next_run"])
            if due is None or due <= now:
                target = (now + dt.timedelta(seconds=5 + offset)).isoformat(timespec="seconds")
                db.execute("UPDATE %s SET next_run=? WHERE id=?" % table, (target, row["id"]))
                offset += STARTUP_STAGGER
    db.commit()


def due_tasks(db):
    """返回 [(kind, row)]，kind 为 rule 或 group。"""
    now = common.now_local()
    result = []
    for kind, table in (("rule", "rules"), ("group", "groups")):
        for row in db.execute("SELECT * FROM %s WHERE enabled=1" % table).fetchall():
            due = common.parse_iso(row["next_run"])
            if due is None or due <= now:
                result.append((kind, row))
    return result


def run_task(db, kind, row):
    task_id = row["id"]
    label = "规则" if kind == "rule" else "同步组"
    log("开始%s「%s」（%s）" % (label, row["name"], task_id))
    started = time.time()
    try:
        if kind == "rule":
            stats = engine.run_rule(db, task_id, trigger="schedule", log=lambda lv, m: log("  " + m))
            log("%s「%s」完成，耗时 %.1f 秒：A→B %d / B→A %d / 删除 %d" % (
                label, row["name"], time.time() - started,
                stats["up"], stats["down"], stats["deleted"]))
        else:
            stats = engine.run_group(db, task_id, trigger="schedule", log=lambda lv, m: log("  " + m))
            log("%s「%s」完成，耗时 %.1f 秒：拉回 %d / 推送 %d / 删除 %d" % (
                label, row["name"], time.time() - started,
                stats["pulled"], stats["pushed"], stats["deleted"]))
    except (engine.RuleError, engine.GroupError) as exc:
        log("%s「%s」跳过：%s" % (label, row["name"], exc))
    except Exception as exc:  # noqa: BLE001
        log("%s「%s」失败：%s" % (label, row["name"], exc))
        log(traceback.format_exc().replace("\n", " | ")[:800])
    finally:
        # 无论成功失败都排下一轮，避免失败任务每 20 秒疯狂重试
        table = "rules" if kind == "rule" else "groups"
        fresh = db.execute("SELECT interval_min FROM %s WHERE id=?" % table, (task_id,)).fetchone()
        minutes = fresh["interval_min"] if fresh else 10
        db.execute("UPDATE %s SET next_run=? WHERE id=?" % table, (compute_next(minutes), task_id))
        db.commit()


def main():
    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)

    if fcntl is None:
        singleton = None
        log("当前平台不支持文件锁，跳过单实例检查（仅调试用）")
    else:
        singleton = acquire_singleton()
        if singleton is None:
            log("已有另一个调度进程在运行，本进程退出")
            return 0

    write_pid()
    log("FileSync 调度进程启动，PID %d" % os.getpid())

    db = common.connect_db()
    initialize_schedule(db)

    while not STOP:
        try:
            settings = common.get_settings(db)
            if settings.get("worker_paused") == "1":
                time.sleep(TICK_SECONDS)
                continue

            for kind, row in due_tasks(db):
                if STOP:
                    break
                run_task(db, kind, row)
        except Exception as exc:  # noqa: BLE001
            log("调度循环异常：%s" % exc)
            log(traceback.format_exc().replace("\n", " | ")[:800])
            time.sleep(5)

        for _ in range(TICK_SECONDS):
            if STOP:
                break
            time.sleep(1)

    log("FileSync 调度进程退出")
    clear_pid()
    try:
        os.close(singleton)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
