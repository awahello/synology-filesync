#!/usr/bin/python3
# Copyright (c) 2026 AWA <https://www.akkdiy.cn>. All rights reserved.
"""FileSync 调度守护：按每条规则的间隔执行同步。

运行模型
--------
单进程常驻，每 20 秒扫一次待执行规则。规则执行是同步阻塞的（一条跑完再跑
下一条），因为文件同步本身是 IO/带宽密集型任务，并行只会互相拖慢并且让
带宽统计失真。单条规则内部由 engine 的文件锁保证不会被重复进入。

排期规则
--------
* 新建/保存时把 next_run 设为「现在 + 首次运行延迟」，让用户能避开开机高峰。
* 跑完一轮：成功按执行间隔排下一轮；失败且从未成功过，按 retry_min 重试，
  直到成功一次为止（首轮失败常见于公钥没装好、对方还没开机）。
"""

import datetime as dt
import os
import signal
import sys
import threading
import time
import traceback

try:  # Windows 上没有 fcntl，仅影响本地调试，DSM 上始终可用
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

import common
import engine
import localroot

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


def next_run_after(db, kind, task_id, ok):
    """算下一轮时间，返回 (iso, 说明)。

    成功           → 按执行间隔
    失败但从未成功 → 按 retry_min 重试，直到成功一次为止（首轮失败多半是网络或
                     密钥还没准备好，隔一小时再试比等一整个间隔更合理）
    失败且已成功过 → 按执行间隔，避免长期失败时每 20 秒猛冲
    """
    table = "rules" if kind == "rule" else "groups"
    row = db.execute("SELECT interval_min,retry_min FROM %s WHERE id=?" % table, (task_id,)).fetchone()
    interval = row["interval_min"] if row else 10
    if ok or row is None:
        return compute_next(interval), ""
    retry = int(row["retry_min"] or 0)
    if retry <= 0:
        return compute_next(interval), ""
    run_key = task_id if kind == "rule" else "group:" + task_id
    # 只看「同步成功」的记录；压缩备份也会写 runs，别把备份成功当成同步成功
    ever_ok = db.execute(
        "SELECT 1 FROM runs WHERE rule_id=? AND status='ok' "
        "AND message NOT LIKE '压缩备份%' LIMIT 1", (run_key,)
    ).fetchone()
    if ever_ok:
        return compute_next(interval), ""
    return compute_next(retry), "首轮未成功，%d 分钟后再试，直到成功一次为止" % retry


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
        # 0644：worker 是 root，停止脚本要以套件账号读这个 PID
        os.chmod(common.PID_PATH, 0o644)
    except OSError:
        pass


def clear_pid():
    try:
        common.PID_PATH.unlink()
    except OSError:
        pass


def initialize_schedule(db):
    """套件启动（开机）时重排过期计划。

    「首次运行延迟」在这里同样生效：开机后所有任务都是从零开始，与其一起冲
    上去抢带宽、抢 CPU，不如先等用户设定的分钟数再跑第一轮。已经有未来计划
    的任务（还没到点）不动，避免把正常的间隔排期往后拖。

    多条任务还会各自错开 STARTUP_STAGGER 秒，防止延迟到点后同时开跑。
    """
    now = common.now_local()
    offset = 0
    for table in ("rules", "groups"):
        for row in db.execute("SELECT * FROM %s WHERE enabled=1 ORDER BY created" % table).fetchall():
            due = common.parse_iso(row["next_run"])
            if due is None or due <= now:
                delay = max(0, int(row["start_delay_min"] or 0))
                target = (now + dt.timedelta(minutes=delay, seconds=5 + offset)).isoformat(timespec="seconds")
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
    ok = False
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
        ok = True
    except (engine.RuleError, engine.GroupError) as exc:
        log("%s「%s」跳过：%s" % (label, row["name"], exc))
    except Exception as exc:  # noqa: BLE001
        log("%s「%s」失败：%s" % (label, row["name"], exc))
        log(traceback.format_exc().replace("\n", " | ")[:800])
    finally:
        # 无论成功失败都排下一轮，避免失败任务每 20 秒疯狂重试；
        # 首轮失败时按 retry_min 重试，成功一次之后回到正常间隔。
        table = "rules" if kind == "rule" else "groups"
        try:
            next_at, note = next_run_after(db, kind, task_id, ok)
        except Exception as exc:  # noqa: BLE001
            next_at, note = compute_next(10), ""
            log("计算下一轮时间失败，按 10 分钟排期：%s" % exc)
        db.execute("UPDATE %s SET next_run=? WHERE id=?" % table, (next_at, task_id))
        db.commit()
        if note:
            log("%s「%s」%s" % (label, row["name"], note))


def idle_wait(server, seconds):
    """等下一轮扫描。目录代读由独立后台线程（serve_socket）常驻服务，这里只负责等待。

    之所以把列目录拆到后台线程：同步（run_task）在主线程里是阻塞的，可能跑很久，
    若只在空闲间隙服务 socket，浏览目录就会在同步期间超时（报「调度进程忙」）。
    """
    deadline = time.time() + seconds
    while not STOP:
        remain = deadline - time.time()
        if remain <= 0:
            return
        time.sleep(min(1.0, remain))


def serve_socket(server):
    """后台线程：时刻响应网页端的目录代读请求。

    同步（run_task）在主线程里是阻塞的，可能跑几分钟甚至更久；如果只在空闲
    间隙服务 socket，浏览目录的请求就会在同步期间超时（报「调度进程忙」）。
    所以把列目录这件只读小事交给独立线程，主线程在同步时也不耽误网页端。
    """
    if server is None:
        return
    while not STOP:
        try:
            localroot.handle_one(server)
        except Exception:  # noqa: BLE001 - 单条请求出错不影响整体服务
            continue


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

    # 记下当前 uid，网页端读它来判断调度进程是不是 root（不是就提示修复）
    try:
        _uid = os.geteuid()
    except AttributeError:  # pragma: no cover
        _uid = -1
    try:
        (common.PKG_VAR / "worker.uid").write_text(str(_uid), encoding="utf-8")
    except OSError:
        pass

    # 网页端（套件账号）读不到的目录由本进程代读，见 localroot.py
    server = localroot.start_server()
    if server is None:
        log("目录代读服务未启动（无法创建 socket），网页端只能浏览有权限的目录")
    else:
        try:
            uid = os.geteuid()
        except AttributeError:  # pragma: no cover
            uid = -1
        log("目录代读服务已就绪（uid=%d）" % uid)
        if uid not in (0, -1):
            log("[warn] 调度进程未以 root 运行（uid=%d）：同步/备份读写 /volume1/homes "
                "会报 Permission denied。请重装或重启套件，让 postinst/postupgrade "
                "写入的 run-as:root 生效。" % uid)
        # 独立后台线程常驻服务：同步（阻塞）进行时也能秒回网页端的列目录请求，
        # 不再因为正忙而超时（报「调度进程忙」）。
        threading.Thread(
            target=serve_socket, args=(server,), name="filesync-browse", daemon=True
        ).start()

    db = common.connect_db()
    initialize_schedule(db)

    while not STOP:
        try:
            settings = common.get_settings(db)
            if settings.get("worker_paused") == "1":
                idle_wait(server, TICK_SECONDS)
                continue

            for kind, row in due_tasks(db):
                if STOP:
                    break
                run_task(db, kind, row)

            # 同步成功后按 backup_delay_min（默认 5 分钟）排的延迟备份，
            # 到点后在这里真正打包（避开同步刚结束时文件还在落盘）。
            for table, name, info in engine.run_due_backups(db, log=lambda lv, m: log("  " + m)):
                log("延迟备份完成「%s」：%s（%s，保留 %d 份）" % (
                    name, info["name"], common.human_size(info["size"]), info["keep"]))
        except Exception as exc:  # noqa: BLE001
            log("调度循环异常：%s" % exc)
            log(traceback.format_exc().replace("\n", " | ")[:800])
            time.sleep(5)

        idle_wait(server, TICK_SECONDS)

    log("FileSync 调度进程退出")
    localroot.stop_server(server)
    clear_pid()
    try:
        os.close(singleton)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
