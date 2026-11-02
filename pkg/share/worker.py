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
import sourcebackup

STOP = False
TICK_SECONDS = 20
STARTUP_STAGGER = 12  # 开机后多条规则错开启动，避免同时抢带宽
LOG_KEEP = 500        # 每个任务最多保留多少条同步/备份日志（runs 表）


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

    执行方式决定「下一轮」：按间隔 → +interval_min；每天/每周 → 下一个时间点；
    开机后 → 本次开机只跑一次，成功后清空 next_run（失败仍按 retry_min 重试）。
    失败但从未成功时按 retry_min 重试，直到成功一次为止（首轮失败多半是公钥
    没装好或对方没开机）；失败且已成功过则回到正常排期，避免每 20 秒猛冲。
    """
    table = "rules" if kind == "rule" else "groups"
    row = db.execute("SELECT * FROM %s WHERE id=?" % table, (task_id,)).fetchone()
    if row is None:
        return compute_next(10), ""
    schedule = common.row_get(row, "schedule_kind", "interval") or "interval"

    def normal():
        if schedule == "boot":
            return ""  # 本次开机已完成，等下一次开机再排
        return common.schedule_next(row).isoformat(timespec="seconds")

    if ok:
        return normal(), ""
    retry = int(row["retry_min"] or 0)
    if retry <= 0:
        return normal(), ""
    # 失败就重试，不区分「以前有没有成功过」：每天/每周的任务失败后等明天太亏，
    # 开机后执行的任务更是要等下次开机。按 retry_min（默认 60 分钟）再试，
    # 成功后自然回到正常排期，所以不会一直空转。
    return compute_next(retry), "本次未成功，%d 分钟后再试" % retry


def prune_logs(db, keep=LOG_KEEP):
    """每个任务只保留最近 keep 条同步/备份日志，避免 runs 表无限增长。

    界面「日志」本来只显示最近 50 条，但数据库会一直累积；这里每天清一次最旧的。
    返回删掉的条数。
    """
    try:
        keep = max(50, int(keep))
    except (TypeError, ValueError):
        keep = LOG_KEEP
    keys = [row[0] for row in db.execute("SELECT DISTINCT rule_id FROM runs").fetchall()]
    removed = 0
    for key in keys:
        stale = [row[0] for row in db.execute(
            "SELECT id FROM runs WHERE rule_id=? ORDER BY id DESC LIMIT -1 OFFSET ?",
            (key, keep)).fetchall()]
        if not stale:
            continue
        placeholders = ",".join("?" * len(stale))
        db.execute("DELETE FROM runs WHERE id IN (%s)" % placeholders, stale)
        removed += len(stale)
    if removed:
        db.commit()
    return removed


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
    boot = common.boot_stamp()
    for table in ("rules", "groups"):
        for row in db.execute("SELECT * FROM %s WHERE enabled=1 ORDER BY created" % table).fetchall():
            schedule = common.row_get(row, "schedule_kind", "interval") or "interval"
            due = common.parse_iso(row["next_run"])
            if schedule == "boot":
                # 开机后执行：用 boot_done 记「本次开机跑过没有」。
                # 只认「开机标识变了」的话，套件重启时任务既跑完了 next_run 又是空的，
                # 会一直不跑（用户反馈的「开机后没按设置时间运行」就是这个）。
                if (common.row_get(row, "boot_done", "") or "") == boot:
                    continue
                if due is not None and due > now:
                    continue
                try:
                    delay = max(1, int(row["boot_delay_min"] or 30))
                except (TypeError, ValueError, IndexError):
                    delay = 30
                target = (now + dt.timedelta(minutes=delay, seconds=offset)).isoformat(timespec="seconds")
            elif schedule in ("daily", "weekly"):
                if due is not None and due > now:
                    continue
                target = common.schedule_next(row, now).isoformat(timespec="seconds")
            else:
                if due is not None and due > now:
                    continue
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
            if due is None:
                # 开机后执行的任务跑完会清空 next_run，不能当成「到点」再跑一遍
                if (common.row_get(row, "schedule_kind", "interval") or "interval") == "boot":
                    continue
                result.append((kind, row))
            elif due <= now:
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
        if ok:
            try:
                db.execute("UPDATE %s SET boot_done=? WHERE id=?" % table,
                           (common.boot_stamp(), task_id))
            except Exception:  # noqa: BLE001 - 记标记失败不影响同步结果
                pass
        db.commit()
        if note:
            log("%s「%s」%s" % (label, row["name"], note))


def run_source_task(db, row):
    """执行一个源码备份任务：本机直接打包，远程用 ssh tar 流写回本机。

    成功按间隔排下一轮，失败 30 分钟后再试——备份失败多半是网络或对方没开机，
    等一整个间隔（可能 24 小时）太亏。
    """
    label = "源码备份「%s」" % row["name"]
    log("开始%s（%s:%s）" % (label, row["site_id"], row["src_dir"]))
    started = time.time()
    ok = False
    try:
        info = sourcebackup.run_task(db, row, log=lambda lv, m: log("  " + m))
        log("%s完成，耗时 %.1f 秒：%s（%s，保留 %d 份%s）" % (
            label, time.time() - started, info["name"], common.human_size(info["size"]),
            info["keep"], "，清理 %d 份旧包" % info["removed"] if info["removed"] else ""))
        ok = True
    except sourcebackup.BackupError as exc:
        log("%s失败：%s" % (label, exc))
    except Exception as exc:  # noqa: BLE001
        log("%s异常：%s" % (label, exc))
        log(traceback.format_exc().replace("\n", " | ")[:800])
    finally:
        next_at = sourcebackup.next_run_after(ok, row)
        db.execute("UPDATE source_backups SET next_run=? WHERE id=?", (next_at, row["id"]))
        db.commit()
        log("%s下次：%s" % (label, next_at))


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

    # 建库/补列失败时别直接崩：DSM 不一定会自动拉起进程，重试几次再退出
    db = None
    for attempt in range(3):
        try:
            db = common.connect_db()
            break
        except Exception as exc:  # noqa: BLE001
            log("数据库初始化失败（第 %d 次）：%s" % (attempt + 1, exc))
            time.sleep(10)
    if db is None:
        log("数据库不可用，调度进程退出")
        return 1

    initialize_schedule(db)
    # 源码备份按「每天/每周/间隔/开机后」排期，规则和同步任务不同，单独处理。
    # 注意 initialize_schedule 的 log 是单参数（log(message)），不能传 (level, message)。
    try:
        sourcebackup.initialize_schedule(db, log=lambda m: log(m))
    except Exception as exc:  # noqa: BLE001 - 排期失败不能让整个调度进程起不来
        log("源码备份排期失败：%s" % exc)

    last_prune = 0  # 上次清理旧日志的时间（秒），每 24 小时清一次
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

            # 源码备份是独立任务：自己定时，源目录可以在本机也可以在远程站点
            for row in sourcebackup.due_tasks(db):
                if STOP:
                    break
                run_source_task(db, row)

            # 每天清理一次旧日志：每个任务只留最近 LOG_KEEP 条
            if time.time() - last_prune > 86400:
                try:
                    removed = prune_logs(db)
                    if removed:
                        log("清理旧同步/备份日志 %d 条（每任务保留最近 %d 条）" % (removed, LOG_KEEP))
                except Exception as exc:  # noqa: BLE001
                    log("清理旧日志失败：%s" % exc)
                last_prune = time.time()
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
