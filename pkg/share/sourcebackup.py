#!/usr/bin/python3
# Copyright (c) 2026 AWA <https://www.akkdiy.cn>. All rights reserved.
"""源码备份：把网站源码目录（本机或远程站点）定时打成压缩包留档。

和同步里的「压缩备份」有什么区别
--------------------------------
同步的压缩备份是「同步成功后顺带打一份」，源目录只能是本机；这里是独立任务：
自己定时、自己选源（可以是路由器/VPS 上的网站目录）、自己按份数轮转，不依赖
任何同步规则，所以同步停用或删掉也不影响它。

打包方式
--------
本机源 → Python zipfile 打成 .zip（Windows 上双击就能看内容）；
远程源 → 在对方机器上跑 tar，把数据流直接写回本机的包文件里，不在远程留临时
文件，也不占对方磁盘。远程用 .tar.gz，因为 BusyBox 上不一定有 zip 命令。

两种后缀都按同一个「任务名-时间戳」前缀轮转，只清理自己产生的包，备份目录里
用户放的其它文件一概不碰。
"""

import datetime as dt
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import time

import archive
import common
import remote

PACK_EXTS = (".zip", ".tar.gz")
REMOTE_TIMEOUT = 6 * 3600
RETRY_MINUTES = 30  # 失败后多久重试（不等一整个间隔，网络抖动不该拖一天）
NAME_BAD = re.compile(r"[\\/:*?\"<>|\s]+")


class BackupError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# 命名、列举、轮转
# --------------------------------------------------------------------------
def prefix_of(row):
    """包名前缀：优先任务名（去掉文件名不允许的字符），没有就退回源目录名。"""
    name = NAME_BAD.sub("-", (row["name"] or "").strip()).strip("-.")
    if not name:
        name = (row["src_dir"] or "").rstrip("/").rsplit("/", 1)[-1] or "source"
    return name[:60]


def list_packs(row, limit=None):
    """列出该任务的备份包，最新的在前。"""
    prefix = prefix_of(row) + "-"
    target = (row["target_dir"] or "").rstrip("/")
    if not target:
        return []
    items = []
    try:
        with os.scandir(target) as entries:
            for entry in entries:
                if not (entry.name.startswith(prefix) and entry.name.endswith(PACK_EXTS)):
                    continue
                try:
                    info = entry.stat()
                except OSError:
                    continue
                items.append({"name": entry.name, "size": info.st_size,
                              "mtime": int(info.st_mtime)})
    except OSError:
        return []
    items.sort(key=lambda item: (item["mtime"], item["name"]), reverse=True)
    return items[:limit] if limit else items


def prune(row):
    """只保留最新 keep 份，返回删掉的份数；keep=0 表示不限，一个都不删。"""
    try:
        keep = int(row["keep"] if row["keep"] is not None else 7)
    except (TypeError, ValueError):
        keep = 7
    if keep <= 0:
        return 0
    removed = 0
    for item in list_packs(row)[keep:]:
        try:
            os.unlink(os.path.join(row["target_dir"], item["name"]))
            removed += 1
        except OSError:
            continue
    return removed


# --------------------------------------------------------------------------
# 打包
# --------------------------------------------------------------------------
def _ensure_target(target):
    target = (target or "").rstrip("/")
    if not target:
        raise BackupError("还没有设置备份目录")
    try:
        os.makedirs(target, exist_ok=True)
    except PermissionError:
        raise BackupError(archive._os_error_text(PermissionError(13, "Permission denied"), target))
    except OSError as exc:
        raise BackupError("无法创建备份目录 %s：%s" % (target, exc))
    try:
        free = shutil.disk_usage(target).free
    except OSError:
        free = None
    if free is not None and free < 2 * 1024 * 1024:
        raise BackupError("备份目录空间不足（仅剩 %s）" % common.human_size(free))
    if not os.access(target, os.W_OK | os.X_OK):
        raise BackupError(archive._os_error_text(PermissionError(13, "Permission denied"), target))
    return target


def _stamp():
    return time.strftime("%Y%m%d-%H%M%S", time.localtime())


def pack_local(row, target):
    """本机目录 → zip。"""
    src = (row["src_dir"] or "").rstrip("/")
    if not src or not os.path.isdir(src):
        raise BackupError("本机目录不可用：" + (src or "（未设置）"))
    if common.paths_overlap(src, target):
        raise BackupError("备份目录不能放在源目录里面：" + target)
    final = os.path.join(target, "%s-%s.zip" % (prefix_of(row), _stamp()))
    temp = final + ".part"
    try:
        archive.pack_to(src, temp, remote.compile_excludes(row["excludes"]), "zip")
        os.replace(temp, final)
    except archive.ArchiveError as exc:
        _unlink(temp)
        raise BackupError(str(exc))
    except OSError as exc:
        _unlink(temp)
        raise BackupError("打包失败：%s" % exc)
    return final


def _tar_command(parent, base, patterns):
    """远程打包命令：把 parent/base 打成 tar.gz 流，交给 ssh 的 stdout。"""
    args = ["tar", "-czf", "-", "-C", shlex.quote(parent)]
    for pattern in patterns:
        pattern = (pattern or "").strip().rstrip("/")
        if pattern:
            args.append("--exclude=" + shlex.quote(pattern))
    args.append(shlex.quote(base))
    return " ".join(args)


def _run_ssh_to_file(site, command, output, timeout=REMOTE_TIMEOUT):
    """执行远程命令，把 stdout 原样写进 output（二进制安全，不经过文本解码）。"""
    argv = remote.ssh_argv(site, command)
    try:
        with open(output, "wb") as handle:
            proc = subprocess.run(argv, stdout=handle, stderr=subprocess.PIPE,
                                  timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise BackupError("远程打包超时（超过 %d 小时）" % (timeout // 3600))
    except OSError as exc:
        raise BackupError("无法执行 ssh：%s" % exc)
    return proc.returncode, proc.stderr.decode("utf-8", "replace")


def pack_remote(row, site, target):
    """远程目录 → 本机 tar.gz（数据流直接落盘，不在远程留临时文件）。"""
    src = (row["src_dir"] or "").rstrip("/")
    if not src.startswith("/"):
        raise BackupError("远程目录必须是以 / 开头的绝对路径")
    parent, base = posixpath.split(src)
    if not base:
        raise BackupError("不能直接打包远程根目录 /")
    final = os.path.join(target, "%s-%s.tar.gz" % (prefix_of(row), _stamp()))
    temp = final + ".part"
    patterns = remote.compile_excludes(row["excludes"])
    code, stderr = _run_ssh_to_file(site, _tar_command(parent, base, patterns), temp)
    # tar 退出码 1 表示「打包过程中有文件被改动/消失」，网站目录很常见，包仍可用；
    # >=2 才是真失败。老版 BusyBox 不认 --exclude 时会直接报错，这里去掉排除项重试一次。
    if code not in (0, 1) and patterns:
        text = (stderr or "").lower()
        if "exclude" in text or "unrecognized option" in text or "invalid option" in text:
            _unlink(temp)
            code, stderr = _run_ssh_to_file(site, _tar_command(parent, base, []), temp)
    if code not in (0, 1):
        _unlink(temp)
        detail = " | ".join((stderr or "").strip().splitlines()[-2:]) or ("ssh 返回代码 " + str(code))
        raise BackupError("远程打包失败：" + detail[:300])
    try:
        os.replace(temp, final)
    except OSError as exc:
        _unlink(temp)
        raise BackupError("无法保存备份包：%s" % exc)
    return final


def _unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass


# --------------------------------------------------------------------------
# 执行一个任务
# --------------------------------------------------------------------------
def _log_run(db, task_id, status, message):
    """写 runs 表，界面的「日志」按钮就能看到每次备份的细节。"""
    now = common.now_iso()
    try:
        db.execute(
            "INSERT INTO runs(rule_id,started,finished,status,message) VALUES(?,?,?,?,?)",
            ("srcbak:" + task_id, now, now, status, message[:2000]),
        )
        db.commit()
    except Exception:  # noqa: BLE001 - 记日志失败不能影响备份本身
        pass


def _save_result(db, task_id, status, message):
    db.execute("UPDATE source_backups SET last_run=?,last_status=?,last_msg=? WHERE id=?",
               (common.now_iso(), status, message[:500], task_id))
    db.commit()


def run_task(db, row, log=None):
    """执行一次源码备份，返回 {"name","size","removed","path"}；失败抛 BackupError。"""
    def emit(message, level="info"):
        if log:
            log(level, message)

    task_id = row["id"]
    site_row = db.execute("SELECT * FROM sites WHERE id=?", (row["site_id"],)).fetchone()
    if not site_row:
        message = "源站点不存在或已被删除"
        _save_result(db, task_id, "error", message)
        _log_run(db, task_id, "error", "源码备份失败：" + message)
        raise BackupError(message)
    site = dict(site_row)
    target = _ensure_target(row["target_dir"])
    where = "%s:%s" % (site["name"], row["src_dir"])
    emit("源码备份 %s → %s" % (where, target))

    try:
        if site["kind"] == "local":
            final = pack_local(row, target)
        else:
            final = pack_remote(row, site, target)
    except BackupError as exc:
        _save_result(db, task_id, "error", "失败：" + str(exc)[:300])
        _log_run(db, task_id, "error", "源码备份失败：%s → %s：%s" % (where, target, str(exc)[:500]))
        raise

    try:
        size = os.path.getsize(final)
    except OSError:
        size = 0
    removed = prune(row)
    name = os.path.basename(final)
    keep = int(row["keep"] if row["keep"] is not None else 7)
    message = "成功：%s（%s，%s%s）" % (
        name, common.human_size(size),
        "保留 %d 份" % keep if keep > 0 else "不限份数",
        "，清理 %d 份旧包" % removed if removed else "")
    _save_result(db, task_id, "ok", message)
    # 记下「本次开机已经备份过」，套件重启后不会再跑一次
    try:
        db.execute("UPDATE source_backups SET boot_done=? WHERE id=?",
                   (common.boot_stamp(), task_id))
        db.commit()
    except Exception:  # noqa: BLE001 - 记标记失败不影响备份结果
        pass
    _log_run(db, task_id, "ok", "源码备份成功：%s → %s" % (where, os.path.join(target, name)))
    emit("源码备份完成：" + message, "good")
    return {"name": name, "path": final, "size": size, "removed": removed,
            "keep": int(row["keep"] or 7), "message": message}


# --------------------------------------------------------------------------
# 调度
# --------------------------------------------------------------------------
KINDS = ("daily", "weekly", "interval", "boot")
DEFAULT_KIND = "daily"
DEFAULT_BOOT_DELAY = 30  # 开机后默认等 30 分钟再备份，避开开机时的磁盘/网络高峰


def _parse_clock(value):
    """'02:00' → (2, 0)；格式不对退回 02:00。"""
    try:
        hour, minute = str(value or "").split(":")[:2]
        hour, minute = int(hour), int(minute)
        if 0 <= hour <= 23 and 0 <= minute <= 59:
            return hour, minute
    except (TypeError, ValueError):
        pass
    return 2, 0


def scheduled_after(row, base=None):
    """算出「下一次该跑的时间」。

    daily    → 今天/明天的 HH:MM
    weekly   → 本周/下周的指定星期几 HH:MM
    interval → base + N 小时
    boot     → base + 5 分钟（只在开机时排一次，见 initialize_schedule）
    """
    base = (base or common.now_local()).astimezone()
    kind = row["schedule_kind"] or DEFAULT_KIND
    if kind == "interval":
        try:
            hours = max(1, int(row["interval_hour"] or 24))
        except (TypeError, ValueError):
            hours = 24
        return base + dt.timedelta(hours=hours)
    if kind == "boot":
        try:
            delay = max(1, int(row["boot_delay_min"] if row["boot_delay_min"] is not None
                               else DEFAULT_BOOT_DELAY))
        except (TypeError, ValueError, IndexError, KeyError):
            delay = DEFAULT_BOOT_DELAY
        return base + dt.timedelta(minutes=delay)
    hour, minute = _parse_clock(row["run_time"])
    candidate = dt.datetime.combine(base.date(), dt.time(hour, minute), tzinfo=base.tzinfo)
    if kind == "weekly":
        try:
            weekday = min(6, max(0, int(row["weekday"] or 0)))
        except (TypeError, ValueError):
            weekday = 0
        candidate += dt.timedelta(days=(weekday - base.weekday()) % 7)
        if candidate <= base:
            candidate += dt.timedelta(days=7)
    elif candidate <= base:
        candidate += dt.timedelta(days=1)
    return candidate


def _iso(value):
    return value.astimezone().isoformat(timespec="seconds")


def initialize_schedule(db, log=None):
    """套件启动时重排计划。

    boot 型任务用 `boot_done` 记「哪一次开机已经跑过」：

    * 本次开机还没跑过 → 排一次（now + 开机延迟），套件重启/升级后也会补上；
    * 本次开机跑过了   → 跳过，套件重启不会重复备份。

    以前只认「开机标识变了才排」，结果套件重启（标识没变）时任务既跑完了
    next_run 又被清空，就一直不跑——用户看到的「开机后没按设置时间运行」。
    """
    now = common.now_local()
    boot = common.boot_stamp()
    for task in db.execute("SELECT * FROM source_backups WHERE enabled=1 ORDER BY created").fetchall():
        kind = task["schedule_kind"] or DEFAULT_KIND
        due = common.parse_iso(task["next_run"])
        if kind == "boot":
            if (task["boot_done"] or "") == boot:
                continue  # 本次开机已经跑过
            if due is not None and due > now:
                continue  # 已经排了未来的时间
            target = scheduled_after(task, now)
            if log:
                log("源码备份「%s」开机排期：%d 分钟后（%s）" % (
                    task["name"], max(1, int(task["boot_delay_min"] or DEFAULT_BOOT_DELAY)),
                    _iso(target)))
        else:
            if due is not None and due > now:
                continue
            target = scheduled_after(task, now)
        db.execute("UPDATE source_backups SET next_run=? WHERE id=?", (_iso(target), task["id"]))
    db.commit()


def due_tasks(db):
    """返回到点该跑的任务行。

    next_run 为空有两种含义：刚建/刚启用（要立刻补一轮），或开机型任务已经
    跑完了（必须跳过）。不区分的话，开机备份会跑完又被捞出来，变成无限循环。
    """
    now = common.now_local()
    result = []
    for row in db.execute("SELECT * FROM source_backups WHERE enabled=1 ORDER BY created"):
        due = common.parse_iso(row["next_run"])
        if due is None:
            if (row["schedule_kind"] or DEFAULT_KIND) == "boot":
                continue
            result.append(row)
        elif due <= now:
            result.append(row)
    return result


def next_run_after(ok, row):
    """成功按规则排下一轮；失败 30 分钟后再试，避免网络抖动拖一整天。

    「开机后备份」成功后必须把 next_run 清空——它只在开机时跑一次，
    若照 scheduled_after 排（now + 开机延迟）就会变成「每 N 分钟备份一次」，
    0.3.27 就是这里漏判，导致设了开机 10 分钟却每 10 分钟跑一轮。
    """
    now = common.now_local()
    if ok:
        if (row["schedule_kind"] or DEFAULT_KIND) == "boot":
            return ""
        return _iso(scheduled_after(row, now))
    return _iso(now + dt.timedelta(minutes=RETRY_MINUTES))
