#!/usr/bin/python3
# Copyright (c) 2026 AWA <https://www.akkdiy.cn>. All rights reserved.
"""FileSync 同步引擎。

为什么不能直接用 rsync 双向 --delete
------------------------------------
`rsync --delete` 是单向的：它认为源是真理。双向各跑一次会互相删除对方的
新文件——A 新增的文件还没传到 B，B 那轮"镜像 A"就把它删了。所以必须引入
"上次同步基线"（baseline）做三向比较：

    文件在 A、不在 B、基线里也没有  → A 新增，复制到 B
    文件在 A、不在 B、基线里有      → B 删除了，跟随删除 A（或恢复 B）
    两边都有但内容不同、只有一边变  → 把变化的一边推过去
    两边都有但内容不同、两边都变了  → 冲突，mtime 较新的胜出

这就是 Syncthing 一类工具的核心思路，"最新文件"的判定就落在冲突分支上。
"""

import datetime as dt
import json
import os
import time
import uuid

try:  # Windows 上没有 fcntl，仅影响本地调试，DSM 上始终可用
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

import common
import archive
import remote


class RuleError(RuntimeError):
    pass


class GroupError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# 读取
# --------------------------------------------------------------------------
def _brief(files, limit=20):
    """把文件列表排成多行（每行一个），便于在日志里逐条阅读。"""
    files = list(files)
    if not files:
        return "（无）"
    lines = ["  " + f for f in files[:limit]]
    if len(files) > limit:
        lines.append("  … 还有 %d 个未列出" % (len(files) - limit))
    return "\n" + "\n".join(lines)


def load_site(db, site_id):
    row = db.execute("SELECT * FROM sites WHERE id=?", (site_id,)).fetchone()
    if not row:
        raise RuleError("站点不存在或已被删除")
    return dict(row)


def load_rule(db, rule_id):
    row = db.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
    if not row:
        raise RuleError("同步规则不存在或已被删除")
    return dict(row)


def load_baseline(db, rule_id):
    result = {}
    for row in db.execute("SELECT rel,a_size,a_mtime,b_size,b_mtime FROM baseline WHERE rule_id=?", (rule_id,)):
        # 旧版本存过带小数的 mtime，这里统一到整数秒，避免和新扫描结果比不相等
        result[row["rel"]] = (
            row["a_size"], remote.norm_mtime(row["a_mtime"]),
            row["b_size"], remote.norm_mtime(row["b_mtime"]),
        )
    return result


# --------------------------------------------------------------------------
# 压缩备份（把本机目录打成 tar.gz 放到另一个目录，按份数轮转）
# --------------------------------------------------------------------------
def local_dir_of_rule(db, rule):
    """规则里属于本机的那一端目录；两端都不是本机时返回空。"""
    for site_id, dir_key in ((rule["site_a"], "dir_a"), (rule["site_b"], "dir_b")):
        site = load_site(db, site_id)
        if site["kind"] == "local":
            return rule[dir_key]
    return ""


def local_dir_of_group(db, group_id):
    for member in load_group_members(db, group_id):
        if member["site"]["kind"] == "local":
            return member["dir"]
    return ""


def task_local_dir(db, table, owner_id):
    if table == "rules":
        return local_dir_of_rule(db, load_rule(db, owner_id))
    return local_dir_of_group(db, owner_id)


def _log_backup_run(db, table, owner_id, status, message):
    """把压缩备份事件写进 runs 表，界面上的「日志」就能看到备份的源目录与结果。"""
    run_key = owner_id if table == "rules" else "group:" + owner_id
    now = common.now_iso()
    try:
        db.execute(
            "INSERT INTO runs(rule_id,started,finished,status,message) VALUES(?,?,?,?,?)",
            (run_key, now, now, status, message[:2000]),
        )
        db.commit()
    except Exception:  # noqa: BLE001 - 记日志失败不能影响备份本身
        pass


def run_backup(db, table, owner_id, force=False, log=None):
    """按配置压缩备份本机目录。

    force=False 时受 backup_interval_hour 约束（同步每轮都会调用它，只有到了
    间隔才真的打包）；force=True 供界面上的「立即备份」使用。
    返回 None 表示本轮不需要备份；失败抛 RuleError。
    """
    def emit(message, level="info"):
        if log:
            log(level, message)

    if table not in ("rules", "groups"):
        raise RuleError("备份目标不正确")
    row = db.execute("SELECT * FROM %s WHERE id=?" % table, (owner_id,)).fetchone()
    if not row:
        raise RuleError("任务不存在或已被删除")
    if not row["backup_enabled"] and not force:
        return None
    target = row["backup_dir"] or ""
    if not target:
        _log_backup_run(db, table, owner_id, "error", "压缩备份失败：还没有设置备份目录")
        raise RuleError("还没有设置备份目录")
    source = task_local_dir(db, table, owner_id)
    if not source:
        _log_backup_run(db, table, owner_id, "error", "压缩备份失败：这个任务没有本机目录")
        raise RuleError("这个任务没有本机目录，无法压缩备份")

    if not force:
        last = common.parse_iso(row["backup_last"])
        hours = int(row["backup_interval_hour"] or 24)
        if last and (common.now_local() - last).total_seconds() < hours * 3600:
            return None

    emit("压缩备份 %s → %s" % (source, target))
    try:
        info = archive.create_archive(source, target, row["backup_keep"] or 7,
                                      remote.compile_excludes(row["excludes"]))
    except archive.ArchiveError as exc:
        message = "失败：" + str(exc)[:300]
        db.execute("UPDATE %s SET backup_last=?,backup_msg=? WHERE id=?" % table,
                   (common.now_iso(), message, owner_id))
        db.commit()
        emit("压缩备份失败：" + str(exc), "error")
        _log_backup_run(db, table, owner_id, "error",
                        "压缩备份失败：%s → %s：%s" % (source, target, str(exc)[:500]))
        raise RuleError("压缩备份失败：" + str(exc))

    message = "成功：%s（%s，保留 %d 份%s）" % (
        info["name"], common.human_size(info["size"]), info["keep"],
        "，清理 %d 份旧包" % info["removed"] if info["removed"] else "")
    db.execute("UPDATE %s SET backup_last=?,backup_msg=? WHERE id=?" % table,
               (common.now_iso(), message, owner_id))
    db.commit()
    emit("压缩备份完成：" + message, "good")
    _log_backup_run(db, table, owner_id, "ok",
                    "压缩备份成功：%s → %s（%s，保留 %d 份%s）" % (
                        source, os.path.join(target, info["name"]),
                        common.human_size(info["size"]), info["keep"],
                        "，清理 %d 份旧包" % info["removed"] if info["removed"] else ""))
    return dict(info, message=message, source=source, target=target)


def schedule_backup(db, table, owner_id):
    """同步成功后安排一次「延迟备份」：backup_due_at = now + backup_delay_min。

    为什么不在这里直接打包：同步刚结束时文件可能还在落盘/被其它进程占用，
    而且打包是重 IO，和同步挤在一起会互相拖慢。把打包延后 N 分钟（默认 5），
    由 worker 的下一个 tick 里 run_due_backups 触发，等文件稳定后再压缩。

    返回 (是否排期, 延迟分钟数)。没开备份 / 没填目录时不排期。
    """
    row = db.execute("SELECT * FROM %s WHERE id=?" % table, (owner_id,)).fetchone()
    if not row or not row["backup_enabled"] or not row["backup_dir"]:
        return False, 0
    delay = int(row["backup_delay_min"] or 0)
    if delay < 0:
        delay = 0
    due = (common.now_local() + dt.timedelta(minutes=delay)).isoformat(timespec="seconds")
    db.execute("UPDATE %s SET backup_due_at=?,backup_force=0 WHERE id=?" % table, (due, owner_id))
    db.commit()
    return True, delay


def run_due_backups(db, log=None):
    """worker 每次 tick 调用：把已到点的延迟备份真正执行掉。

    无论本次打包成功、被间隔节流跳过、还是失败，都清掉 backup_due_at，
    避免同一次排期被反复触发；下一轮同步成功后会重新排期。
    """
    now = common.now_local()
    results = []
    for table in ("rules", "groups"):
        rows = db.execute(
            "SELECT id, name, backup_due_at, backup_force FROM %s WHERE backup_due_at<>''" % table
        ).fetchall()
        for row in rows:
            due = common.parse_iso(row["backup_due_at"])
            if due is not None and due > now:
                continue  # 还没到点
            info = None
            try:
                # backup_force=1 是界面上的「立即备份」，绕过间隔；否则按间隔节流
                info = run_backup(db, table, row["id"], force=bool(row["backup_force"]), log=log)
            except RuleError as exc:
                if log:
                    log("warn", "延迟备份未完成：%s" % str(exc)[:200])
            db.execute("UPDATE %s SET backup_due_at='',backup_force=0 WHERE id=?" % table, (row["id"],))
            db.commit()
            if info:
                results.append((table, row["name"], info))
    return results


def list_backups(db, table, owner_id):
    """列出这个任务的已有备份包（最新在前）。"""
    row = db.execute("SELECT * FROM %s WHERE id=?" % table, (owner_id,)).fetchone()
    if not row:
        raise RuleError("任务不存在或已被删除")
    source = task_local_dir(db, table, owner_id)
    if not source or not row["backup_dir"]:
        return []
    return archive.list_archives(source, row["backup_dir"])


# --------------------------------------------------------------------------
# 决策（纯函数，便于单测）
# --------------------------------------------------------------------------
def decide(man_a, man_b, baseline, mode, delete_follow):
    """三向合并决策。

    参数
    ----
    man_a, man_b : {rel: (size, mtime)}
    baseline     : {rel: (a_size, a_mtime, b_size, b_mtime)}  上次成功同步后的两端状态
    mode         : both | a2b | b2a
    delete_follow: 是否让删除传播

    返回
    ----
    dict(a2b, b2a, del_a, del_b, conflicts, same)
        a2b/b2a  需要传输的相对路径
        del_a    需要从 A 侧删除（因为 B 侧删了）
        del_b    需要从 B 侧删除（因为 A 侧删了）
        conflicts [(rel, loser)] loser='a'/'b' 表示被覆盖的一侧，用于保留副本
        same     两端已一致的文件数
    """
    plan = {"a2b": [], "b2a": [], "del_a": [], "del_b": [], "conflicts": [], "same": 0}

    if mode == "a2b":
        # A 是权威源，B 完全跟随 A
        for rel, meta in man_a.items():
            if rel not in man_b or man_b[rel] != meta:
                plan["a2b"].append(rel)
            else:
                plan["same"] += 1
        if delete_follow:
            for rel in man_b:
                if rel not in man_a:
                    plan["del_b"].append(rel)
        return plan

    if mode == "b2a":
        for rel, meta in man_b.items():
            if rel not in man_a or man_a[rel] != meta:
                plan["b2a"].append(rel)
            else:
                plan["same"] += 1
        if delete_follow:
            for rel in man_a:
                if rel not in man_b:
                    plan["del_a"].append(rel)
        return plan

    # mode == 'both'：双向对等，三向合并
    all_rels = set(man_a) | set(man_b) | set(baseline)
    for rel in all_rels:
        a = man_a.get(rel)
        b = man_b.get(rel)
        base = baseline.get(rel)

        if not a and not b:
            continue

        if a and b:
            if a == b:
                plan["same"] += 1
                continue
            a_changed = base is None or (a[0], a[1]) != (base[0], base[1])
            b_changed = base is None or (b[0], b[1]) != (base[2], base[3])
            if a_changed and b_changed:
                # 冲突：修改时间较新的胜出（这正是"最新文件"的判定）
                if b[1] > a[1]:
                    plan["b2a"].append(rel)
                    plan["conflicts"].append((rel, "a"))
                else:
                    plan["a2b"].append(rel)
                    plan["conflicts"].append((rel, "b"))
            elif a_changed:
                plan["a2b"].append(rel)
            else:
                plan["b2a"].append(rel)
            continue

        if a and not b:
            if base is None:
                plan["a2b"].append(rel)          # A 侧新增
            elif delete_follow:
                plan["del_a"].append(rel)        # B 侧删除，跟随
            else:
                plan["a2b"].append(rel)          # 不跟随删除，把文件推回 B
            continue

        if b and not a:
            if base is None:
                plan["b2a"].append(rel)          # B 侧新增
            elif delete_follow:
                plan["del_b"].append(rel)        # A 侧删除，跟随
            else:
                plan["b2a"].append(rel)
    return plan


# --------------------------------------------------------------------------
# 执行
# --------------------------------------------------------------------------
def _acquire_lock(rule_id):
    """同一规则不允许并发执行（调度与手动触发可能撞车）。"""
    return _acquire_named_lock("rule-%s" % rule_id, "这条规则正在同步中，请稍后再试")


def _acquire_named_lock(name, busy_message):
    if fcntl is None:
        return None
    path = common.PKG_VAR / (name + ".lock")
    fd = os.open(str(path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise RuleError(busy_message)
    return fd


def _release_lock(fd):
    if fd is None or fcntl is None:
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def run_rule(db, rule_id, trigger="manual", log=None):
    """执行一条同步规则。返回统计 dict。异常时抛 RuleError / RemoteError。"""
    def emit(message, level="info"):
        if log:
            log(level, message)

    lock_fd = _acquire_lock(rule_id)
    started = common.now_iso()
    cur = db.execute(
        "INSERT INTO runs(rule_id,started,status,message) VALUES(?,?,'running',?)",
        (rule_id, started, trigger),
    )
    run_id = cur.lastrowid
    db.commit()

    try:
        rule = load_rule(db, rule_id)
        site_a = load_site(db, rule["site_a"])
        site_b = load_site(db, rule["site_b"])
        settings = common.get_settings(db)
        delete_follow = rule["delete_policy"] in ("trash", "purge")
        patterns = remote.compile_excludes(rule["excludes"])
        stamp = time.strftime("%Y%m%d-%H%M%S")
        detail = []          # 记录实际操作，写进日志供界面查看

        emit("扫描 A 端（%s）：%s" % (site_a["name"], rule["dir_a"]))
        man_a = remote.scan_side(site_a, rule["dir_a"])
        emit("扫描 B 端（%s）：%s" % (site_b["name"], rule["dir_b"]))
        man_b = remote.scan_side(site_b, rule["dir_b"])

        man_a = remote.filter_manifest(man_a, patterns)
        man_b = remote.filter_manifest(man_b, patterns)
        emit("A 端 %d 个文件，B 端 %d 个文件" % (len(man_a), len(man_b)))

        baseline = load_baseline(db, rule_id)
        # 任一端扫描到 0 个文件而基线非空，禁用删除，防止路径失效误删另一端
        if baseline and (not man_a or not man_b):
            emit("警告：有一端扫描到 0 个文件，本轮不执行删除（请检查目录是否正确）", "warn")
            delete_follow = False
        plan = decide(man_a, man_b, baseline, rule["mode"], delete_follow)
        if not plan["a2b"] and not plan["b2a"] and not plan["del_a"] and not plan["del_b"]:
            emit("两端内容一致：%d 个文件全部已是最新，本轮只扫描检查，不传输" % plan["same"], "good")
        else:
            emit("计划：A→B %d 个，B→A %d 个，删除 %d 个，冲突 %d 个，已一致 %d 个（不动）" % (
                len(plan["a2b"]), len(plan["b2a"]),
                len(plan["del_a"]) + len(plan["del_b"]),
                len(plan["conflicts"]), plan["same"]))

        # 冲突覆盖前先保留败方副本，避免"最新优先"直接抹掉另一边的改动
        if plan["conflicts"] and settings.get("conflict_copy") == "1":
            for loser, site, directory in (
                ("a", site_a, rule["dir_a"]),
                ("b", site_b, rule["dir_b"]),
            ):
                files = [rel for rel, side in plan["conflicts"] if side == loser]
                if files:
                    moved = remote.trash_side(site, directory, files, "conflicts/" + stamp)
                    emit("已保留 %d 个冲突副本（%s 侧）" % (moved, loser.upper()), "warn")

        bytes_moved = 0
        if plan["a2b"]:
            bytes_moved += sum(man_a[rel][0] for rel in plan["a2b"] if rel in man_a)
            emit("传输 A → B：%d 个文件，%s：%s" % (
                len(plan["a2b"]),
                common.human_size(sum(man_a[rel][0] for rel in plan["a2b"] if rel in man_a)),
                _brief(plan["a2b"])))
            detail.append("A → B（%d 个）：%s" % (len(plan["a2b"]), _brief(plan["a2b"])))
            remote.transfer(site_a, rule["dir_a"], site_b, rule["dir_b"], plan["a2b"])
            try:
                remote.set_mtime(site_b, rule["dir_b"],
                                 [(rel, man_a[rel][1]) for rel in plan["a2b"] if rel in man_a])
            except remote.RemoteError as exc:
                emit("统一 B 端文件时间失败（文件已同步）：%s" % exc, "warn")

        if plan["b2a"]:
            bytes_moved += sum(man_b[rel][0] for rel in plan["b2a"] if rel in man_b)
            emit("传输 B → A：%d 个文件，%s：%s" % (
                len(plan["b2a"]),
                common.human_size(sum(man_b[rel][0] for rel in plan["b2a"] if rel in man_b)),
                _brief(plan["b2a"])))
            detail.append("B → A（%d 个）：%s" % (len(plan["b2a"]), _brief(plan["b2a"])))
            remote.transfer(site_b, rule["dir_b"], site_a, rule["dir_a"], plan["b2a"])
            try:
                remote.set_mtime(site_a, rule["dir_a"],
                                 [(rel, man_b[rel][1]) for rel in plan["b2a"] if rel in man_b])
            except remote.RemoteError as exc:
                emit("统一 A 端文件时间失败（文件已同步）：%s" % exc, "warn")

        deleted = 0
        if rule["delete_policy"] == "purge":
            deleted += remote.purge_side(site_a, rule["dir_a"], plan["del_a"])
            deleted += remote.purge_side(site_b, rule["dir_b"], plan["del_b"])
        else:
            if plan["del_a"]:
                deleted += remote.trash_side(site_a, rule["dir_a"], plan["del_a"], stamp)
            if plan["del_b"]:
                deleted += remote.trash_side(site_b, rule["dir_b"], plan["del_b"], stamp)
        if deleted:
            emit("跟随删除 %d 个文件（%s）：%s" % (
                deleted, "直接删除" if rule["delete_policy"] == "purge" else "已移入回收站",
                _brief(plan["del_a"] + plan["del_b"])))
            detail.append("删除（%d 个）：%s" % (deleted, _brief(plan["del_a"] + plan["del_b"])))

        # 以同步后的真实状态重建基线，rsync 部分失败时下次会自动重试
        man_a_after = remote.filter_manifest(remote.scan_side(site_a, rule["dir_a"]), patterns)
        man_b_after = remote.filter_manifest(remote.scan_side(site_b, rule["dir_b"]), patterns)
        db.execute("DELETE FROM baseline WHERE rule_id=?", (rule_id,))
        rows = []
        for rel in set(man_a_after) & set(man_b_after):
            a = man_a_after[rel]
            b = man_b_after[rel]
            rows.append((rule_id, rel, a[0], a[1], b[0], b[1]))
        db.executemany(
            "INSERT OR REPLACE INTO baseline(rule_id,rel,a_size,a_mtime,b_size,b_mtime) VALUES(?,?,?,?,?,?)",
            rows,
        )
        db.commit()

        leftover = len(set(man_a_after) ^ set(man_b_after))
        if leftover:
            emit("注意：同步后仍有 %d 个文件两端不一致，下轮会重试" % leftover, "warn")

        # 回收站过期清理
        keep_days = int(settings.get("trash_days") or 0)
        if keep_days > 0:
            remote.purge_trash(site_a, rule["dir_a"], keep_days)
            remote.purge_trash(site_b, rule["dir_b"], keep_days)

        # 压缩备份：同步成功后先排期，等 N 分钟（backup_delay_min，默认 5）再由
        # worker 打包——避开同步刚结束时文件还在落盘、以及和同步抢 IO 的问题。
        try:
            scheduled, delay = schedule_backup(db, "rules", rule_id)
            if scheduled:
                detail.append("已安排在 %d 分钟后压缩备份" % delay if delay else "已安排压缩备份")
        except RuleError as exc:
            detail.append("压缩备份排期失败：%s" % str(exc)[:200])

        stats = {
            "up": len(plan["a2b"]),
            "down": len(plan["b2a"]),
            "deleted": deleted,
            "bytes": bytes_moved,
            "conflicts": len(plan["conflicts"]),
            "leftover": leftover,
            "same": plan["same"],
        }
        message = "A→B %d，B→A %d，删除 %d，冲突 %d，未变 %d" % (
            stats["up"], stats["down"], stats["deleted"], stats["conflicts"], plan["same"])
        if detail:
            message += "\n" + "\n".join(detail)
        db.execute(
            "UPDATE runs SET finished=?,status='ok',up_count=?,down_count=?,del_count=?,bytes=?,message=? WHERE id=?",
            (common.now_iso(), stats["up"], stats["down"], stats["deleted"], bytes_moved, message, run_id),
        )
        db.execute(
            "UPDATE rules SET last_run=?,last_status='ok',last_message=? WHERE id=?",
            (common.now_iso(), message, rule_id),
        )
        db.commit()
        emit("完成：" + message, "good")
        return stats

    except Exception as exc:  # noqa: BLE001
        detail = str(exc)[:500] or type(exc).__name__
        db.execute("UPDATE runs SET finished=?,status='error',message=? WHERE id=?",
                   (common.now_iso(), detail, run_id))
        db.execute("UPDATE rules SET last_run=?,last_status='error',last_message=? WHERE id=?",
                   (common.now_iso(), detail, rule_id))
        db.commit()
        emit("失败：" + detail, "error")
        raise
    finally:
        _release_lock(lock_fd)


def test_rule(db, rule_id, log=None):
    """只做扫描和决策，不传输——用于"预演"按钮。"""
    rule = load_rule(db, rule_id)
    site_a = load_site(db, rule["site_a"])
    site_b = load_site(db, rule["site_b"])
    patterns = remote.compile_excludes(rule["excludes"])
    man_a = remote.filter_manifest(remote.scan_side(site_a, rule["dir_a"]), patterns)
    man_b = remote.filter_manifest(remote.scan_side(site_b, rule["dir_b"]), patterns)
    baseline = load_baseline(db, rule_id)
    plan = decide(man_a, man_b, baseline, rule["mode"], rule["delete_policy"] in ("trash", "purge"))
    sample = {
        "a2b": plan["a2b"][:20],
        "b2a": plan["b2a"][:20],
        "del_a": plan["del_a"][:20],
        "del_b": plan["del_b"][:20],
    }
    return {
        "a_files": len(man_a),
        "b_files": len(man_b),
        "a2b": len(plan["a2b"]),
        "b2a": len(plan["b2a"]),
        "del": len(plan["del_a"]) + len(plan["del_b"]),
        "conflicts": len(plan["conflicts"]),
        "same": plan["same"],
        "sample": sample,
    }


# ==========================================================================
# 多站互备（3 个以上站点，N 路合并）
# ==========================================================================
def load_group(db, group_id):
    row = db.execute("SELECT * FROM groups WHERE id=?", (group_id,)).fetchone()
    if not row:
        raise GroupError("同步组不存在或已被删除")
    return dict(row)


def load_group_members(db, group_id):
    members = []
    for row in db.execute(
        "SELECT * FROM group_members WHERE group_id=? ORDER BY position", (group_id,)
    ):
        member = dict(row)
        member["site"] = load_site(db, row["site_id"])
        members.append(member)
    return members


def load_group_baseline(db, group_id):
    return {
        row["rel"]: (row["size"], remote.norm_mtime(row["mtime"]))
        for row in db.execute("SELECT rel,size,mtime FROM group_baseline WHERE group_id=?", (group_id,))
    }


def decide_group(manifests, baseline, delete_follow):
    """N 路合并决策。

    参数
    ----
    manifests   : {member_id: {rel: (size, mtime)}}
    baseline    : {rel: (size, mtime)}   上次同步后的权威版本
    delete_follow: 是否让删除传播（多数决）

    返回
    ----
    dict(
        winners   = {rel: member_id},     该路径以谁为准
        delete    = [rel],                需要从所有成员删除
        conflicts = [(rel, member_id)],   落败方，覆盖前要留副本
        same      = int,                  已完全一致的路径数
    )

    删除为什么用多数决
    ------------------
    三站里 A 误删一个文件，如果"任一删除即跟随"，B、C 会立刻跟着删——一次误操作
    波及全部。改成多数决后：2 站删除才真的删，1 删 2 存则把文件推回去。两站时
    1:1 属于平局，保守起见按"保留"处理。
    """
    member_ids = list(manifests.keys())
    total = len(member_ids)
    plan = {"winners": {}, "delete": [], "conflicts": [], "same": 0}

    all_rels = set(baseline)
    for manifest in manifests.values():
        all_rels |= set(manifest)

    for rel in all_rels:
        present = {mid: manifests[mid][rel] for mid in member_ids if rel in manifests[mid]}

        if not present:
            continue  # 所有成员都没了，重建基线时自然消失

        if len(present) == 1:
            only_member, meta = next(iter(present.items()))
            if rel not in baseline:
                plan["winners"][rel] = only_member      # 某站新增
                continue
            missing = total - 1                          # 其余成员都删掉了它
            if delete_follow and missing > 1:
                plan["delete"].append(rel)               # 多数决通过，删除
            else:
                plan["winners"][rel] = only_member       # 平局或少数，推回去
            continue

        versions = set(present.values())
        if len(versions) == 1:
            # 内容一致；如果有成员缺失，仍要推给它
            if len(present) == total:
                plan["same"] += 1
            else:
                plan["winners"][rel] = next(iter(present))
            continue

        # 多版本并存：先看谁相对基线改过。
        # 只按 mtime 选最新有个坑：OpenWrt 等设备时钟可能比 NAS 慢，
        # 明明在路由器上刚改过，时间戳却更旧，会被本机旧版本覆盖。
        base = baseline.get(rel)
        # 判断「谁改过」只看大小：mtime 会受各站时钟影响（OpenWrt 常比 NAS 慢），
        # 用时间判断会把刚改过的站误判成旧版本，导致它的改动被覆盖。
        # 大小变了才算真的改过；大小没变的差异交给下面的冲突分支处理。
        changed = {mid: meta for mid, meta in present.items() if base is None or meta[0] != base[0]}

        if len(changed) == 1:
            # 只有一个站改过 → 以它为准，不看 mtime
            plan["winners"][rel] = next(iter(changed))
        elif len(changed) >= 2:
            # 多个站都改过 → 真冲突，mtime 最新者胜，其余留副本
            winner_id, winner_meta = max(changed.items(), key=lambda kv: kv[1][1])
            plan["winners"][rel] = winner_id
            for mid, meta in changed.items():
                if mid != winner_id and meta != winner_meta:
                    plan["conflicts"].append((rel, mid))
        else:
            # 没有站改过但版本不同（基线缺失或不准）→ 退回 mtime 最新
            winner_id, winner_meta = max(present.items(), key=lambda kv: kv[1][1])
            plan["winners"][rel] = winner_id
    return plan


def run_group(db, group_id, trigger="manual", log=None):
    """执行一次多站互备。

    流程刻意分成三段，与用户的心智模型一致：
        ① 把各路径的胜出版本先拉回本机
        ② 再从本机推给其余成员
        ③ 最后处理删除
    这样本机始终是"中转站"，A 与 C 之间不需要直连。
    """
    def emit(message, level="info"):
        if log:
            log(level, message)

    lock_fd = _acquire_named_lock("group-%s" % group_id, "这个同步组正在同步中，请稍后再试")
    started = common.now_iso()
    cur = db.execute(
        "INSERT INTO runs(rule_id,started,status,message) VALUES(?,?,'running',?)",
        ("group:" + group_id, started, trigger),
    )
    run_id = cur.lastrowid
    db.commit()

    try:
        group = load_group(db, group_id)
        members = load_group_members(db, group_id)
        if len(members) < 2:
            raise GroupError("同步组至少需要 2 个成员")
        locals_ = [m for m in members if m["site"]["kind"] == "local"]
        if not locals_:
            raise GroupError("同步组必须包含本机成员（本机是中转站）")
        local_member = locals_[0]
        by_id = {m["id"]: m for m in members}

        settings = common.get_settings(db)
        delete_follow = group["delete_policy"] in ("trash", "purge")
        patterns = remote.compile_excludes(group["excludes"])
        stamp = time.strftime("%Y%m%d-%H%M%S")
        detail = []          # 记录实际操作，写进日志供界面查看

        # ---------- 扫描 ----------
        manifests = {}
        for member in members:
            manifest = remote.scan_side(member["site"], member["dir"])
            manifest = remote.filter_manifest(manifest, patterns)
            manifests[member["id"]] = manifest
            emit("扫描 %s（%s）：%d 个文件" % (member["site"]["name"], member["dir"], len(manifest)))

        baseline = load_group_baseline(db, group_id)
        # 某成员扫描到 0 个文件、而基线里有过记录，说明该站目录可能失效（路径错/未挂载）。
        # 此时若按多数决删除，会把仅存的文件从其他站删掉，所以本轮禁用删除。
        empty_members = [m for m in members if not manifests[m["id"]]]
        if empty_members and baseline:
            names = "、".join(m["site"]["name"] for m in empty_members)
            emit("警告：%s 扫描到 0 个文件，本轮不执行删除（请检查该站目录是否正确）" % names, "warn")
            delete_follow = False
        plan = decide_group(manifests, baseline, delete_follow)
        if not plan["winners"] and not plan["delete"]:
            emit("三站内容一致：%d 个文件全部已是最新，本轮只扫描检查，不拉取也不推送" % plan["same"], "good")
        else:
            emit("决策：%d 个文件需更新，%d 个已一致（不动），%d 个待删除，%d 个冲突" % (
                len(plan["winners"]), plan["same"], len(plan["delete"]), len(plan["conflicts"])))

        # ---------- 冲突副本 ----------
        if plan["conflicts"] and settings.get("conflict_copy") == "1":
            grouped = {}
            for rel, mid in plan["conflicts"]:
                grouped.setdefault(mid, []).append(rel)
            for mid, files in grouped.items():
                member = by_id[mid]
                moved = remote.trash_side(member["site"], member["dir"], files, "conflicts/" + stamp)
                emit("保留 %d 个冲突副本（%s 侧）" % (moved, member["site"]["name"]), "warn")

        # ---------- 阶段一：胜出版本拉回本机 ----------
        pull_by_source = {}
        for rel, winner_id in plan["winners"].items():
            if winner_id == local_member["id"]:
                continue
            local_meta = manifests[local_member["id"]].get(rel)
            if local_meta == manifests[winner_id][rel]:
                continue
            pull_by_source.setdefault(winner_id, []).append(rel)

        # 时间不同但内容相同（复制/解压导致时间漂移）不应重复传输：
        # 用内容哈希确认，相同的从计划里剔除，只保留真正内容不同的文件。
        skipped_same = 0
        if pull_by_source:
            for winner_id in list(pull_by_source):
                files = pull_by_source[winner_id]
                try:
                    src_hashes = remote.hash_side(by_id[winner_id]["site"], by_id[winner_id]["dir"], files)
                    dst_hashes = remote.hash_side(local_member["site"], local_member["dir"], files)
                except remote.RemoteError as exc:
                    emit("计算哈希失败，按原计划传输：%s" % exc, "warn")
                    continue
                keep = [rel for rel in files if src_hashes.get(rel) != dst_hashes.get(rel)]
                skipped_same += len(files) - len(keep)
                if keep:
                    pull_by_source[winner_id] = keep
                else:
                    del pull_by_source[winner_id]
        if skipped_same:
            emit("内容相同、仅时间不同：跳过 %d 个文件" % skipped_same, "good")

        pulled = 0
        bytes_moved = 0
        for winner_id, files in pull_by_source.items():
            source = by_id[winner_id]
            size = sum(manifests[winner_id][rel][0] for rel in files)
            emit("阶段一：从 %s 拉回 %d 个文件（%s）：%s" % (
                source["site"]["name"], len(files), common.human_size(size), _brief(files)))
            detail.append("拉回 %s → 本机（%d 个，以 %s 的版本为准）：%s" % (
                source["site"]["name"], len(files), source["site"]["name"], _brief(files)))
            remote.transfer(source["site"], source["dir"],
                            local_member["site"], local_member["dir"], files)
            # 传输后把本机 mtime 统一为权威值：不依赖 rsync/tar 是否保留时间，
            # 否则目标时间一旦漂移，下一轮又会被判成「有变化」而反复重传。
            try:
                remote.set_mtime(local_member["site"], local_member["dir"],
                                 [(rel, manifests[winner_id][rel][1]) for rel in files])
            except remote.RemoteError as exc:
                emit("统一本机文件时间失败（文件已同步，不影响内容）：%s" % exc, "warn")
            pulled += len(files)
            bytes_moved += size
        if not pulled:
            emit("阶段一：本机已是各文件的最新版本，无需拉取")

        # ---------- 阶段二：从本机推给其余成员 ----------
        pushed = 0
        for member in members:
            if member["id"] == local_member["id"]:
                continue
            need = []
            for rel, winner_id in plan["winners"].items():
                if rel in plan["delete"]:
                    continue
                target_meta = manifests[member["id"]].get(rel)
                if target_meta != manifests[winner_id][rel]:
                    need.append(rel)
            if need:
                try:
                    src_hashes = remote.hash_side(local_member["site"], local_member["dir"], need)
                    dst_hashes = remote.hash_side(member["site"], member["dir"], need)
                    before = len(need)
                    need = [rel for rel in need if src_hashes.get(rel) != dst_hashes.get(rel)]
                    skipped_same += before - len(need)
                except remote.RemoteError as exc:
                    emit("计算哈希失败，按原计划推送：%s" % exc, "warn")
            if not need:
                continue
            size = sum(manifests[plan["winners"][rel]][rel][0] for rel in need)
            emit("阶段二：推送 %d 个文件到 %s（%s）：%s" % (
                len(need), member["site"]["name"], common.human_size(size), _brief(need)))
            detail.append("推送 本机 → %s（%d 个）：%s" % (
                member["site"]["name"], len(need), _brief(need)))
            remote.transfer(local_member["site"], local_member["dir"],
                            member["site"], member["dir"], need)
            # 目标站的时间同样统一为权威值，保证三站 mtime 完全一致
            try:
                remote.set_mtime(member["site"], member["dir"],
                                 [(rel, manifests[plan["winners"][rel]][rel][1]) for rel in need])
            except remote.RemoteError as exc:
                emit("统一 %s 文件时间失败（文件已同步，不影响内容）：%s" % (
                    member["site"]["name"], exc), "warn")
            pushed += len(need)
            bytes_moved += size
        if not pushed:
            emit("阶段二：其余成员都已是最新，无需推送")

        # ---------- 阶段三：删除 ----------
        deleted = 0
        for rel in plan["delete"]:
            for member in members:
                if rel not in manifests[member["id"]]:
                    continue
                if group["delete_policy"] == "purge":
                    deleted += remote.purge_side(member["site"], member["dir"], [rel])
                else:
                    deleted += remote.trash_side(member["site"], member["dir"], [rel], stamp)
        if deleted:
            emit("阶段三：多数成员已删除，跟随删除 %d 个文件（%s）：%s" % (
                deleted, "直接删除" if group["delete_policy"] == "purge" else "已移入回收站",
                _brief(plan["delete"])))
            detail.append("删除（多数决，%d 个）：%s" % (deleted, _brief(plan["delete"])))

        # ---------- 重建基线 ----------
        after = {}
        for member in members:
            after[member["id"]] = remote.filter_manifest(
                remote.scan_side(member["site"], member["dir"]), patterns)
        rels = set()
        for manifest in after.values():
            rels |= set(manifest)

        rows = []
        leftover = 0
        for rel in rels:
            present = [after[mid][rel] for mid in after if rel in after[mid]]
            if not present:
                continue
            counts = {}
            for meta in present:
                counts[meta] = counts.get(meta, 0) + 1
            best = max(counts.items(), key=lambda kv: (kv[1], kv[0][1]))[0]
            rows.append((group_id, rel, best[0], best[1]))
            if len(counts) > 1:
                leftover += 1

        db.execute("DELETE FROM group_baseline WHERE group_id=?", (group_id,))
        db.executemany(
            "INSERT OR REPLACE INTO group_baseline(group_id,rel,size,mtime) VALUES(?,?,?,?)", rows)
        db.commit()

        if leftover:
            emit("注意：仍有 %d 个文件在成员间不一致，下轮会重试" % leftover, "warn")

        keep_days = int(settings.get("trash_days") or 0)
        if keep_days > 0:
            for member in members:
                remote.purge_trash(member["site"], member["dir"], keep_days)

        # 压缩备份：只备份本机（中转站）目录，同步成功后延迟 N 分钟再由 worker 打包
        try:
            scheduled, delay = schedule_backup(db, "groups", group_id)
            if scheduled:
                detail.append("已安排在 %d 分钟后压缩备份" % delay if delay else "已安排压缩备份")
        except RuleError as exc:
            detail.append("压缩备份排期失败：%s" % str(exc)[:200])

        stats = {
            "pulled": pulled,
            "pushed": pushed,
            "deleted": deleted,
            "conflicts": len(plan["conflicts"]),
            "bytes": bytes_moved,
            "leftover": leftover,
            "same": plan["same"],
        }
        message = "拉回 %d，推送 %d，删除 %d，冲突 %d，未变 %d" % (
            pulled, pushed, deleted, len(plan["conflicts"]), plan["same"])
        if detail:
            message += "\n" + "\n".join(detail)
        db.execute(
            "UPDATE runs SET finished=?,status='ok',up_count=?,down_count=?,del_count=?,bytes=?,message=? WHERE id=?",
            (common.now_iso(), pushed, pulled, deleted, bytes_moved, message, run_id),
        )
        db.execute("UPDATE groups SET last_run=?,last_status='ok',last_message=? WHERE id=?",
                   (common.now_iso(), message, group_id))
        db.commit()
        emit("完成：" + message, "good")
        return stats

    except Exception as exc:  # noqa: BLE001
        detail = str(exc)[:500] or type(exc).__name__
        db.execute("UPDATE runs SET finished=?,status='error',message=? WHERE id=?",
                   (common.now_iso(), detail, run_id))
        db.execute("UPDATE groups SET last_run=?,last_status='error',last_message=? WHERE id=?",
                   (common.now_iso(), detail, group_id))
        db.commit()
        emit("失败：" + detail, "error")
        raise
    finally:
        _release_lock(lock_fd)


def test_group(db, group_id):
    """只扫描和决策，不传输。"""
    group = load_group(db, group_id)
    members = load_group_members(db, group_id)
    if not members:
        raise GroupError("同步组还没有成员")
    patterns = remote.compile_excludes(group["excludes"])
    manifests = {}
    detail = []
    for member in members:
        manifest = remote.filter_manifest(remote.scan_side(member["site"], member["dir"]), patterns)
        manifests[member["id"]] = manifest
        detail.append({"name": member["site"]["name"], "dir": member["dir"], "files": len(manifest)})
    baseline = load_group_baseline(db, group_id)
    plan = decide_group(manifests, baseline, group["delete_policy"] in ("trash", "purge"))

    by_id = {m["id"]: m["site"]["name"] for m in members}
    winners = {}
    for rel, mid in plan["winners"].items():
        winners.setdefault(by_id[mid], 0)
        winners[by_id[mid]] += 1

    return {
        "members": detail,
        "winners": winners,
        "update": len(plan["winners"]),
        "delete": len(plan["delete"]),
        "conflicts": len(plan["conflicts"]),
        "same": plan["same"],
        "delete_sample": plan["delete"][:10],
    }
