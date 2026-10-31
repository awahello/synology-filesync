#!/usr/bin/python3
# Copyright (c) 2026 AWA <https://www.akkdiy.cn>. All rights reserved.
"""FileSync Web 入口：DSM 套件界面 + JSON API。

index.cgi  → cgi_app.py index  → 渲染 HTML 界面
api.cgi    → cgi_app.py api    → 处理 JSON 请求
"""

import datetime as dt
import json
import os
import re
import secrets
import sys
import uuid
from pathlib import Path

import common
import engine
import remote

UI_PATH = Path(__file__).with_name("ui_page.html")

HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._:\-]{0,252})$")
USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9._\-]{0,63}$")


# --------------------------------------------------------------------------
# 请求解析
# --------------------------------------------------------------------------
def read_json():
    try:
        length = int(os.environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    if length <= 0 or length > common.MAX_BODY:
        raise ValueError("请求内容不正确")
    raw = sys.stdin.buffer.read(length)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ValueError("请求内容不是有效的 JSON")
    if not isinstance(data, dict):
        raise ValueError("请求内容格式不正确")
    return data


def query_action():
    from urllib.parse import parse_qs
    return parse_qs(os.environ.get("QUERY_STRING", "")).get("action", [""])[0]


# --------------------------------------------------------------------------
# 序列化
# --------------------------------------------------------------------------
def site_public(row):
    return {
        "id": row["id"], "name": row["name"], "kind": row["kind"],
        "host": row["host"], "port": row["port"], "ssh_user": row["ssh_user"],
        "key_id": row["key_id"], "note": row["note"],
        "last_check": row["last_check"], "last_ok": row["last_ok"],
        "last_check_msg": row["last_check_msg"], "caps_json": row["caps_json"],
    }


def rule_public(row):
    return {
        "id": row["id"], "name": row["name"],
        "site_a": row["site_a"], "dir_a": row["dir_a"],
        "site_b": row["site_b"], "dir_b": row["dir_b"],
        "mode": row["mode"], "delete_policy": row["delete_policy"],
        "excludes": row["excludes"], "interval_min": row["interval_min"],
        "start_delay_min": row["start_delay_min"], "retry_min": row["retry_min"],
        "backup_enabled": row["backup_enabled"], "backup_dir": row["backup_dir"],
        "backup_keep": row["backup_keep"], "backup_interval_hour": row["backup_interval_hour"],
        "backup_delay_min": row["backup_delay_min"], "backup_due_at": row["backup_due_at"],
        "backup_last": row["backup_last"], "backup_msg": row["backup_msg"],
        "enabled": row["enabled"], "next_run": row["next_run"],
        "last_run": row["last_run"], "last_status": row["last_status"],
        "last_message": row["last_message"],
    }


# --------------------------------------------------------------------------
# 排期与压缩备份的入参处理（规则与同步组共用）
# --------------------------------------------------------------------------
def int_field(req, key, default, low, high, label):
    raw = req.get(key)
    if raw is None or raw == "":
        raw = default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValueError(label + "不正确")
    if not low <= value <= high:
        raise ValueError("%s必须在 %d 到 %d 之间" % (label, low, high))
    return value


def next_run_iso(delay_minutes):
    """首次运行延迟：保存后先等 N 分钟再跑第一轮，避开开机/安装高峰。"""
    delay = max(0, int(delay_minutes or 0))
    return (common.now_local() + dt.timedelta(minutes=delay)).isoformat(timespec="seconds")


def backup_fields(req, local_dir, label="规则"):
    """解析压缩备份的四个参数，并挡住「备份目录落在同步目录里」这种致命配置。"""
    enabled = 1 if str(req.get("backup_enabled") or "0") in ("1", "true", "True") else 0
    raw_dir = (req.get("backup_dir") or "").strip()
    backup_dir = common.clean_abs_path(raw_dir) if raw_dir else ""
    if raw_dir and not backup_dir:
        raise ValueError("备份目录必须是以 / 开头的绝对路径，且不能包含 ..")
    keep = int_field(req, "backup_keep", 7, 1, 999, "备份保留份数")
    hours = int_field(req, "backup_interval_hour", 24, 1, 720, "备份间隔")
    delay = int_field(req, "backup_delay_min", 5, 0, 1440, "备份延迟")
    if enabled:
        if not backup_dir:
            raise ValueError("启用压缩备份需要填写备份目录")
        if not local_dir:
            raise ValueError("这条%s两端都不是本机，没有可打包的主机目录" % label)
        if common.paths_overlap(local_dir, backup_dir):
            raise ValueError("备份目录不能和本机同步目录重叠，否则备份包会被再次同步")
    return enabled, backup_dir, keep, hours, delay


def worker_running():
    try:
        pid = int(common.PID_PATH.read_text(encoding="utf-8").strip())
        os.kill(pid, 0)
        return pid
    except (OSError, ValueError):
        return 0


# --------------------------------------------------------------------------
# GET
# --------------------------------------------------------------------------
def api_bootstrap(db):
    sites = [site_public(r) for r in db.execute("SELECT * FROM sites ORDER BY kind='local' DESC, created")]
    rules = [rule_public(r) for r in db.execute("SELECT * FROM rules ORDER BY created")]
    groups = [group_public(db, r) for r in db.execute("SELECT * FROM groups ORDER BY created")]
    keys = [{"id": r["id"], "name": r["name"], "public_line": r["public_line"], "created": r["created"]}
            for r in db.execute("SELECT * FROM keys ORDER BY created")]
    return {
        "ok": True,
        "version": common.APP_VERSION,
        "sites": sites,
        "rules": rules,
        "groups": groups,
        "keys": keys,
        "settings": common.get_settings(db),
        "worker": {"pid": worker_running()},
    }


def api_logs(db, req):
    target = req.get("id")
    if not isinstance(target, str):
        raise ValueError("编号不正确")
    if target.startswith("group:"):
        if not re.fullmatch(r"group:[0-9a-f-]{36}", target):
            raise ValueError("同步组编号不正确")
        key = target
    else:
        if not re.fullmatch(r"[0-9a-f-]{36}", target):
            raise ValueError("规则编号不正确")
        key = target
    rows = db.execute(
        "SELECT started,finished,status,message,up_count,down_count,del_count,bytes "
        "FROM runs WHERE rule_id=? ORDER BY id DESC LIMIT 50", (key,)
    ).fetchall()
    return {"ok": True, "runs": [dict(r) for r in rows]}


# --------------------------------------------------------------------------
# POST：站点
# --------------------------------------------------------------------------
def ensure_default_key(db):
    """远端站点必须有密钥才能工作，所以不存在"没有密钥"这种合法状态。

    有现成的就复用第一个，一个都没有就自动生成一把。用户不需要关心这件事。
    """
    row = db.execute("SELECT id FROM keys ORDER BY created LIMIT 1").fetchone()
    if row:
        return row["id"]
    key_id, public_line = remote.generate_key("同步密钥")
    db.execute("INSERT INTO keys(id,name,public_line,created) VALUES(?,?,?,?)",
               (key_id, "同步密钥", public_line, common.now_iso()))
    db.commit()
    return key_id


def api_save_site(db, req):
    site_id = req.get("id")
    name = common.clean_text(req.get("name"), 60, allow_empty=False)
    kind = req.get("kind")
    host = (req.get("host") or "").strip()
    ssh_user = (req.get("ssh_user") or "").strip()
    key_id = req.get("key_id") or ""
    note = common.clean_text(req.get("note"), 120) or ""

    if not name:
        raise ValueError("请填写站点名称（最多 60 字）")
    if kind not in ("openwrt", "linux"):
        raise ValueError("站点类型不正确")
    if not host or not HOST_RE.match(host):
        raise ValueError("站点地址格式不正确")
    if not ssh_user or not USER_RE.match(ssh_user):
        raise ValueError("SSH 用户名为空或格式不正确")
    try:
        port = int(req.get("port") or 22)
    except (TypeError, ValueError):
        raise ValueError("SSH 端口不正确")
    if not 1 <= port <= 65535:
        raise ValueError("SSH 端口必须在 1-65535 之间")
    if key_id:
        if not db.execute("SELECT 1 FROM keys WHERE id=?", (key_id,)).fetchone():
            raise ValueError("所选密钥不存在")
    else:
        # 没选就自动补一把，避免用户被"请先生成密钥"卡住
        try:
            key_id = ensure_default_key(db)
        except remote.RemoteError as exc:
            raise ValueError("自动生成密钥失败：" + str(exc))

    if site_id:
        row = db.execute("SELECT kind FROM sites WHERE id=?", (site_id,)).fetchone()
        if not row:
            raise ValueError("站点不存在")
        if row["kind"] == "local":
            raise ValueError("本机站点不能修改")
        db.execute(
            "UPDATE sites SET name=?,kind=?,host=?,port=?,ssh_user=?,key_id=?,note=? WHERE id=?",
            (name, kind, host, port, ssh_user, key_id, note, site_id),
        )
    else:
        site_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO sites(id,name,kind,host,port,ssh_user,key_id,note,created) VALUES(?,?,?,?,?,?,?,?,?)",
            (site_id, name, kind, host, port, ssh_user, key_id, note, common.now_iso()),
        )
    db.commit()
    return {"ok": True, "id": site_id}


def api_delete_site(db, req):
    site_id = req.get("id")
    if not isinstance(site_id, str):
        raise ValueError("站点编号不正确")
    if site_id == "local":
        raise ValueError("本机站点不能删除")
    used = db.execute("SELECT COUNT(*) FROM rules WHERE site_a=? OR site_b=?", (site_id, site_id)).fetchone()[0]
    if used:
        raise ValueError("还有 %d 条同步规则使用此站点，请先删除这些规则" % used)
    db.execute("DELETE FROM sites WHERE id=?", (site_id,))
    db.commit()
    return {"ok": True}


def api_test_site(db, req):
    site = engine.load_site(db, req.get("id"))
    if site["kind"] == "local":
        caps = remote.test_local()
        summary = "本机路径可直接访问"
    else:
        # 老数据里可能存在没绑定密钥的站点，这里顺手补上再测
        if not site["key_id"]:
            try:
                key_id = ensure_default_key(db)
            except remote.RemoteError as exc:
                raise ValueError("无法生成密钥：" + str(exc))
            db.execute("UPDATE sites SET key_id=? WHERE id=?", (key_id, site["id"]))
            db.commit()
            site["key_id"] = key_id
        try:
            caps = remote.probe(site)
        except remote.RemoteError as exc:
            message = str(exc)
            if "permission denied" in message.lower() or "publickey" in message.lower():
                message = ("密钥登录被拒绝，公钥可能还没装到对方机器上。"
                           "请编辑这个站点，填一次 SSH 密码后点「用密码部署公钥」。")
            db.execute("UPDATE sites SET last_check=?,last_ok=0,last_check_msg=? WHERE id=?",
                       (common.now_iso(), message[:300], site["id"]))
            db.commit()
            raise ValueError("连接失败：" + message)
        rsync = caps.get("rsync", "none")
        summary = "%s %s · %s" % (
            caps.get("os", "?"), caps.get("kernel", ""),
            ("rsync " + rsync.replace("rsync  version ", "").split()[0]) if caps.get("has_rsync") else "未安装 rsync（将使用 tar 传输）",
        )
    db.execute("UPDATE sites SET last_check=?,last_ok=1,last_check_msg=?,caps_json=? WHERE id=?",
               (common.now_iso(), summary, json.dumps(caps, ensure_ascii=False), site["id"]))
    db.commit()
    return {"ok": True, "summary": summary, "caps": caps}


def api_deploy_key(db, req):
    """用一次性密码把公钥装到对方机器，之后全部走密钥免密。密码不保存。"""
    site = engine.load_site(db, req.get("id"))
    if site["kind"] == "local":
        raise ValueError("本机站点不需要部署密钥")
    password = req.get("password")
    if not isinstance(password, str) or not password:
        raise ValueError("请填写对方的 SSH 密码")
    if len(password) > 256 or any(ord(c) < 9 for c in password):
        raise ValueError("密码格式不正确")
    key_id = site["key_id"]
    if not key_id:
        try:
            key_id = ensure_default_key(db)
        except remote.RemoteError as exc:
            raise ValueError("无法生成密钥：" + str(exc))
        db.execute("UPDATE sites SET key_id=? WHERE id=?", (key_id, site["id"]))
        db.commit()
        site["key_id"] = key_id
    row = db.execute("SELECT public_line FROM keys WHERE id=?", (key_id,)).fetchone()
    if not row:
        raise ValueError("所选密钥已不存在，请重新选择")

    try:
        remote.deploy_public_key(site, password, row["public_line"])
    except remote.RemoteError as exc:
        raise ValueError(str(exc))

    # 部署完立刻用密钥验证，确保不是"写进去了但登不上"
    try:
        caps = remote.probe(site)
    except remote.RemoteError as exc:
        raise ValueError("公钥已写入，但密钥登录仍未成功：" + str(exc))

    summary = "%s %s · %s" % (
        caps.get("os", "?"), caps.get("kernel", ""),
        ("rsync " + caps.get("rsync", "").replace("rsync  version ", "").split()[0])
        if caps.get("has_rsync") else "未安装 rsync（将使用 tar 传输）",
    )
    db.execute("UPDATE sites SET last_check=?,last_ok=1,last_check_msg=?,caps_json=? WHERE id=?",
               (common.now_iso(), summary, json.dumps(caps, ensure_ascii=False), site["id"]))
    db.commit()
    return {"ok": True, "summary": summary, "caps": caps}


# --------------------------------------------------------------------------
# POST：密钥
# --------------------------------------------------------------------------
def api_gen_key(db, req):
    name = common.clean_text(req.get("name"), 60) or "同步密钥"
    key_id, public_line = remote.generate_key(name)
    db.execute("INSERT INTO keys(id,name,public_line,created) VALUES(?,?,?,?)",
               (key_id, name, public_line, common.now_iso()))
    db.commit()
    return {"ok": True, "id": key_id, "public_line": public_line}


def api_delete_key(db, req):
    key_id = req.get("id")
    if not isinstance(key_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", key_id):
        raise ValueError("密钥编号不正确")
    used = db.execute("SELECT COUNT(*) FROM sites WHERE key_id=?", (key_id,)).fetchone()[0]
    if used:
        raise ValueError("有 %d 个站点正在使用此密钥，请先改绑" % used)
    db.execute("DELETE FROM keys WHERE id=?", (key_id,))
    db.commit()
    remote.delete_key_file(key_id)
    return {"ok": True}


# --------------------------------------------------------------------------
# POST：规则
# --------------------------------------------------------------------------
def api_save_rule(db, req):
    rule_id = req.get("id")
    name = common.clean_text(req.get("name"), 80, allow_empty=False)
    site_a = req.get("site_a")
    site_b = req.get("site_b")
    dir_a = common.clean_abs_path(req.get("dir_a"))
    dir_b = common.clean_abs_path(req.get("dir_b"))
    mode = req.get("mode")
    delete_policy = req.get("delete_policy")
    excludes = req.get("excludes") or ""
    try:
        interval = int(req.get("interval_min") or 10)
    except (TypeError, ValueError):
        raise ValueError("执行间隔不正确")

    if not name:
        raise ValueError("请填写规则名称（最多 80 字）")
    if not dir_a or not dir_b:
        raise ValueError("两端目录必须是以 / 开头的绝对路径，且不能包含 ..")
    if not site_a or not site_b:
        raise ValueError("请选择两端的站点")
    if site_a == site_b and dir_a == dir_b:
        raise ValueError("两端不能是同一个站点上的同一个目录")
    for sid in (site_a, site_b):
        if not db.execute("SELECT 1 FROM sites WHERE id=?", (sid,)).fetchone():
            raise ValueError("所选站点不存在")
    if mode not in ("both", "a2b", "b2a"):
        raise ValueError("同步方向不正确")
    if delete_policy not in ("trash", "purge", "keep"):
        raise ValueError("删除处理方式不正确")
    if not 1 <= interval <= 10080:
        raise ValueError("执行间隔必须在 1 到 10080 分钟之间")
    if not isinstance(excludes, str) or len(excludes) > 8000 or any(ord(c) < 9 for c in excludes):
        raise ValueError("排除规则格式不正确")

    start_delay = int_field(req, "start_delay_min", 0, 0, 10080, "首次运行延迟")
    retry = int_field(req, "retry_min", 60, 0, 1440, "首轮失败重试间隔")

    # 压缩备份只打本机那一端的目录：两端都是远端时没有"主机目录"可打包
    local_dir = ""
    for sid, directory in ((site_a, dir_a), (site_b, dir_b)):
        site = db.execute("SELECT kind FROM sites WHERE id=?", (sid,)).fetchone()
        if site and site["kind"] == "local":
            local_dir = directory
            break
    backup_enabled, backup_dir, backup_keep, backup_hour, backup_delay = backup_fields(req, local_dir)
    next_at = next_run_iso(start_delay)

    if rule_id:
        if not db.execute("SELECT 1 FROM rules WHERE id=?", (rule_id,)).fetchone():
            raise ValueError("规则不存在")
        db.execute(
            "UPDATE rules SET name=?,site_a=?,dir_a=?,site_b=?,dir_b=?,mode=?,delete_policy=?,"
            "excludes=?,interval_min=?,start_delay_min=?,retry_min=?,backup_enabled=?,backup_dir=?,"
            "backup_keep=?,backup_interval_hour=?,backup_delay_min=?,backup_due_at='',backup_force=0,"
            "next_run=? WHERE id=?",
            (name, site_a, dir_a, site_b, dir_b, mode, delete_policy, excludes, interval,
             start_delay, retry, backup_enabled, backup_dir, backup_keep, backup_hour,
             backup_delay, next_at, rule_id),
        )
    else:
        rule_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO rules(id,name,site_a,dir_a,site_b,dir_b,mode,delete_policy,excludes,"
            "interval_min,start_delay_min,retry_min,backup_enabled,backup_dir,backup_keep,"
            "backup_interval_hour,backup_delay_min,enabled,next_run,created)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)",
            (rule_id, name, site_a, dir_a, site_b, dir_b, mode, delete_policy, excludes,
             interval, start_delay, retry, backup_enabled, backup_dir, backup_keep, backup_hour,
             backup_delay, next_at, common.now_iso()),
        )
    db.commit()
    return {"ok": True, "id": rule_id, "next_run": next_at}


def api_delete_rule(db, req):
    rule_id = req.get("id")
    if not isinstance(rule_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", rule_id):
        raise ValueError("规则编号不正确")
    db.execute("DELETE FROM baseline WHERE rule_id=?", (rule_id,))
    db.execute("DELETE FROM runs WHERE rule_id=?", (rule_id,))
    db.execute("DELETE FROM rules WHERE id=?", (rule_id,))
    db.commit()
    return {"ok": True}


def api_run_rule(db, req):
    rule_id = req.get("id")
    if not isinstance(rule_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", rule_id):
        raise ValueError("规则编号不正确")
    if not db.execute("SELECT 1 FROM rules WHERE id=?", (rule_id,)).fetchone():
        raise ValueError("规则不存在")
    db.execute("UPDATE rules SET next_run=? WHERE id=?", (common.now_iso(), rule_id))
    db.commit()
    return {"ok": True}


def api_toggle_rule(db, req):
    rule_id = req.get("id")
    enabled = req.get("enabled")
    if not isinstance(rule_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", rule_id):
        raise ValueError("规则编号不正确")
    if not isinstance(enabled, bool):
        raise ValueError("启用状态不正确")
    row = db.execute("SELECT start_delay_min FROM rules WHERE id=?", (rule_id,)).fetchone()
    delay = row["start_delay_min"] if row else 0
    db.execute("UPDATE rules SET enabled=?,next_run=? WHERE id=?",
               (1 if enabled else 0, next_run_iso(delay) if enabled else "", rule_id))
    db.commit()
    return {"ok": True}


def api_test_rule(db, req):
    rule_id = req.get("id")
    if not isinstance(rule_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", rule_id):
        raise ValueError("规则编号不正确")
    try:
        return dict(engine.test_rule(db, rule_id), ok=True)
    except remote.RemoteError as exc:
        raise ValueError("预演失败：" + str(exc))


# --------------------------------------------------------------------------
# POST：多站互备（同步组）
# --------------------------------------------------------------------------
def group_public(db, row):
    members = []
    for m in db.execute("SELECT * FROM group_members WHERE group_id=? ORDER BY position", (row["id"],)):
        site = db.execute("SELECT name,kind FROM sites WHERE id=?", (m["site_id"],)).fetchone()
        members.append({
            "id": m["id"],
            "site_id": m["site_id"],
            "dir": m["dir"],
            "site_name": site["name"] if site else "（站点已删除）",
            "site_kind": site["kind"] if site else "unknown",
        })
    return {
        "id": row["id"], "name": row["name"],
        "delete_policy": row["delete_policy"], "excludes": row["excludes"],
        "interval_min": row["interval_min"],
        "start_delay_min": row["start_delay_min"], "retry_min": row["retry_min"],
        "backup_enabled": row["backup_enabled"], "backup_dir": row["backup_dir"],
        "backup_keep": row["backup_keep"], "backup_interval_hour": row["backup_interval_hour"],
        "backup_delay_min": row["backup_delay_min"], "backup_due_at": row["backup_due_at"],
        "backup_last": row["backup_last"], "backup_msg": row["backup_msg"],
        "enabled": row["enabled"],
        "next_run": row["next_run"], "last_run": row["last_run"],
        "last_status": row["last_status"], "last_message": row["last_message"],
        "members": members,
    }


def api_save_group(db, req):
    group_id = req.get("id")
    name = common.clean_text(req.get("name"), 80, allow_empty=False)
    delete_policy = req.get("delete_policy")
    excludes = req.get("excludes") or ""
    raw_members = req.get("members")
    try:
        interval = int(req.get("interval_min") or 10)
    except (TypeError, ValueError):
        raise ValueError("执行间隔不正确")

    if not name:
        raise ValueError("请填写同步组名称（最多 80 字）")
    if delete_policy not in ("trash", "purge", "keep"):
        raise ValueError("删除处理方式不正确")
    if not 1 <= interval <= 10080:
        raise ValueError("执行间隔必须在 1 到 10080 分钟之间")
    if not isinstance(excludes, str) or len(excludes) > 8000:
        raise ValueError("排除规则格式不正确")
    if not isinstance(raw_members, list) or len(raw_members) < 2:
        raise ValueError("同步组至少需要 2 个成员")
    if len(raw_members) > 8:
        raise ValueError("同步组最多 8 个成员")

    cleaned = []
    seen = set()
    has_local = False
    local_dir = ""
    for item in raw_members:
        if not isinstance(item, dict):
            raise ValueError("成员格式不正确")
        site_id = item.get("site_id")
        directory = common.clean_abs_path(item.get("dir"))
        if not site_id or not directory:
            raise ValueError("每个成员都需要选择站点并填写绝对路径")
        site = db.execute("SELECT kind FROM sites WHERE id=?", (site_id,)).fetchone()
        if not site:
            raise ValueError("成员里包含不存在的站点")
        if site["kind"] == "local":
            has_local = True
            local_dir = directory
        key = (site_id, directory)
        if key in seen:
            raise ValueError("同一个站点不能重复添加同一个目录")
        seen.add(key)
        cleaned.append((site_id, directory))

    if not has_local:
        raise ValueError("同步组必须包含本机成员——本机负责中转，A 站与 C 站之间不需要直连")

    start_delay = int_field(req, "start_delay_min", 0, 0, 10080, "首次运行延迟")
    retry = int_field(req, "retry_min", 60, 0, 1440, "首轮失败重试间隔")
    backup_enabled, backup_dir, backup_keep, backup_hour, backup_delay = backup_fields(req, local_dir, "同步组")
    next_at = next_run_iso(start_delay)

    if group_id:
        if not db.execute("SELECT 1 FROM groups WHERE id=?", (group_id,)).fetchone():
            raise ValueError("同步组不存在")
        db.execute(
            "UPDATE groups SET name=?,delete_policy=?,excludes=?,interval_min=?,start_delay_min=?,"
            "retry_min=?,backup_enabled=?,backup_dir=?,backup_keep=?,backup_interval_hour=?,"
            "backup_delay_min=?,backup_due_at='',backup_force=0,next_run=? WHERE id=?",
            (name, delete_policy, excludes, interval, start_delay, retry, backup_enabled,
             backup_dir, backup_keep, backup_hour, backup_delay, next_at, group_id),
        )
        db.execute("DELETE FROM group_members WHERE group_id=?", (group_id,))
    else:
        group_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO groups(id,name,delete_policy,excludes,interval_min,start_delay_min,retry_min,"
            "backup_enabled,backup_dir,backup_keep,backup_interval_hour,backup_delay_min,"
            "enabled,next_run,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)",
            (group_id, name, delete_policy, excludes, interval, start_delay, retry, backup_enabled,
             backup_dir, backup_keep, backup_hour, backup_delay, next_at, common.now_iso()),
        )
    for position, (site_id, directory) in enumerate(cleaned):
        db.execute(
            "INSERT INTO group_members(id,group_id,site_id,dir,position) VALUES(?,?,?,?,?)",
            (str(uuid.uuid4()), group_id, site_id, directory, position),
        )
    db.commit()
    return {"ok": True, "id": group_id, "next_run": next_at}


def api_delete_group(db, req):
    group_id = req.get("id")
    if not isinstance(group_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", group_id):
        raise ValueError("同步组编号不正确")
    db.execute("DELETE FROM group_members WHERE group_id=?", (group_id,))
    db.execute("DELETE FROM group_baseline WHERE group_id=?", (group_id,))
    db.execute("DELETE FROM runs WHERE rule_id=?", ("group:" + group_id,))
    db.execute("DELETE FROM groups WHERE id=?", (group_id,))
    db.commit()
    return {"ok": True}


def api_run_group(db, req):
    group_id = req.get("id")
    if not isinstance(group_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", group_id):
        raise ValueError("同步组编号不正确")
    if not db.execute("SELECT 1 FROM groups WHERE id=?", (group_id,)).fetchone():
        raise ValueError("同步组不存在")
    db.execute("UPDATE groups SET next_run=? WHERE id=?", (common.now_iso(), group_id))
    db.commit()
    return {"ok": True}


def api_toggle_group(db, req):
    group_id = req.get("id")
    enabled = req.get("enabled")
    if not isinstance(group_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", group_id):
        raise ValueError("同步组编号不正确")
    if not isinstance(enabled, bool):
        raise ValueError("启用状态不正确")
    row = db.execute("SELECT start_delay_min FROM groups WHERE id=?", (group_id,)).fetchone()
    delay = row["start_delay_min"] if row else 0
    db.execute("UPDATE groups SET enabled=?,next_run=? WHERE id=?",
               (1 if enabled else 0, next_run_iso(delay) if enabled else "", group_id))
    db.commit()
    return {"ok": True}


def api_test_group(db, req):
    group_id = req.get("id")
    if not isinstance(group_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", group_id):
        raise ValueError("同步组编号不正确")
    try:
        return dict(engine.test_group(db, group_id), ok=True)
    except (remote.RemoteError, engine.GroupError) as exc:
        raise ValueError("预演失败：" + str(exc))


# --------------------------------------------------------------------------
# POST：压缩备份
# --------------------------------------------------------------------------
BACKUP_TABLES = {"rule": "rules", "group": "groups"}


def _backup_target(db, req):
    kind = req.get("kind") or "rule"
    table = BACKUP_TABLES.get(kind)
    if not table:
        raise ValueError("备份对象不正确")
    owner_id = req.get("id")
    if not isinstance(owner_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", owner_id):
        raise ValueError("编号不正确")
    row = db.execute("SELECT id,name,backup_enabled,backup_dir FROM %s WHERE id=?" % table,
                     (owner_id,)).fetchone()
    if not row:
        raise ValueError("任务不存在或已被删除")
    return table, owner_id, row


def api_run_backup(db, req):
    """手动立刻打包一次，不受备份间隔限制。

    注意：不能在 CGI 里直接打包——api.cgi 以套件账号运行，写不了
    /volume1/homes 这类只有 root 能写的目录（tar 会报 Permission denied）。
    所以这里只排一个「立刻 + 强制」的备份，由以 root 运行的调度进程在
    20 秒内真正执行；结果写回 backup_msg，界面刷新即可看到。
    """
    table, owner_id, row = _backup_target(db, req)
    if not row["backup_enabled"]:
        raise ValueError("这个任务还没有启用压缩备份")
    if not row["backup_dir"]:
        raise ValueError("这个任务还没有设置备份目录")
    db.execute("UPDATE %s SET backup_due_at=?,backup_force=1 WHERE id=?" % table,
               (common.now_iso(), owner_id))
    db.commit()
    return {"ok": True, "scheduled": True}


def api_list_backups(db, req):
    table, owner_id, row = _backup_target(db, req)
    items = engine.list_backups(db, table, owner_id)
    return {
        "ok": True,
        "backup_dir": row["backup_dir"],
        "keep": db.execute("SELECT backup_keep FROM %s WHERE id=?" % table, (owner_id,)).fetchone()[0],
        "backups": [dict(item, size_text=common.human_size(item["size"])) for item in items],
    }


# --------------------------------------------------------------------------
# POST：浏览目录（界面上的「选择目录」）
# --------------------------------------------------------------------------
def api_browse(db, req):
    site = engine.load_site(db, req.get("site_id"))
    path = common.clean_abs_path(req.get("path") or "/")
    if path is None:
        raise ValueError("目录必须是以 / 开头的绝对路径")
    if site["kind"] != "local" and not site["key_id"]:
        raise ValueError("这个站点还没有可用的密钥，请先回到站点卡片点「测试连接」")
    names = remote.list_dirs(site, path)
    truncated = len(names) > remote.MAX_DIR_ENTRIES
    if truncated:
        names = names[:remote.MAX_DIR_ENTRIES]
    return {
        "ok": True,
        "path": path,
        "parent": remote.parent_posix(path),
        "dirs": [{"name": name, "path": remote.join_posix(path, name)} for name in names],
        "truncated": truncated,
    }


# --------------------------------------------------------------------------
# POST：设置
# --------------------------------------------------------------------------
def api_save_settings(db, req):
    if "trash_days" in req:
        try:
            days = int(req["trash_days"])
        except (TypeError, ValueError):
            raise ValueError("回收站保留天数不正确")
        if not 0 <= days <= 3650:
            raise ValueError("回收站保留天数必须在 0 到 3650 之间")
        common.set_setting(db, "trash_days", days)
    if "conflict_copy" in req:
        value = str(req["conflict_copy"])
        if value not in ("0", "1"):
            raise ValueError("冲突处理设置不正确")
        common.set_setting(db, "conflict_copy", value)
    if "worker_paused" in req:
        value = str(req["worker_paused"])
        if value not in ("0", "1"):
            raise ValueError("暂停设置不正确")
        common.set_setting(db, "worker_paused", value)
    return {"ok": True}


def api_clear_trash(db, req):
    """清理所有同步目录下的 .filesync-trash 回收站。"""
    targets = set()
    for row in db.execute("SELECT site_a, dir_a, site_b, dir_b FROM rules"):
        targets.add((row["site_a"], row["dir_a"]))
        targets.add((row["site_b"], row["dir_b"]))
    for row in db.execute("SELECT site_id, dir FROM group_members"):
        targets.add((row["site_id"], row["dir"]))
    cleared = 0
    for site_id, directory in targets:
        if not site_id or not directory:
            continue
        try:
            site = engine.load_site(db, site_id)
        except engine.RuleError:
            continue
        try:
            cleared += remote.clear_trash(site, directory)
        except remote.RemoteError:
            continue
    return {"ok": True, "cleared": cleared}


# --------------------------------------------------------------------------
# 分发
# --------------------------------------------------------------------------
POST_HANDLERS = {
    "save_site": api_save_site,
    "delete_site": api_delete_site,
    "test_site": api_test_site,
    "deploy_key": api_deploy_key,
    "gen_key": api_gen_key,
    "delete_key": api_delete_key,
    "save_rule": api_save_rule,
    "delete_rule": api_delete_rule,
    "run_rule": api_run_rule,
    "toggle_rule": api_toggle_rule,
    "test_rule": api_test_rule,
    "save_group": api_save_group,
    "delete_group": api_delete_group,
    "run_group": api_run_group,
    "toggle_group": api_toggle_group,
    "test_group": api_test_group,
    "browse": api_browse,
    "logs": api_logs,
    "run_backup": api_run_backup,
    "list_backups": api_list_backups,
    "clear_trash": api_clear_trash,
    "save_settings": api_save_settings,
}


def render_page(owner):
    nonce = secrets.token_urlsafe(18)
    csrf = common.new_csrf(owner)
    from urllib.parse import parse_qs
    token = parse_qs(os.environ.get("QUERY_STRING", "")).get("SynoToken", [""])[0].strip()
    html = UI_PATH.read_text(encoding="utf-8")
    html = html.replace("__NONCE__", nonce)
    html = html.replace("__CSRF__", csrf)
    html = html.replace("__SYNO_TOKEN__", json.dumps(token) if token else "null")
    return html, nonce


def main():
    # index.cgi 的启动器会传 "index"；api.cgi 不传参数，默认即 API 模式
    mode = "index" if len(sys.argv) > 1 and sys.argv[1] == "index" else "api"
    owner = common.authenticate()

    if not owner:
        message = "无法验证 DSM 当前的登录会话，套件不需要单独登录。"
        if mode == "index":
            common.text_out(
                "<!doctype html><meta charset=utf-8><title>DSM 会话验证</title>"
                "<h3>" + message + "</h3><p>诊断：" + common.AUTH_DIAGNOSTIC + "</p>",
                "401 Unauthorized",
            )
        else:
            common.json_out({"ok": False, "error": message, "diagnostic": common.AUTH_DIAGNOSTIC,
                             "version": common.APP_VERSION}, "401 Unauthorized")
        return

    if not common.application_authorized(owner):
        if mode == "index":
            common.text_out("<!doctype html><meta charset=utf-8><title>没有权限</title>"
                            "<p>此套件只允许 DSM administrators 群组使用。</p>", "403 Forbidden")
        else:
            common.json_out({"ok": False, "error": "此套件只允许 DSM administrators 群组使用。"}, "403 Forbidden")
        return

    if mode == "index":
        html, nonce = render_page(owner)
        common.text_out(html, nonce=nonce)
        return

    db = common.connect_db()
    try:
        method = os.environ.get("REQUEST_METHOD", "GET").upper()
        if method == "GET":
            action = query_action() or "bootstrap"
            if action == "bootstrap":
                common.json_out(api_bootstrap(db))
            elif action == "logs":
                common.json_out(api_logs(db, {"id": _query_value("id")}))
            else:
                common.json_out({"ok": False, "error": "不支持的操作"}, "400 Bad Request")
            return

        # POST 一律要求 CSRF，防止跨站伪造请求
        token = os.environ.get("HTTP_X_CSRF_TOKEN", "").strip()
        if not common.valid_csrf(owner, token):
            common.json_out({"ok": False, "error": "请求校验失败，请刷新页面重试"}, "403 Forbidden")
            return
        origin = os.environ.get("HTTP_ORIGIN", "")
        if origin and not common.same_origin():
            common.json_out({"ok": False, "error": "请求来源不正确"}, "403 Forbidden")
            return

        req = read_json()
        action = req.get("action") or query_action()
        handler = POST_HANDLERS.get(action)
        if not handler:
            common.json_out({"ok": False, "error": "不支持的操作"}, "400 Bad Request")
            return
        try:
            result = handler(db, req)
            common.json_out(result)
        except (ValueError, engine.RuleError) as exc:
            common.json_out({"ok": False, "error": str(exc)}, "400 Bad Request")
        except remote.RemoteError as exc:
            common.json_out({"ok": False, "error": str(exc)}, "400 Bad Request")
    except ValueError as exc:
        common.json_out({"ok": False, "error": str(exc)}, "400 Bad Request")
    except Exception as exc:  # noqa: BLE001
        common.json_out({"ok": False, "error": "服务器内部错误：" + type(exc).__name__ + " " + str(exc)[:200]},
                        "500 Internal Server Error")
    finally:
        db.close()


def _query_value(name):
    from urllib.parse import parse_qs
    return parse_qs(os.environ.get("QUERY_STRING", "")).get(name, [""])[0]


if __name__ == "__main__":
    main()
