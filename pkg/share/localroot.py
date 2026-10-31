#!/usr/bin/python3
# Copyright (c) 2026 AWA <https://www.akkdiy.cn>. All rights reserved.
"""本机特权目录列举：CGI 读不到的目录，交给以 root 运行的调度进程代读。

为什么需要这一层
----------------
DSM 7 不允许未签名的第三方套件以 root 运行 CGI，所以 api.cgi 是以套件账号
filesync 跑的。而 /volume1/homes、别人的共享文件夹这类目录在 DSM 上是
`root:root 711`——能进、不能列。结果是同步本身没问题（调度进程是 root），
但网页上的「选择目录」和「预演」看不见里面有什么。

于是调度进程（root）在 PKG_VAR 下开一个 Unix socket，CGI 连上去只说一句话：
「列出这个目录的直接子目录」。只读目录名，不读文件内容、不写、不删——即使
被滥用，能拿到的也只有目录名。

socket 权限 0666，但位于 0700 的 PKG_VAR 里，只有套件账号和 root 能连上。
"""

import json
import os
import socket

import common

SOCK_NAME = "browse.sock"
MAX_REQUEST = 2048
MAX_ENTRIES = 2000
CLIENT_TIMEOUT = 6.0


class LocalRootError(RuntimeError):
    pass


def socket_path():
    return str(common.PKG_VAR / SOCK_NAME)


def af_unix():
    """本地 socket 地址族；Windows 的 Python 常常没有 AF_UNIX。"""
    return getattr(socket, "AF_UNIX", None)


def _sort_names(names):
    return sorted(names, key=lambda s: (s.lower(), s))


def list_subdirs(path):
    """列出直接子目录。可能抛 OSError（无权限、不存在等）。"""
    names = []
    with os.scandir(path) as entries:
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=True):
                    names.append(entry.name)
            except OSError:
                continue
    return _sort_names(names)[:MAX_ENTRIES]


# --------------------------------------------------------------------------
# 服务端（跑在调度进程里）
# --------------------------------------------------------------------------
def start_server():
    """建立监听 socket；失败返回 None（例如平台不支持 AF_UNIX）。

    这里故意保持阻塞模式：目录代读由后台线程 serve_socket 独占服务，阻塞
    accept 在空闲时让线程挂起（不空转、不占 CPU），来连接时再唤醒。
    """
    family = af_unix()
    if family is None:
        return None
    path = socket_path()
    try:
        common.ensure_private_dir()
        if os.path.exists(path):
            os.unlink(path)
        server = socket.socket(family, socket.SOCK_STREAM)
        server.bind(path)
        # 目录本身是 0700，socket 再放开读写，只有套件账号和 root 连得进来
        os.chmod(path, 0o666)
        server.listen(8)
        return server
    except OSError:
        return None


def current_uid():
    try:
        return os.geteuid()
    except AttributeError:  # pragma: no cover - 仅 Windows 调试
        return -1


def respond(request):
    """把一条请求变成响应字典。单独拆出来便于测试。"""
    uid = current_uid()
    path = request.get("path") if isinstance(request, dict) else None
    # 只接受绝对路径：相对路径在不同进程的工作目录下含义不同，没有意义
    if (not isinstance(path, str) or not path or len(path) > 1024
            or any(ord(c) < 32 for c in path) or not os.path.isabs(path)):
        return {"ok": False, "error": "路径不正确", "uid": uid}
    # 错误信息里不带路径：调用方会把路径和原因拼成一句完整的话
    try:
        return {"ok": True, "dirs": list_subdirs(path), "uid": uid}
    except FileNotFoundError:
        return {"ok": False, "error": "目录不存在", "uid": uid}
    except NotADirectoryError:
        return {"ok": False, "error": "这不是一个目录", "uid": uid}
    except PermissionError:
        return {"ok": False, "error": "权限不足", "uid": uid}
    except OSError as exc:
        return {"ok": False, "error": "无法读取目录：%s" % exc, "uid": uid}


def handle_one(server):
    """处理一个请求（非阻塞 accept 失败时直接返回）。"""
    try:
        conn, _ = server.accept()
    except OSError:
        return
    try:
        conn.settimeout(3)
        try:
            raw = conn.recv(MAX_REQUEST)
            request = json.loads(raw.decode("utf-8", "replace") or "{}")
        except (OSError, ValueError):
            request = {}
        payload = respond(request)
        try:
            conn.sendall(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        except OSError:
            pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def stop_server(server):
    if server is None:
        return
    try:
        server.close()
    except OSError:
        pass
    try:
        os.unlink(socket_path())
    except OSError:
        pass


# --------------------------------------------------------------------------
# 客户端（跑在 CGI 里）
# --------------------------------------------------------------------------
def list_dirs_via_worker(path, timeout=CLIENT_TIMEOUT):
    """让调度进程代读目录，返回子目录名列表；失败抛 LocalRootError。"""
    family = af_unix()
    if family is None:
        raise LocalRootError("当前系统不支持本地 socket")
    try:
        client = socket.socket(family, socket.SOCK_STREAM)
        client.settimeout(timeout)
    except OSError as exc:
        raise LocalRootError("无法创建本地 socket：%s" % exc)

    try:
        try:
            client.connect(socket_path())
        except FileNotFoundError:
            raise LocalRootError("调度进程未运行，无法代读目录")
        except OSError:
            raise LocalRootError("连接调度进程失败，请确认套件已启动")
        try:
            client.sendall(json.dumps({"path": path}, ensure_ascii=False).encode("utf-8"))
            raw = b""
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                raw += chunk
        except socket.timeout:
            raise LocalRootError("调度进程忙（可能正在同步），请稍后再试")
        except OSError as exc:
            raise LocalRootError("与调度进程通信失败：%s" % exc)
    finally:
        try:
            client.close()
        except OSError:
            pass

    try:
        payload = json.loads(raw.decode("utf-8", "replace") or "{}")
    except ValueError:
        raise LocalRootError("调度进程返回内容不正确")
    if not payload.get("ok"):
        reason = payload.get("error") or "代读目录失败"
        uid = payload.get("uid")
        if reason == "权限不足":
            if isinstance(uid, int) and uid != 0:
                reason = ("调度进程未以 root 运行（当前 uid %d）。"
                          "请重装套件，或 SSH 登录后执行："
                          "sed -i 's/\"run-as\": \"package\"/\"run-as\": \"root\"/' "
                          "/var/packages/FileSync/conf/privilege && synopkg restart FileSync" % uid)
            else:
                reason = "连 root 都读不到，可能是加密共享文件夹未解锁"
        raise LocalRootError(reason)
    dirs = payload.get("dirs")
    if not isinstance(dirs, list):
        raise LocalRootError("调度进程返回内容不正确")
    return [str(name) for name in dirs if isinstance(name, str)]
