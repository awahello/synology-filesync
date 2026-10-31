"""打包 FileSync 为 DSM 7 套件（.spk）。

结构：
    FileSync.spk
    ├── INFO / PACKAGE_ICON*.PNG / LICENSE / DISCLAIMER.txt
    ├── conf/privilege, conf/PKG_DEPS
    ├── scripts/start-stop-status, scripts/postinst
    └── package.tgz (xz)
        ├── share/*.py, share/ui_page.html   后端与页面模板
        └── ui/index.cgi, api.cgi, FileSync.js, config, images/
"""

import io
import lzma
import tarfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PKG = ROOT / "pkg"
VERSION = "0.3.10-0001"
OUT = ROOT.parent / ("多站文件同步-" + VERSION.split("-")[0] + ".spk")

# package.tgz 内的条目（顺序即打包顺序）
PAYLOAD = [
    ("share", "dir"),
    ("share/common.py", "f"),
    ("share/remote.py", "f"),
    ("share/engine.py", "f"),
    ("share/archive.py", "f"),
    ("share/localroot.py", "f"),
    ("share/cgi_app.py", "f"),
    ("share/worker.py", "f"),
    ("share/ui_page.html", "f"),
    ("ui", "dir"),
    ("ui/images", "dir"),
    ("ui/images/icon_16.png", "f"),
    ("ui/images/icon_24.png", "f"),
    ("ui/images/icon_32.png", "f"),
    ("ui/images/icon_48.png", "f"),
    ("ui/images/icon_64.png", "f"),
    ("ui/images/icon_72.png", "f"),
    ("ui/images/icon_256.png", "f"),
    ("ui/config", "f"),
    ("ui/api.cgi", "f"),
    ("ui/FileSync.js", "f"),
    ("ui/index.cgi", "f"),
    ("var", "dir"),
]

EXECUTABLES = {"ui/api.cgi", "ui/index.cgi"}


def add_entry(tf, name, src, mode, isdir=False):
    info = tarfile.TarInfo(name)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = int(time.time())
    if isdir:
        info.type = tarfile.DIRTYPE
        tf.addfile(info)
    else:
        data = Path(src).read_bytes()
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))


def build_payload():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, kind in PAYLOAD:
            src = PKG / name
            if kind == "dir":
                add_entry(tf, name, None, 0o755, True)
            else:
                if not src.exists():
                    raise SystemExit("缺少文件：" + str(src))
                add_entry(tf, name, src, 0o755 if name in EXECUTABLES else 0o644)
    compressed = lzma.compress(buf.getvalue(), format=lzma.FORMAT_XZ, preset=6)
    (ROOT / "package.tgz").write_bytes(compressed)
    return len(compressed), len(buf.getvalue())


def build_info():
    extract_kb = int(sum(p.stat().st_size for p in PKG.rglob("*") if p.is_file()) / 1024) + 1
    text = (
        'package="FileSync"\n'
        'version="' + VERSION + '"\n'
        'maintainer="AWA (www.akkdiy.cn)"\n'
        'maintainer_url="https://www.akkdiy.cn"\n'
        'arch="x86_64"\n'
        'dsmuidir="ui"\n'
        'dsmappname="SYNO.SDS.App.FileSync.Instance"\n'
        'startable="yes"\n'
        'os_min_ver="7.0-40000"\n'
        'description="多站点文件互相同步：在本机与 OpenWrt 路由、Linux 服务器之间按最新修改时间双向同步指定目录，'
        '冲突以较新文件为准，删除可跟随并进入回收站。通过 SSH 免密连接，支持 rsync 增量传输与 tar 降级，'
        '可配置双向互备或单向备份。"\n'
        'displayname="多站文件同步"\n'
        'extractsize="' + str(extract_kb) + '"\n'
        'toolkit_version="90074"\n'
        'create_time="' + time.strftime("%Y%m%d-%H:%M:%S") + '"\n'
    )
    (ROOT / "INFO").write_text(text, encoding="utf-8", newline="\n")
    return extract_kb


def build_spk():
    outer = [
        ("DISCLAIMER.txt", "f", 0o644),
        ("INFO", "f", 0o644),
        ("LICENSE", "f", 0o644),
        ("PACKAGE_ICON.PNG", "f", 0o644),
        ("PACKAGE_ICON_256.PNG", "f", 0o644),
        ("conf", "d", 0o755),
        ("conf/privilege", "f", 0o644),
        ("conf/PKG_DEPS", "f", 0o644),
        ("package.tgz", "f", 0o644),
        ("scripts", "d", 0o755),
        ("scripts/postinst", "f", 0o755),
        ("scripts/start-stop-status", "f", 0o755),
    ]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name, kind, mode in outer:
            add_entry(tf, name, None if kind == "d" else ROOT / name, mode, kind == "d")
    OUT.write_bytes(buf.getvalue())
    return OUT


if __name__ == "__main__":
    size, raw = build_payload()
    extract_kb = build_info()
    out = build_spk()
    print("package.tgz  %d bytes (raw %d)" % (size, raw))
    print("extractsize %d KB" % extract_kb)
    print("spk         %s  %d bytes" % (out, out.stat().st_size))
