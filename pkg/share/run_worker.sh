#!/bin/sh
# Copyright (c) 2026 AWA <https://www.akkdiy.cn>. All rights reserved.
# 以 root 运行调度进程。
#
# 为什么需要它
# ------------
# DSM 7 的套件服务以套件账号（filesync）启动，而 /volume1/homes、其他用户的
# 共享文件夹、加密目录这些位置只有 root 能读。同步与压缩备份都要读写这些
# 目录，所以调度进程必须以 root 运行。
#
# scripts/postinst 会给套件账号写一条只允许执行本脚本的免密 sudo 规则，
# 因此这里不接受任何参数，python 路径也在脚本内自行探测，避免被拿去做别的事。
set -eu

APP="/var/packages/FileSync/target/share/worker.py"
[ -f "$APP" ] || { echo "worker.py is missing" >&2; exit 1; }

PYTHON=""
for candidate in \
    /var/packages/Python3*/target/usr/local/bin/python3.[0-9]* \
    /var/packages/Python3*/target/usr/bin/python3.[0-9]* \
    /var/packages/Python3*/target/usr/local/bin/python3 \
    /var/packages/Python3*/target/usr/bin/python3 \
    /usr/local/bin/python3 \
    /usr/bin/python3; do
    [ -x "$candidate" ] || continue
    PYTHON="$candidate"
    break
done
[ -n "$PYTHON" ] || { echo "Python 3 is required" >&2; exit 1; }

exec "$PYTHON" "$APP"
