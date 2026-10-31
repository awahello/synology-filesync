#!/bin/sh
# Copyright (c) 2026 AWA <https://www.akkdiy.cn>. All rights reserved.
# 停止以 root 运行的调度进程。
#
# 为什么需要它：调度进程是 root，套件账号 kill 不动它，所以 DSM 停止套件时
# 由这条脚本（postinst 配的免密 sudo 规则）代劳。不接受任何参数。
set -u

PIDFILE="/var/packages/FileSync/var/worker.pid"
APP="/var/packages/FileSync/target/share/worker.py"

[ -f "$PIDFILE" ] || exit 0
pid="$(cat "$PIDFILE" 2>/dev/null || true)"
case "$pid" in
    ''|*[!0-9]*) exit 0 ;;
esac
# 确认这个 PID 确实是我们的 worker，避免 PID 复用误杀别的进程
[ -r "/proc/$pid/cmdline" ] || exit 0
tr '\000' ' ' < "/proc/$pid/cmdline" | grep -F "$APP" >/dev/null 2>&1 || exit 0

kill "$pid" 2>/dev/null || true
n=0
while [ "$n" -lt 20 ]; do
    [ -d "/proc/$pid" ] || exit 0
    sleep 1
    n=$((n + 1))
done
kill -9 "$pid" 2>/dev/null || true
exit 0
