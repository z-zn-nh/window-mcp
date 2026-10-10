"""通用看门狗：把子进程跑起来，挂了就带退避重启。

为什么不用 Windows 服务
----------------------
我们的 MCP 服务器要截屏、要 SendInput 往桌面发键鼠事件，这些**必须在交互式会话
（用户登录的那个 session）里**才有意义。Windows 服务跑在 session 0，没有桌面，
所有 GUI 工具都会失效。所以走「登录时触发的计划任务 + 当前用户身份」。

两种日志（为什么不是一份）
------------------------
* `--log`（子进程日志）：子进程的 stdout/stderr，追加写。
* `--watchdog-log`（看门狗日志，默认 `<子进程日志同目录>/supervise-<name>.log`）：
  看门狗自己的时间线——启动、护栏命中、子进程退出码、退避重启。
  单独一份是**必须的**：如果这个文件被别人以独占写方式占着（实测：老的手工
  `cmd.exe ... > logs\named-tunnel.log` 重定向就是这种），看门狗会连自己的重启
  记录都写不进去。看门狗自己的日志只能由它自己写。
两份都**追加**写、**按大小轮转**（20 MB，保留 3 份），启动时绝不删除。

三条硬要求
----------
1. **日志不在启动时删除**：一律追加写入；超过上限按大小**重命名轮转**（不是删）。
2. **单实例**：三重护栏，任一命中就退出、不启动子进程 ——
     a. 锁文件（记看门狗自身 PID；PID 已消失视为陈旧锁，可接管）
     b. `--port`：该端口已在监听
     c. `--match`：已有进程的命令行包含该串
   这条专门用来满足「接管时不要产生两个进程同时连」。
3. **退避重启**：2,4,8,16,32,60 秒封顶；子进程连续存活够 `--healthy-s` 秒后重置退避。

用法
----
启动（后台，无控制台窗口）：

    E:\\Python\\pythonw.exe supervise.py --name v2-server --port 8770 \\
        --log logs\\server.log --cwd . -- E:\\Python\\python.exe -u -m mcp_server

    E:\\Python\\pythonw.exe supervise.py --name named-tunnel \\
        --match tunnel\\config.yml --log logs\\named-tunnel.log --cwd . \\
        -- cloudflared.exe tunnel --config ... run window-mcp

查询 / 停止：

    python supervise.py --name v2-server --port 8770 --log logs\\server.log --status
    python supervise.py --name v2-server --port 8770 --log logs\\server.log --stop
    python supervise.py --name v2-server --port 8770 --log logs\\server.log --check-only

日常别手敲这些，用同目录的 `supervise_server.cmd` / `supervise_tunnel.cmd` /
`autostart.cmd`（install|status|stop|uninstall）。
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
BACKOFF = [2, 4, 8, 16, 32, 60]
MAX_LOG_BYTES = 20 * 1024 * 1024   # 单个日志 20 MB
KEEP_ROTATIONS = 3
IS_WINDOWS = os.name == "nt"
CREATE_NEW_PROCESS_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


# --------------------------------------------------------------------- 基础工具

def ensure_streams() -> None:
    """pythonw.exe 下 sys.stdout / sys.stderr 是 None，先补上，免得写日志时炸。"""
    for name in ("stdout", "stderr"):
        if getattr(sys, name, None) is None:
            try:
                setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))
            except OSError:
                pass


def log_path_of(raw: str) -> Path:
    p = Path(raw)
    return p if p.is_absolute() else (HERE / p)


def rotated(log_path: Path, index: int) -> Path:
    return log_path.parent / f"{log_path.name}.{index}"


def rotate_if_needed(log_path: Path) -> bool:
    """按大小轮转：x.log -> x.log.1 -> x.log.2 -> x.log.3（最老的才丢）。"""
    try:
        if not log_path.exists() or log_path.stat().st_size < MAX_LOG_BYTES:
            return False
    except OSError:
        return False
    for i in range(KEEP_ROTATIONS, 0, -1):
        src = log_path if i == 1 else rotated(log_path, i - 1)
        dst = rotated(log_path, i)
        try:
            if src.exists():
                if dst.exists():
                    dst.unlink()
                src.rename(dst)
        except OSError:
            pass
    return True


def open_append(log_path: Path):
    """一律 "ab"（追加 + 原子定位到末尾），绝不截断。"""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    return open(log_path, "ab", buffering=0)


def note(watchdog_log: Path, message: str) -> None:
    """看门狗自己的事件。只写它自己独占的那份日志（外加 stderr，pythonw 下是空的）。"""
    line = f"[supervise {time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n"
    try:
        with open_append(watchdog_log) as fh:
            fh.write(line.encode("utf-8", "replace"))
    except OSError as exc:
        try:
            sys.stderr.write(f"（看门狗日志也写不进去: {exc}）\n")
        except Exception:
            pass
    try:
        sys.stderr.write(line)
        sys.stderr.flush()
    except Exception:
        pass


# ------------------------------------------------------------------ 进程 / 端口

def _psutil():
    try:
        import psutil
    except Exception:
        return None
    return psutil


def pid_alive(pid: int) -> bool:
    """进程还在不在。

    注意：**绝不能用 os.kill(pid, 0)** —— 在 Windows 上 os.kill 除了
    CTRL_C_EVENT / CTRL_BREAK_EVENT 之外一律走 TerminateProcess，
    os.kill(pid, 0) 会真的把那个进程杀掉。
    """
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    ps = _psutil()
    if ps is not None:
        try:
            return bool(ps.pid_exists(pid))
        except Exception:
            pass
    if IS_WINDOWS:
        try:
            import ctypes
            from ctypes import wintypes

            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.OpenProcess.restype = wintypes.HANDLE
            k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            handle = k32.OpenProcess(0x1000, False, int(pid))  # QUERY_LIMITED_INFORMATION
            if not handle:
                return False
            try:
                code = wintypes.DWORD()
                if k32.GetExitCodeProcess(handle, ctypes.byref(code)):
                    return code.value == 259  # STILL_ACTIVE
                return True
            finally:
                k32.CloseHandle(handle)
        except Exception:
            pass
    return True   # 查不出来就当它还活着：宁可不启动，也不重复启动


def port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.6)
        return s.connect_ex(("127.0.0.1", int(port))) == 0


def pids_on_port(port: int) -> list[int]:
    ps = _psutil()
    if ps is None:
        return []
    found: list[int] = []
    try:
        for conn in ps.net_connections("tcp"):
            try:
                if (conn.status == ps.CONN_LISTEN and conn.laddr
                        and int(conn.laddr.port) == int(port) and conn.pid):
                    found.append(int(conn.pid))
            except Exception:
                continue
    except Exception:
        return []
    return sorted(set(found))


def snapshot_processes() -> tuple[list[tuple[int, str]], bool]:
    """[(pid, 命令行)]。第二个值 False = 两条路都没查成（护栏此时必须保守）。"""
    ps = _psutil()
    if ps is not None:
        rows: list[tuple[int, str]] = []
        try:
            for proc in ps.process_iter(["pid", "cmdline"]):
                try:
                    rows.append((int(proc.info["pid"]),
                                 " ".join(proc.info.get("cmdline") or [])))
                except Exception:
                    continue
            return rows, True
        except Exception:
            pass
    # 退路：PowerShell CIM（只有 psutil 不可用时才走到这里）
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Get-CimInstance Win32_Process | "
             "Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress"],
            capture_output=True, text=True, timeout=90,
            creationflags=CREATE_NO_WINDOW,
        )
        data = json.loads(proc.stdout) if (proc.stdout or "").strip() else []
        if isinstance(data, dict):
            data = [data]
        rows = [(int(r.get("ProcessId") or 0), r.get("CommandLine") or "") for r in data]
        return [r for r in rows if r[0] and r[1]], True
    except Exception:
        return [], False


def matching_processes(needle: str) -> tuple[list[tuple[int, str]], bool]:
    """命令行里包含 needle 的进程（排除看门狗自己和它的父进程 / 脚本）。"""
    rows, ok = snapshot_processes()
    if not ok:
        return [], False
    me = os.getpid()
    parent = os.getppid()
    hits: list[tuple[int, str]] = []
    for pid, cmd in rows:
        if pid in (me, parent):
            continue
        if "supervise" in cmd.lower():
            continue      # 别把看门狗自己的脚本/进程算进去
        if needle in cmd:
            hits.append((pid, cmd))
    return hits, True


# ---------------------------------------------------------------------- 锁/状态

def read_lock(lock_path: Path) -> int:
    try:
        return int((lock_path.read_text(encoding="utf-8").strip() or "0"))
    except (OSError, ValueError):
        return 0


def acquire_lock(lock_path: Path) -> tuple[bool, int]:
    """拿锁。(True, 0) = 拿到（含接管陈旧锁）；(False, holder) = 别人在跑。"""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    old = read_lock(lock_path)
    if old and old != os.getpid() and pid_alive(old):
        return False, old
    lock_path.write_text(str(os.getpid()), encoding="utf-8")
    return True, 0


def release_lock(lock_path: Path) -> None:
    try:
        if lock_path.exists() and read_lock(lock_path) == os.getpid():
            lock_path.unlink()
    except OSError:
        pass


def read_child_pid(child_state: Path) -> int:
    try:
        return int((child_state.read_text(encoding="utf-8").strip() or "0"))
    except (OSError, ValueError):
        return 0


def write_child_pid(child_state: Path, pid: int | None) -> None:
    try:
        if pid is None:
            if child_state.exists():
                child_state.unlink()
        else:
            child_state.parent.mkdir(parents=True, exist_ok=True)
            child_state.write_text(str(pid), encoding="utf-8")
    except OSError:
        pass


def guards_tripped(args) -> str | None:
    """返回命中原因；None = 可以启动。"""
    got, holder = acquire_lock(args.lock)
    if not got:
        return f"锁文件被活着的看门狗占着（pid={holder}）"
    reason: str | None = None
    if args.port and port_in_use(args.port):
        reason = f"端口 {args.port} 已在监听"
    if reason is None and args.match:
        hits, ok = matching_processes(args.match)
        if not ok:
            reason = ("查不到进程列表（psutil 与 PowerShell CIM 都失败），"
                      "为不产生重复进程而放弃启动")
        elif hits:
            reason = (f"已有 {len(hits)} 个进程命令行包含 {args.match!r}"
                      f"（pid={hits[0][0]}）")
    if reason:
        release_lock(args.lock)
    return reason


# -------------------------------------------------------------------- 子进程执行

def open_child_log(log_path: Path, wlog: Path):
    """打开子进程日志。打不开（被别人独占）时**绝不能崩**：退回 devnull 并留痕。

    实测过：手工 `cmd.exe ... > logs\\named-tunnel.log` 会以不允许写入共享的方式
    占住该文件，此时 open(..., "ab") 直接 PermissionError。
    """
    try:
        return open_append(log_path), log_path
    except OSError as exc:
        note(wlog, f"子进程日志 {log_path} 打不开（{exc}）→ 子进程输出改送 devnull，"
                   f"服务照常启动")
        return open(os.devnull, "wb", buffering=0), Path(os.devnull)


def run_child(args) -> int:
    """跑一次子进程，返回退出码。"""
    if rotate_if_needed(args.log_path):
        note(args.watchdog_log,
             f"子进程日志超过 {MAX_LOG_BYTES // (1024 * 1024)} MB，已按大小轮转"
             f"（保留 {KEEP_ROTATIONS} 份，最老的才丢）")
    note(args.watchdog_log, "启动子进程: " + " ".join(args.command))
    flags = CREATE_NEW_PROCESS_GROUP | (CREATE_NO_WINDOW if IS_WINDOWS else 0)
    fh, real_log = open_child_log(args.log_path, args.watchdog_log)
    try:
        fh.write(f"\n===== 子进程启动 {time.strftime('%Y-%m-%d %H:%M:%S')} =====\n".encode())
        fh.flush()
        proc = subprocess.Popen(
            args.command, cwd=str(args.cwd or HERE),
            stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            creationflags=flags,
        )
        write_child_pid(args.child_state, proc.pid)
        note(args.watchdog_log, f"子进程 pid={proc.pid}，输出 → {real_log}")
        try:
            return proc.wait()
        except KeyboardInterrupt:
            note(args.watchdog_log, "收到中断，正在结束子进程…")
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            raise
        finally:
            write_child_pid(args.child_state, None)
    finally:
        try:
            fh.close()
        except OSError:
            pass


# ---------------------------------------------------------------- status / stop

def taskkill(pid: int, tree: bool = False) -> bool:
    cmd = ["taskkill", "/F", "/PID", str(pid)]
    if tree:
        cmd.insert(2, "/T")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30,
                              creationflags=CREATE_NO_WINDOW)
        return proc.returncode == 0
    except Exception:
        return False


def _size(p: Path) -> str:
    try:
        return f"{p.stat().st_size} 字节"
    except OSError:
        return "（无）"


def report_status(args) -> int:
    print(f"[{args.name}]")
    print(f"  子进程日志: {args.log_path}  {_size(args.log_path)}")
    print(f"  看门狗日志: {args.watchdog_log}  {_size(args.watchdog_log)}")
    holder = read_lock(args.lock)
    if holder:
        print(f"  看门狗    : pid={holder} "
              f"{'在跑' if pid_alive(holder) else '已消失（陈旧锁，下次启动会接管）'}")
    else:
        print("  看门狗    : 没在跑（无锁文件）")
    child = read_child_pid(args.child_state)
    if child:
        print(f"  子进程    : pid={child} "
              f"{'在跑' if pid_alive(child) else '已消失（陈旧记录）'}")
    else:
        print("  子进程    : 没有记录（看门狗没在跑或刚重启）")
    if args.port:
        pids = pids_on_port(args.port)
        print(f"  端口 {args.port} : " + (f"被 pid={pids} 监听" if pids else "空闲"))
    if args.match:
        hits, ok = matching_processes(args.match)
        if not ok:
            print("  进程匹配  : 查不到（psutil 与 PowerShell CIM 都失败）")
        else:
            print(f"  进程匹配  : {args.match!r} → "
                  + (f"{len(hits)} 个 pid={[h[0] for h in hits]}" if hits else "无"))
    return 0


def do_stop(args) -> int:
    lines: list[str] = []
    holder = read_lock(args.lock)
    if holder and holder != os.getpid() and pid_alive(holder):
        ok = taskkill(holder, tree=True)
        lines.append(f"看门狗 pid={holder} " + ("已结束（含子进程）" if ok else "结束失败"))
    elif holder:
        lines.append(f"锁文件里的 pid={holder} 已不存在（陈旧锁，清掉）")
    try:
        args.lock.unlink(missing_ok=True)
    except OSError:
        pass

    time.sleep(0.5)   # 给 taskkill /T 一点时间
    if args.port:
        for pid in pids_on_port(args.port):
            if pid == os.getpid():
                continue
            ok = taskkill(pid)
            lines.append(f"端口 {args.port} 占用者 pid={pid} " + ("已结束" if ok else "结束失败"))
    if args.match:
        hits, ok = matching_processes(args.match)
        if not ok:
            lines.append("查不到进程列表，--match 兜底没做")
        else:
            for pid, _cmd in hits:
                if pid == os.getpid():
                    continue
                killed = taskkill(pid)
                lines.append(f"命令行含 {args.match!r} 的 pid={pid} "
                             + ("已结束" if killed else "结束失败"))
    write_child_pid(args.child_state, None)
    for line in (lines or ["没有在跑的东西"]):
        print("  - " + line)
    return 0


# ------------------------------------------------------------------------- 主流程

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", required=True, help="看门狗名字（锁文件/状态文件用它命名）")
    ap.add_argument("--log", required=True, help="子进程的 stdout/stderr（追加写，超 20MB 轮转）")
    ap.add_argument("--watchdog-log", default="",
                    help="看门狗自己的事件日志（默认 <子进程日志同目录>/supervise-<name>.log）")
    ap.add_argument("--cwd", default="", help="子进程工作目录（默认本目录）")
    ap.add_argument("--port", type=int, default=0, help="护栏：该端口在监听就不启动")
    ap.add_argument("--match", default="", help="护栏：已有进程命令行含此串就不启动")
    ap.add_argument("--healthy-s", type=int, default=300,
                    help="子进程连续存活多久算健康（重置退避）")
    ap.add_argument("--check-only", action="store_true",
                    help="只跑护栏检查并打印结论，不启动任何东西")
    ap.add_argument("--status", action="store_true", help="只读地报告当前状态")
    ap.add_argument("--stop", action="store_true", help="停掉看门狗和它的子进程")
    ap.add_argument("command", nargs=argparse.REMAINDER,
                    help="-- 之后是要监督的命令")
    return ap


def main() -> int:
    ensure_streams()
    args = build_parser().parse_args()
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    args.log_path = log_path_of(args.log)
    args.watchdog_log = (log_path_of(args.watchdog_log) if args.watchdog_log
                         else args.log_path.parent / f"supervise-{args.name}.log")
    args.lock = HERE / "state" / f"supervise-{args.name}.lock"
    args.child_state = HERE / "state" / f"supervise-{args.name}.child"

    if args.stop:
        return do_stop(args)
    if args.status:
        return report_status(args)

    reason = guards_tripped(args)
    if reason:
        if args.check_only:
            print(f"[{args.name}] 护栏命中：{reason}")
            return 0
        note(args.watchdog_log, f"不启动：{reason}（已有实例在跑，避免重复）")
        return 0

    if args.check_only:
        release_lock(args.lock)
        print(f"[{args.name}] 护栏通过：当前没有实例在跑，可以启动")
        return 0

    if not args.command:
        note(args.watchdog_log, "没有给要监督的命令（-- 之后）")
        release_lock(args.lock)
        return 2

    note(args.watchdog_log,
         f"看门狗启动 pid={os.getpid()}，锁={args.lock}，子进程日志={args.log_path}")

    def _bye(_signum, _frame):
        raise KeyboardInterrupt

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _bye)
        except (ValueError, OSError):
            pass

    failures = 0
    try:
        while True:
            started = time.time()
            try:
                code = run_child(args)
            except KeyboardInterrupt:
                note(args.watchdog_log, "看门狗退出（收到中断）")
                return 0
            uptime = time.time() - started
            if uptime >= args.healthy_s:
                failures = 0          # 活够久了，退避重新从最小开始
            failures += 1
            delay = BACKOFF[min(failures - 1, len(BACKOFF) - 1)]
            note(args.watchdog_log,
                 f"子进程退出 code={code} 存活={uptime:.0f}s → {delay}s 后重启"
                 f"（第 {failures} 次连续失败）")
            try:
                time.sleep(delay)
            except KeyboardInterrupt:
                note(args.watchdog_log, "看门狗退出（收到中断）")
                return 0
    finally:
        write_child_pid(args.child_state, None)
        release_lock(args.lock)


if __name__ == "__main__":
    raise SystemExit(main())
