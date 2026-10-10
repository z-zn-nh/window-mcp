"""MCP 服务器：工具注册、策略闸门、鉴权与审批端点。

对应文档 §2 / §5 / §6。关键约束（全部来自 Hark 实测）：
* 每次调用都是全新会话，服务器必须无状态：stateless_http=True + json_response=True；
* 任务、审批单等状态按 job_id / approval_id 存在服务器端，不挂会话；
* pending_approval 必须用「成功结果」返回，不能用 isError；
* 单条命令按 ≤50 秒设计，超时转后台并保留结果。
"""

from __future__ import annotations

import base64
import io
import json
import os
import platform
import threading
import time
import urllib.parse
from collections import deque
from pathlib import Path

import psutil
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from . import agent_status as agent_status_mod
from . import desktop
from . import uia as uia_mod

from .approvals import (
    APPROVED,
    ERROR,
    EXECUTED,
    EXPIRED,
    PENDING,
    REJECTED,
    Approval,
    ApprovalStore,
)
from .audit import AuditLog
from .config import Config
from .jobs import JobManager, truncate_output
from .notifier import Notifier
from .policy import ToolLock, tool_granted
from .remote_approval import RemoteApprovalQueue, RuntimeSettings
from .security import (
    Decision,
    PathError,
    PathGuard,
    classify_command,
    looks_binary,
    token_matches,
)

INSTRUCTIONS = """\
这是运行在用户 Windows 电脑上的 MCP 服务器，只监听 127.0.0.1，通过隧道对外暴露。

使用约定：
1. 每次调用都是新会话，服务器不保存会话状态。长任务请用 job_id、审批请用 approval_id 跟踪。
2. run_command 只审「危险命令」（删除、改注册表/服务/防火墙/计划任务、提权、
   下载执行、安装、发布、结束进程、关机等）。普通读写、查询、构建类命令直接执行，
   不用等审批。命中危险清单时不会立即执行，而是返回
   {"status":"pending_approval","approval_id":"..."}。这是**成功结果**，不是失败：
   请稍后用 approval_status(approval_id) 轮询，不要当成错误重试。
3. 单次调用默认 60 秒超时，所以 run_command 的 timeout_s 上限是 50 秒；
   跑不完的命令会自动转后台并返回 job_id，用 job_status 取结果，结果不会丢。
4. 写操作（run_command / start_job / write_file / edit_file）请带上 request_id，
   服务器会在 10 分钟内对同一个 request_id 去重，避免超时重发导致重复执行。
5. screenshot 返回的是 base64 文本（第一行 JSON 元数据，第二行起 base64），
   因为客户端会丢弃 ImageContent。请解码成图片文件后再查看。
6. 可以直接操作这台电脑的桌面：screenshot 截屏、click 点击（用真实屏幕坐标）、
   type_text 输入文字（支持中文）、hotkey 按组合键、wake_screen 唤醒显示器。
   这些默认免审批。若返回 {"error":"session_locked"}，说明电脑已锁屏，
   任何 GUI 操作都不会生效，需要先让用户解锁。
"""


# ---------------------------------------------------------------------------
# 限速
# ---------------------------------------------------------------------------


class RateLimiter:
    def __init__(self, per_minute: int, high_per_hour: int) -> None:
        self.per_minute = per_minute
        self.high_per_hour = high_per_hour
        self._calls: deque[float] = deque()
        self._high: deque[float] = deque()
        self._lock = threading.Lock()

    def check(self, level: str) -> str | None:
        now = time.time()
        with self._lock:
            while self._calls and now - self._calls[0] > 60:
                self._calls.popleft()
            if len(self._calls) >= self.per_minute:
                return f"触发限速：每分钟最多 {self.per_minute} 次调用"
            self._calls.append(now)

            if level in ("H", "X"):
                while self._high and now - self._high[0] > 3600:
                    self._high.popleft()
                if len(self._high) >= self.high_per_hour:
                    return f"触发限速：高危操作每小时最多 {self.high_per_hour} 次"
                self._high.append(now)
        return None


# ---------------------------------------------------------------------------
# 幂等去重
# ---------------------------------------------------------------------------


class Dedupe:
    """按 request_id 去重：Hark 不自动重试，但超时后可能手动重发。"""

    def __init__(self, path: Path, ttl_s: int) -> None:
        self.path = Path(path)
        self.ttl_s = ttl_s
        self._lock = threading.Lock()
        self._items: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        now = time.time()
        self._items = {
            key: value for key, value in (data.get("items") or {}).items()
            if now - float(value.get("ts", 0)) <= self.ttl_s
        }

    def _save(self) -> None:
        with self._lock:
            payload = {"items": self._items}
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self.path)

    def get(self, request_id: str | None) -> dict | None:
        if not request_id:
            return None
        with self._lock:
            item = self._items.get(request_id)
        if item is None:
            return None
        if time.time() - float(item.get("ts", 0)) > self.ttl_s:
            return None
        return item.get("result")

    def put(self, request_id: str | None, result: dict) -> None:
        if not request_id:
            return
        with self._lock:
            self._items[request_id] = {"ts": time.time(), "result": result}
        self._save()


# ---------------------------------------------------------------------------
# 服务器
# ---------------------------------------------------------------------------


class Server:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.guard = PathGuard(cfg.read_roots, cfg.write_roots, cfg.denied_patterns)
        self.audit = AuditLog(cfg.log_path)
        self.jobs = JobManager(cfg)
        self.notifier = Notifier(cfg, self.audit)
        self.approvals = ApprovalStore(cfg.approval_file, cfg.approval_ttl_s)
        self.dedupe = Dedupe(cfg.dedupe_file, cfg.dedupe_ttl_s)
        self._exec_lock = threading.Lock()
        self._cpu_primed = False
        self._proc_primed = False
        # 远程审批（三档策略里的 ask 档）：阻塞式待审批队列 + 面板可改的运行时旋钮 +
        # 鼠标键盘工具的全局锁。三者都挂在 Server 上，MCP 侧与面板侧共用同一份。
        self.runtime = RuntimeSettings(
            cfg.panel_settings.settings_file,
            defaults={
                "approval_wait_s": cfg.panel_settings.approval_wait_s,
                "ntfy_server": cfg.panel_settings.ntfy_server,
                "ntfy_topic": cfg.panel_settings.ntfy_topic,
                "ntfy_token": cfg.panel_settings.ntfy_token,
            })
        self.remote = RemoteApprovalQueue(
            self.audit, wait_s=cfg.panel_settings.approval_wait_s,
            auto_minutes=cfg.panel_settings.auto_allow_minutes)
        self.tool_lock = ToolLock()
        self.rate = RateLimiter(cfg.rate_per_minute, cfg.rate_high_per_hour)
        # UIA 桥接层懒加载：不碰 UIA 工具就不起那条 STA 工作线程
        self._uia: uia_mod.UiaBridge | None = None
        self._uia_lock = threading.Lock()

        self.mcp = FastMCP(
            name="windows-pc",
            instructions=INSTRUCTIONS,
            stateless_http=True,
            json_response=True,
            streamable_http_path=cfg.path,
            # 经隧道/反代访问时 Host 头是公网域名，不列进来会一律 421
            transport_security=TransportSecuritySettings(
                enable_dns_rebinding_protection=True,
                allowed_hosts=list(cfg.allowed_hosts),
                allowed_origins=list(cfg.allowed_origins),
            ),
        )
        self._approved_handlers = {
            "run_command": self._do_run_command,
            "start_job": self._do_start_job,
            "write_file": self._do_write_file,
            "edit_file": self._do_edit_file,
            "screenshot": self._do_screenshot,
            "type_text": self._do_type_text,
            "click": self._do_click,
            "hotkey": self._do_hotkey,
            "wake_screen": self._do_wake_screen,
            "uia_click": self._do_uia_click,
            "uia_type": self._do_uia_type,
            "clipboard_set": self._do_clipboard_set,
        }
        self._register_tools()

    # ------------------------------------------------------------------ 注册

    def _register_tools(self) -> None:
        prefix = self.cfg.tool_prefix or ""
        _add = self.mcp.add_tool
        # 注册过的**内部**工具名。ASGI 闸门用它区分「真的有个 ask 档工具要审批」
        # 和「客户端把工具名拼错了」——后者交给 SDK 回它自己的错误，
        # 而不是挂起 120 秒等人去批一个根本不存在的工具。
        self.tool_names: set[str] = set()

        def add(fn, *, name, description, structured_output=False):
            """统一挂前缀。内部/审计里仍用不带前缀的原名，便于日志对齐。"""
            self.tool_names.add(name)
            _add(fn, name=f"{prefix}{name}", description=description,
                 structured_output=structured_output)

        add(self.system_info, name="system_info",
            description="系统版本、主机名、开机时长、CPU 型号与核数、内存总量。只读。",
            structured_output=False)
        add(self.system_stats, name="system_stats",
            description="CPU 占用（总/每核）、内存、各磁盘用量、网络收发累计。只读。",
            structured_output=False)
        add(self.list_processes, name="list_processes",
            description="按 CPU 或内存排序的进程列表。只读。",
            structured_output=False)
        add(self.list_windows, name="list_windows",
            description="当前可见窗口的标题、进程名、位置、是否前台。只读。",
            structured_output=False)
        add(self.list_dir, name="list_dir",
            description="列出目录内容（受路径白名单约束）。只读。",
            structured_output=False)
        add(self.read_file, name="read_file",
            description="读取文本文件（受路径白名单约束，默认上限 200 KB）。只读。",
            structured_output=False)
        add(self.screenshot, name="screenshot",
            description="截屏，返回 base64 JPEG 文本（第一行 JSON 元数据）。默认免审批。",
            structured_output=False)
        add(self.run_command, name="run_command",
            description="执行 PowerShell 或 WSL 命令。只有危险命令（删除/系统配置/提权/"
                        "下载执行/安装/发布等）需要审批，其余直接执行。",
            structured_output=False)
        add(self.start_job, name="start_job",
            description="启动长任务（构建、服务、部署），立即返回 job_id。",
            structured_output=False)
        add(self.job_status, name="job_status",
            description="查看任务状态与最近输出。只读。",
            structured_output=False)
        add(self.stop_job, name="stop_job",
            description="结束任务及其整个子进程树。",
            structured_output=False)
        add(self.write_file, name="write_file",
            description="写文件，只允许写工作目录内；覆盖前自动备份到 .mcp_backup/。",
            structured_output=False)
        add(self.edit_file, name="edit_file",
            description="精确替换文件内容，old 必须唯一匹配；改前自动备份。",
            structured_output=False)
        add(self.approval_status, name="approval_status",
            description="查询审批单状态；已批准的单子会在这里被执行并返回结果。只读。",
            structured_output=False)
        add(self.list_pending_approvals, name="list_pending_approvals",
            description="列出所有待审批的操作。只读。",
            structured_output=False)
        add(self.type_text, name="type_text",
            description="把文字输入到当前焦点窗口，支持中文等任意 Unicode。默认免审批。",
            structured_output=False)
        add(self.click, name="click",
            description="把鼠标移到屏幕坐标 (x,y) 并点击；clicks=0 只移动不点击。"
                        "坐标用 screenshot 返回的真实屏幕坐标。默认免审批。",
            structured_output=False)
        add(self.hotkey, name="hotkey",
            description='按组合键，用 + 连接，如 "ctrl+c"、"win+r"、"alt+f4"。默认免审批。',
            structured_output=False)
        add(self.wake_screen, name="wake_screen",
            description="唤醒显示器并保持常亮（屏幕熄灭后可先调它）。默认免审批。",
            structured_output=False)

        # ---- UIA 无障碍树（移植自 CursorTouch/Windows-MCP，见 vendor/NOTICE.md）----
        add(self.uia_snapshot, name="uia_snapshot",
            description="截取桌面无障碍树：列出可交互元素的 [标签] 名称、控件类型、"
                        "中心坐标、所属窗口。返回的 label 可直接喂给 uia_click / "
                        "uia_type，比按坐标点更稳。只读、免审批。",
            structured_output=False)
        add(self.uia_wait_for, name="uia_wait_for",
            description="轮询等待界面变化。condition 取 element_exists（按 name / "
                        "control_type 匹配控件）或 window（匹配当前窗口标题子串）；"
                        "超时返回 matched=false，不算错误。只读、免审批。",
            structured_output=False)
        add(self.uia_click, name="uia_click",
            description="按 uia_snapshot 给出的 label 点击控件（内部换算成屏幕坐标）。"
                        "clicks=2 为双击。默认免审批。",
            structured_output=False)
        add(self.uia_type, name="uia_type",
            description="按 label 定位输入框并输入文字；clear=true 先全选清空，"
                        "press_enter=true 输完回车。默认免审批。",
            structured_output=False)
        add(self.clipboard_get, name="clipboard_get",
            description="读取系统剪贴板文本。只读、免审批。",
            structured_output=False)
        add(self.clipboard_set, name="clipboard_set",
            description="把文本写入系统剪贴板（覆盖原有内容）。默认免审批。",
            structured_output=False)
        add(self.agent_status, name="agent_status",
            description="只读查看 PI-Desktop 与 DeepSeek Harness 的会话概况：各会话"
                        "最后一条用户消息、最后一条回复、时间、是否在运行。"
                        "内容已截断并脱敏，不含工具输出与凭据。免审批。",
            structured_output=False)

    # ------------------------------------------------------------------ 闸门

    def _classify(self, command: str, shell: str) -> Decision:
        """按配置的策略给命令分级（默认 danger-only：只审危险命令）。"""
        return classify_command(
            command, shell, self.guard,
            policy=self.cfg.command_policy,
            extra_danger=self.cfg.extra_danger_patterns,
            restrict_writes=self.cfg.restrict_writes_to_roots,
        )

    def _pre(self, tool: str, args: dict, level: str) -> dict | None:
        blocked = self.rate.check(level)
        if blocked:
            self.audit.call(tool, args, level, "rate_limited", 0, blocked)
            return {"error": "rate_limited", "message": blocked}
        return None

    def _run_tool(self, tool: str, args: dict, level: str, fn) -> dict:
        blocked = self._pre(tool, args, level)
        if blocked:
            return blocked
        start = time.perf_counter()
        try:
            result = fn()
        except desktop.SessionLocked as exc:
            self._audit(tool, args, level, "error", start, f"session_locked: {exc}")
            return {"error": "session_locked", "message": str(exc)}
        except desktop.DesktopError as exc:
            self._audit(tool, args, level, "error", start, f"bad_request: {exc}")
            return {"error": "bad_request", "message": str(exc)}
        except PathError as exc:
            self._audit(tool, args, level, "denied", start, str(exc))
            return {"error": "path_denied", "message": str(exc)}
        except Exception as exc:  # 工具内部错误不应该让整个调用崩掉
            self._audit(tool, args, level, "error", start, f"{type(exc).__name__}: {exc}")
            return {"error": "internal_error", "message": f"{type(exc).__name__}: {exc}"}
        self._audit(tool, args, level, "allowed", start, "ok")
        return result

    def _audit(self, tool: str, args: dict, level: str, decision: str,
               start: float, summary: str) -> None:
        self.audit.call(tool, args, level, decision,
                        int((time.perf_counter() - start) * 1000), summary)

    # ------------------------------------------------------------------ 审批

    def _pending(self, tool: str, args: dict, summary: str, reason: str) -> dict:
        existing = self.approvals.find_pending_by_request_id(args.get("request_id"))
        if existing is not None:
            payload = existing.public()
            payload["deduplicated"] = True
            return payload
        approval = self.approvals.create(tool, args, summary, level="H")
        self.audit.approval("created", approval.approval_id, tool, args)
        self.audit.call(tool, args, "H", "pending_approval", 0, reason)
        self.notifier.send_approval(approval)
        return approval.public()

    def _execute_approved(self, approval: Approval) -> dict:
        with self._exec_lock:
            current = self.approvals.get(approval.approval_id)
            if current is None:
                return {"error": "not_found", "message": "审批单不存在"}
            if current.status in (EXECUTED, ERROR):
                return {"status": current.status, "result": current.result}
            if current.status != APPROVED:
                return {"error": "not_approved", "status": current.status}

            handler = self._approved_handlers.get(current.tool)
            if handler is None:
                result = {"error": "unsupported_tool", "message": current.tool}
                self.approvals.mark_executed(current.approval_id, result, ok=False)
                return result

            try:
                result = handler(**current.args)
            except Exception as exc:
                result = {"error": "execution_failed", "message": f"{type(exc).__name__}: {exc}"}
                self.approvals.mark_executed(current.approval_id, result, ok=False)
                self.audit.approval("executed", current.approval_id, current.tool, current.args)
                return result

            self.approvals.mark_executed(current.approval_id, result, ok=True)
            self.audit.approval("executed", current.approval_id, current.tool, current.args)
            return result

    # ================================================================== 工具

    # ---- 只读监控 ----

    def system_info(self) -> dict:
        return self._run_tool("system_info", {}, "R", self._do_system_info)

    def _do_system_info(self) -> dict:
        boot = psutil.boot_time()
        mem = psutil.virtual_memory()
        return {
            "os": f"{platform.system()} {platform.release()}",
            "os_version": platform.version(),
            "hostname": platform.node(),
            "user": os.environ.get("USERNAME", ""),
            "boot_time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(boot)),
            "uptime_hours": round((time.time() - boot) / 3600, 2),
            "cpu_model": platform.processor(),
            "cores_logical": psutil.cpu_count(),
            "cores_physical": psutil.cpu_count(logical=False),
            "memory_total_bytes": mem.total,
            "python_version": platform.python_version(),
        }

    def system_stats(self) -> dict:
        return self._run_tool("system_stats", {}, "R", self._do_system_stats)

    def _do_system_stats(self) -> dict:
        # psutil.cpu_percent() 第一次调用返回 0.0，必须先给一个真实采样间隔
        if not self._cpu_primed:
            overall = psutil.cpu_percent(interval=0.2)
            per_core = psutil.cpu_percent(interval=0.0, percpu=True)
            self._cpu_primed = True
        else:
            overall = psutil.cpu_percent(interval=None)
            per_core = psutil.cpu_percent(interval=None, percpu=True)

        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()

        disks = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except (PermissionError, OSError):
                continue
            disks.append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "percent": usage.percent,
            })

        try:
            net = psutil.net_io_counters()
            network = {"bytes_sent": net.bytes_sent, "bytes_recv": net.bytes_recv,
                       "packets_sent": net.packets_sent, "packets_recv": net.packets_recv}
        except Exception:
            network = {}

        return {
            "cpu_percent": overall,
            "cpu_per_core_percent": per_core,
            "memory": {"total_bytes": mem.total, "used_bytes": mem.used,
                       "available_bytes": mem.available, "percent": mem.percent},
            "swap": {"total_bytes": swap.total, "used_bytes": swap.used, "percent": swap.percent},
            "disks": disks,
            "network": network,
        }

    def list_processes(self, sort_by: str = "cpu", limit: int = 20) -> dict:
        args = {"sort_by": sort_by, "limit": limit}
        return self._run_tool("list_processes", args, "R",
                              lambda: self._do_list_processes(sort_by, limit))

    def _do_list_processes(self, sort_by: str = "cpu", limit: int = 20) -> dict:
        limit = max(1, min(int(limit or 20), 200))
        procs = []
        for proc in psutil.process_iter(["pid", "name", "memory_info", "create_time"]):
            try:
                info = proc.info
                procs.append({
                    "pid": info["pid"],
                    "name": info["name"],
                    "memory_bytes": getattr(info.get("memory_info"), "rss", 0),
                    "create_time": info.get("create_time"),
                    "_proc": proc,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # 每进程 CPU% 同样需要两次采样
        for item in procs:
            try:
                item["_proc"].cpu_percent(None)
            except psutil.Error:
                item["cpu_percent"] = 0.0
        if not self._proc_primed:
            time.sleep(0.15)
            self._proc_primed = True
        for item in procs:
            try:
                item["cpu_percent"] = item["_proc"].cpu_percent(None)
            except psutil.Error:
                item["cpu_percent"] = 0.0

        key = "memory_bytes" if (sort_by or "").lower() == "memory" else "cpu_percent"
        procs.sort(key=lambda x: x.get(key) or 0, reverse=True)

        out = []
        for item in procs[:limit]:
            item.pop("_proc", None)
            created = item.get("create_time")
            item["create_time_iso"] = (
                time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(created)) if created else None
            )
            out.append(item)
        return {"count": len(procs), "returned": len(out), "processes": out}

    def list_windows(self) -> dict:
        return self._run_tool("list_windows", {}, "R", self._do_list_windows)

    def _do_list_windows(self) -> dict:
        try:
            import win32gui
            import win32process
        except ImportError as exc:
            raise RuntimeError(f"缺少 pywin32（win32gui）：{exc}") from exc

        foreground = win32gui.GetForegroundWindow()
        windows = []

        def callback(hwnd, _):
            if not win32gui.IsWindowVisible(hwnd):
                return
            title = win32gui.GetWindowText(hwnd)
            if not title:
                return
            try:
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                name = psutil.Process(pid).name()
            except Exception:
                pid, name = None, ""
            left, top, right, bottom = win32gui.GetWindowRect(hwnd)
            windows.append({
                "hwnd": hwnd,
                "title": title,
                "pid": pid,
                "process": name,
                "rect": {"left": left, "top": top, "width": right - left, "height": bottom - top},
                "foreground": hwnd == foreground,
            })

        win32gui.EnumWindows(callback, None)
        windows.sort(key=lambda w: (not w["foreground"], w["process"]))
        return {"count": len(windows), "windows": windows}

    # ---- 文件 ----

    def list_dir(self, path: str, limit: int = 500) -> dict:
        args = {"path": path, "limit": limit}
        return self._run_tool("list_dir", args, "R",
                              lambda: self._do_list_dir(path, limit))

    def _do_list_dir(self, path: str, limit: int = 500) -> dict:
        target = self.guard.check_read(path)
        if not target.is_dir():
            raise PathError(f"不是目录：{target}")
        limit = max(1, min(int(limit or 500), 2000))
        entries = []
        for child in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            if len(entries) >= limit:
                break
            try:
                stat = child.stat()
            except OSError:
                continue
            entries.append({
                "name": child.name,
                "is_dir": child.is_dir(),
                "size_bytes": stat.st_size,
                "modified": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(stat.st_mtime)),
            })
        return {"path": str(target), "count": len(entries), "entries": entries}

    def read_file(self, path: str, offset: int = 0, limit: int = 0) -> dict:
        args = {"path": path, "offset": offset, "limit": limit}
        return self._run_tool("read_file", args, "R",
                              lambda: self._do_read_file(path, offset, limit))

    def _do_read_file(self, path: str, offset: int = 0, limit: int = 0) -> dict:
        target = self.guard.check_read(path)
        if not target.is_file():
            raise PathError(f"不是文件：{target}")
        size = target.stat().st_size
        max_bytes = self.cfg.max_read_bytes
        offset = max(0, int(offset or 0))
        limit = int(limit or 0) or max_bytes
        limit = max(1, min(limit, max_bytes))

        with open(target, "rb") as fh:
            fh.seek(offset)
            data = fh.read(limit)
        truncated = offset + len(data) < size
        if looks_binary(data):
            return {"path": str(target), "binary": True, "size_bytes": size,
                    "message": "二进制文件，拒绝以文本返回"}
        return {
            "path": str(target),
            "size_bytes": size,
            "offset": offset,
            "returned_bytes": len(data),
            "truncated": truncated,
            "text": data.decode("utf-8", errors="replace"),
        }

    def screenshot(self, monitor: int = 1, max_width: int = 0) -> dict:
        args = {"monitor": monitor, "max_width": max_width, "request_id": None}
        level = (self.cfg.screenshot_level or "H").upper()
        if level == "R" or tool_granted("screenshot"):
            return self._run_tool("screenshot", args, "R",
                                  lambda: self._do_screenshot(monitor, max_width))
        if level == "X":
            self.audit.call("screenshot", args, "X", "denied", 0, "配置为禁止")
            return {"error": "denied_by_policy", "level": "X", "reason": "截屏已在配置中禁用"}
        return self._pending("screenshot", args, f"截屏（显示器 {monitor}）", "截屏需审批")

    def _do_screenshot(self, monitor: int = 1, max_width: int = 0,
                       request_id: str | None = None) -> dict:
        import mss
        from PIL import Image

        max_width = int(max_width or 0) or self.cfg.screenshot_max_width
        with mss.mss() as sct:
            monitors = sct.monitors
            index = int(monitor or 1)
            if index < 0 or index >= len(monitors):
                index = 1 if len(monitors) > 1 else 0
            region = monitors[index]
            shot = sct.grab(region)

        image = Image.frombytes("RGB", shot.size, shot.rgb)
        original_width, original_height = image.size
        if max_width and original_width > max_width:
            scale = max_width / original_width
            image = image.resize((max_width, max(1, int(original_height * scale))),
                                 Image.LANCZOS)
        returned_width, returned_height = image.size
        scale_ratio = returned_width / original_width

        buffer = io.BytesIO()
        image.save(buffer, format="JPEG", quality=self.cfg.screenshot_quality, optimize=True)
        raw = buffer.getvalue()
        encoded = base64.b64encode(raw).decode("ascii")

        meta = {
            "monitor": index,
            "left": region["left"],
            "top": region["top"],
            "width": original_width,
            "height": original_height,
            "returned_width": returned_width,
            "returned_height": returned_height,
            "scale": round(scale_ratio, 6),
            "format": "jpeg",
            "quality": self.cfg.screenshot_quality,
            "bytes": len(raw),
            # 把截图坐标换算回真实屏幕坐标
            "coord_map": "real_x = left + round(x / scale), real_y = top + round(y / scale)",
        }
        return {"meta": meta, "image_base64": encoded}

    # ---- GUI 操作（点击 / 输入 / 快捷键 / 唤醒屏幕）----

    def _gate(self, tool: str, args: dict, summary: str, fn,
              level_attr: str = "gui_level") -> dict:
        """GUI / UIA 工具的统一闸门。

        默认 "R"：免审批直接执行。配成 "H" 时每次操作都要审批；
        配成 "X" 时这些工具整体禁用。

        ``tool_granted`` 是远程审批那条路：ASGI 闸门已经让手机端点了「批准」，
        这里就不该再拦一次（否则同一次调用要人批两遍）。
        """
        level = (getattr(self.cfg, level_attr) or "R").upper()
        if level == "X":
            self.audit.call(tool, args, "X", "denied", 0, f"{tool} 已在配置中禁用")
            return {"error": "denied_by_policy", "level": "X",
                    "reason": f"{tool} 已在配置中禁用（{level_attr} = X）"}
        if level == "H" and not tool_granted(tool):
            return self._pending(tool, args, summary, f"{tool} 需审批")
        return self._run_tool(tool, args, "R", fn)

    def _gui(self, tool: str, args: dict, summary: str, fn) -> dict:
        """GUI 工具的统一闸门（受 gui_level 控制）。"""
        return self._gate(tool, args, summary, fn, "gui_level")

    def type_text(self, text: str, interval_ms: int = 0) -> dict:
        if not isinstance(text, str):
            return {"error": "bad_request", "message": "text 必须是字符串"}
        limit = max(1, int(self.cfg.gui_max_chars or 10000))
        if len(text) > limit:
            return {"error": "bad_request",
                    "message": f"text 过长（{len(text)} 字符），单次上限 {limit} 字符，"
                               "请分多次输入"}
        interval_ms = max(0, min(int(interval_ms or 0), 1000))
        # 逐字符发送要 sleep，Hark 单次调用 60 秒就断了，先自己拦掉
        if len(text) * interval_ms > 40000:
            return {"error": "bad_request",
                    "message": f"{len(text)} 字符 × {interval_ms} ms 会超出单次调用时限，"
                               "请调小 interval_ms 或分多次输入"}
        args = {"text": text, "interval_ms": interval_ms}
        return self._gui("type_text", args,
                         f"输入文字（{len(text)} 字符）：{text[:60]}",
                         lambda: desktop.type_text(text, interval_ms))

    def click(self, x: int, y: int, button: str = "left", clicks: int = 1,
              interval_ms: int = 0) -> dict:
        args = {"x": x, "y": y, "button": button, "clicks": clicks,
                "interval_ms": interval_ms}
        return self._gui("click", args,
                         f"点击 ({x}, {y}) {button} ×{clicks}",
                         lambda: desktop.click(x, y, button, clicks, interval_ms))

    def hotkey(self, keys: str, repeat: int = 1) -> dict:
        args = {"keys": keys, "repeat": repeat}
        return self._gui("hotkey", args,
                         f"按键 {keys} ×{repeat}",
                         lambda: desktop.hotkey(keys, repeat))

    def wake_screen(self) -> dict:
        return self._gui("wake_screen", {}, "唤醒显示器",
                         lambda: desktop.wake_screen())

    # 审批通过后由 _execute_approved 调用，参数名必须与上面 args 的键一致

    def _do_type_text(self, text: str, interval_ms: int = 0) -> dict:
        return desktop.type_text(text, interval_ms)

    def _do_click(self, x: int, y: int, button: str = "left", clicks: int = 1,
                  interval_ms: int = 0) -> dict:
        return desktop.click(x, y, button, clicks, interval_ms)

    def _do_hotkey(self, keys: str, repeat: int = 1) -> dict:
        return desktop.hotkey(keys, repeat)

    def _do_wake_screen(self) -> dict:
        return desktop.wake_screen()

    # ---- UIA 无障碍树（移植自 CursorTouch/Windows-MCP，见 vendor/NOTICE.md）----

    @property
    def uia(self) -> uia_mod.UiaBridge:
        """懒加载。UiaBridge 会起一条 STA 工作线程，不用 UIA 就不起。"""
        if self._uia is None:
            with self._uia_lock:
                if self._uia is None:
                    self._uia = uia_mod.UiaBridge(
                        max_windows=int(self.cfg.uia_max_windows or 6),
                        call_timeout_s=float(self.cfg.uia_timeout_s or 40),
                    )
        return self._uia

    def _uia_label_desc(self, label: int) -> str:
        try:
            return self.uia.describe_label(int(label))
        except Exception:
            return f"label {label}"

    def uia_snapshot(self, use_dom: bool = False, max_elements: int = 0,
                     include_tree: bool = True,
                     exclude: list[str] | None = None) -> dict:
        limit = int(max_elements or 0) or int(self.cfg.uia_max_elements or 150)
        limit = max(1, min(limit, 600))
        args = {"use_dom": bool(use_dom), "max_elements": limit,
                "include_tree": bool(include_tree),
                "exclude": list(exclude or [])}
        return self._run_tool(
            "uia_snapshot", args, "R",
            lambda: self.uia.snapshot(use_dom=bool(use_dom), max_elements=limit,
                                      include_tree=bool(include_tree),
                                      exclude=exclude))

    def uia_wait_for(self, condition: str = "element_exists", name: str = "",
                     control_type: str = "", timeout_s: int = 10,
                     interval_ms: int = 600, use_dom: bool = False) -> dict:
        timeout_s = max(1, min(int(timeout_s or 10), 50))  # Hark 单次调用 60 秒
        interval_ms = max(100, min(int(interval_ms or 600), 5000))
        args = {"condition": condition, "name": name,
                "control_type": control_type, "timeout_s": timeout_s,
                "interval_ms": interval_ms, "use_dom": bool(use_dom)}
        return self._run_tool(
            "uia_wait_for", args, "R",
            lambda: self.uia.wait_for(
                condition=condition, name=name, control_type=control_type,
                timeout_s=float(timeout_s), interval_s=interval_ms / 1000.0,
                use_dom=bool(use_dom),
                max_elements=int(self.cfg.uia_max_elements or 150)))

    def uia_click(self, label: int, button: str = "left", clicks: int = 1,
                  interval_ms: int = 0) -> dict:
        args = {"label": int(label), "button": button, "clicks": int(clicks),
                "interval_ms": int(interval_ms)}
        return self._gate(
            "uia_click", args,
            f"按标签点击 {self._uia_label_desc(label)}",
            lambda: self._do_uia_click(**args), "uia_level")

    def _do_uia_click(self, label: int, button: str = "left", clicks: int = 1,
                      interval_ms: int = 0) -> dict:
        item = self.uia.resolve_label(int(label))
        result = desktop.click(int(item["x"]), int(item["y"]), button,
                               int(clicks), int(interval_ms))
        return {**result, "label": int(label),
                "target": {"name": item.get("name", ""),
                           "control_type": item.get("control_type", ""),
                           "window": item.get("window", ""),
                           "x": item["x"], "y": item["y"]}}

    def uia_type(self, text: str, label: int, interval_ms: int = 0,
                 clear: bool = False, press_enter: bool = False) -> dict:
        if not isinstance(text, str):
            return {"error": "bad_request", "message": "text 必须是字符串"}
        limit = max(1, int(self.cfg.gui_max_chars or 10000))
        if len(text) > limit:
            return {"error": "bad_request",
                    "message": f"text 过长（{len(text)} 字符），单次上限 {limit} 字符"}
        args = {"text": text, "label": int(label), "interval_ms": int(interval_ms),
                "clear": bool(clear), "press_enter": bool(press_enter)}
        return self._gate(
            "uia_type", args,
            f"按标签输入到 {self._uia_label_desc(label)}（{len(text)} 字符）",
            lambda: self._do_uia_type(**args), "uia_level")

    def _do_uia_type(self, text: str, label: int, interval_ms: int = 0,
                     clear: bool = False, press_enter: bool = False) -> dict:
        item = self.uia.resolve_label(int(label))
        x, y = int(item["x"]), int(item["y"])
        desktop.click(x, y, "left", 1, 0)   # 先把焦点给到目标控件
        if clear:
            desktop.hotkey("ctrl+a", 1)
            desktop.hotkey("delete", 1)
        result = desktop.type_text(text, int(interval_ms))
        if press_enter:
            desktop.hotkey("enter", 1)
        return {**result, "label": int(label), "typed": len(text),
                "clear": bool(clear), "press_enter": bool(press_enter)}

    def clipboard_get(self, max_chars: int = 20000) -> dict:
        n = max(1, min(int(max_chars or 20000), 100000))
        return self._run_tool("clipboard_get", {"max_chars": n}, "R",
                              lambda: uia_mod.clipboard_get(n))

    def clipboard_set(self, text: str) -> dict:
        if not isinstance(text, str):
            return {"error": "bad_request", "message": "text 必须是字符串"}
        args = {"text": text}
        return self._gate("clipboard_set", args,
                          f"写入剪贴板（{len(text)} 字符）",
                          lambda: self._do_clipboard_set(**args), "uia_level")

    def _do_clipboard_set(self, text: str) -> dict:
        return uia_mod.clipboard_set(text)

    # ---- 两个 agent 的会话概况（只读）----

    def agent_status(self, pi_limit: int = 3, dsh_limit: int = 3,
                     max_chars: int = 240) -> dict:
        args = {"pi_limit": int(pi_limit or 3), "dsh_limit": int(dsh_limit or 3),
                "max_chars": int(max_chars or 240)}
        return self._run_tool("agent_status", args, "R",
                              lambda: agent_status_mod.collect(**args))

    # ---- 命令执行 ----

    def run_command(self, command: str, shell: str = "powershell", cwd: str = "",
                    timeout_s: int = 0, request_id: str = "") -> dict:
        args = {"command": command, "shell": shell, "cwd": cwd or None,
                "timeout_s": int(timeout_s or self.cfg.default_timeout_s),
                "request_id": request_id or None}

        cached = self.dedupe.get(args["request_id"])
        if cached is not None:
            return {**cached, "deduplicated": True}

        # 先分级再限速：普通命令不该占用「高危操作」的每小时额度
        decision = self._classify(command, shell)
        if decision.level == "X":
            self.audit.call("run_command", args, "X", "denied", 0, decision.reason)
            return {"error": "denied_by_policy", "level": "X", "reason": decision.reason}

        blocked = self._pre("run_command", args, decision.level)
        if blocked:
            return blocked

        if decision.level == "H" and not tool_granted("run_command"):
            return self._pending("run_command", args,
                                 f"{shell}: {command[:300]}", decision.reason)

        try:
            if args["cwd"]:
                self.guard.check_cwd(args["cwd"])
            start = time.perf_counter()
            result = self._do_run_command(**args)
            self._audit("run_command", args, decision.level, "allowed", start, decision.reason)
            self.dedupe.put(args["request_id"], result)
            return result
        except PathError as exc:
            self.audit.call("run_command", args, "R", "denied", 0, str(exc))
            return {"error": "path_denied", "message": str(exc)}
        except Exception as exc:
            self.audit.call("run_command", args, "R", "error", 0, f"{type(exc).__name__}: {exc}")
            return {"error": "internal_error", "message": f"{type(exc).__name__}: {exc}"}

    def _do_run_command(self, command: str, shell: str = "powershell", cwd: str | None = None,
                        timeout_s: int = 30, request_id: str | None = None) -> dict:
        timeout = max(1, min(int(timeout_s or self.cfg.default_timeout_s), self.cfg.max_timeout_s))
        result = self.jobs.run_and_wait(command, shell, cwd, timeout, name=command[:60])
        output = result.get("output") or ""
        clipped, was_truncated = truncate_output(output, self.cfg.max_output_bytes)
        result["output"] = clipped
        if was_truncated:
            result["output_truncated"] = True
            result["note"] = "输出已截断，完整内容见 log_file"
        return result

    def start_job(self, command: str, shell: str = "powershell", cwd: str = "",
                  name: str = "", request_id: str = "") -> dict:
        args = {"command": command, "shell": shell, "cwd": cwd or None,
                "name": name, "request_id": request_id or None}

        cached = self.dedupe.get(args["request_id"])
        if cached is not None:
            return {**cached, "deduplicated": True}

        # 先分级再限速：普通任务不该占用「高危操作」的每小时额度
        decision = self._classify(command, shell)
        if decision.level == "X":
            self.audit.call("start_job", args, "X", "denied", 0, decision.reason)
            return {"error": "denied_by_policy", "level": "X", "reason": decision.reason}

        blocked = self._pre("start_job", args, decision.level)
        if blocked:
            return blocked

        if decision.level == "H" and not tool_granted("start_job"):
            return self._pending("start_job", args,
                                 f"后台任务 {name or ''} {shell}: {command[:240]}", decision.reason)

        try:
            if args["cwd"]:
                self.guard.check_cwd(args["cwd"])
            start = time.perf_counter()
            result = self._do_start_job(**args)
            self._audit("start_job", args, decision.level, "allowed", start, decision.reason)
            self.dedupe.put(args["request_id"], result)
            return result
        except PathError as exc:
            self.audit.call("start_job", args, "R", "denied", 0, str(exc))
            return {"error": "path_denied", "message": str(exc)}

    def _do_start_job(self, command: str, shell: str = "powershell", cwd: str | None = None,
                      name: str = "", request_id: str | None = None) -> dict:
        job = self.jobs.start(command, shell=shell, cwd=cwd, name=name,
                              request_id=request_id)
        return {
            "status": "started",
            "job_id": job.job_id,
            "name": job.name,
            "log_file": str(job.log_path),
            "next": "call job_status",
        }

    def job_status(self, job_id: str, tail_lines: int = 100) -> dict:
        args = {"job_id": job_id, "tail_lines": tail_lines}
        return self._run_tool("job_status", args, "R",
                              lambda: self.jobs.status(job_id, tail_lines))

    def stop_job(self, job_id: str) -> dict:
        args = {"job_id": job_id}
        return self._run_tool("stop_job", args, "W", lambda: self.jobs.stop(job_id))

    # ---- 文件写入 ----

    def write_file(self, path: str, content: str, mode: str = "overwrite",
                   request_id: str = "") -> dict:
        args = {"path": path, "content": content, "mode": mode,
                "request_id": request_id or None}
        cached = self.dedupe.get(args["request_id"])
        if cached is not None:
            return {**cached, "deduplicated": True}
        try:
            start = time.perf_counter()
            result = self._do_write_file(**args)
            self._audit("write_file", args, "W", "allowed", start, result.get("path", ""))
            self.dedupe.put(args["request_id"], result)
            return result
        except PathError as exc:
            self.audit.call("write_file", args, "X", "denied", 0, str(exc))
            return {"error": "path_denied", "message": str(exc)}

    def _do_write_file(self, path: str, content: str, mode: str = "overwrite",
                       request_id: str | None = None) -> dict:
        target = self.guard.check_write(path)
        if target.is_dir():
            raise PathError(f"目标是目录：{target}")
        if mode not in ("overwrite", "append"):
            raise PathError("mode 只能是 overwrite 或 append")
        target.parent.mkdir(parents=True, exist_ok=True)

        backup = None
        if target.exists():
            backup = self._backup(target)

        with open(target, "a" if mode == "append" else "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
        return {
            "path": str(target),
            "mode": mode,
            "written_bytes": len(content.encode("utf-8")),
            "backup": str(backup) if backup else None,
            "size_bytes": target.stat().st_size,
        }

    def edit_file(self, path: str, old: str, new: str, request_id: str = "") -> dict:
        args = {"path": path, "old": old, "new": new, "request_id": request_id or None}
        cached = self.dedupe.get(args["request_id"])
        if cached is not None:
            return {**cached, "deduplicated": True}
        try:
            start = time.perf_counter()
            result = self._do_edit_file(**args)
            self._audit("edit_file", args, "W", "allowed", start, result.get("path", ""))
            self.dedupe.put(args["request_id"], result)
            return result
        except PathError as exc:
            self.audit.call("edit_file", args, "X", "denied", 0, str(exc))
            return {"error": "path_denied", "message": str(exc)}

    def _do_edit_file(self, path: str, old: str, new: str,
                      request_id: str | None = None) -> dict:
        target = self.guard.check_write(path)
        if not target.is_file():
            raise PathError(f"文件不存在：{target}")
        text = target.read_text(encoding="utf-8", errors="replace")
        occurrences = text.count(old)
        if occurrences == 0:
            raise PathError("old 在文件中不存在，未做任何修改")
        if occurrences > 1:
            raise PathError(f"old 匹配到 {occurrences} 处，不唯一，请提供更长的上下文")

        backup = self._backup(target)
        updated = text.replace(old, new, 1)
        target.write_text(updated, encoding="utf-8", newline="")
        return {
            "path": str(target),
            "replaced": 1,
            "backup": str(backup),
            "size_bytes": target.stat().st_size,
        }

    def _backup(self, target: Path) -> Path:
        backup_dir = target.parent / ".mcp_backup"
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        backup = backup_dir / f"{stamp}-{target.name}"
        counter = 1
        while backup.exists():
            backup = backup_dir / f"{stamp}-{counter}-{target.name}"
            counter += 1
        backup.write_bytes(target.read_bytes())
        return backup

    # ---- 审批查询 ----

    def approval_status(self, approval_id: str) -> dict:
        args = {"approval_id": approval_id}
        approval = self.approvals.get(approval_id)
        if approval is None:
            self.audit.call("approval_status", args, "R", "not_found", 0, approval_id)
            return {"error": "not_found", "message": f"审批单不存在：{approval_id}"}

        if approval.status == PENDING:
            return approval.public()
        if approval.status in (REJECTED, EXPIRED):
            self.audit.call("approval_status", args, "R", approval.status, 0, approval.summary)
            return {"status": approval.status, "approval_id": approval_id,
                    "tool": approval.tool, "summary": approval.summary,
                    "decided_by": approval.decided_by}
        if approval.status == APPROVED:
            result = self._execute_approved(approval)
            return {"status": "executed", "approval_id": approval_id,
                    "tool": approval.tool, "result": result}
        return {"status": approval.status, "approval_id": approval_id,
                "tool": approval.tool, "result": approval.result}

    def list_pending_approvals(self) -> dict:
        return self._run_tool("list_pending_approvals", {}, "R",
                              self._do_list_pending)

    def _do_list_pending(self) -> dict:
        items = self.approvals.list_pending()
        return {"count": len(items), "pending": [a.as_dict() for a in items]}
