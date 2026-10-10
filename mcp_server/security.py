"""安全层：路径校验、命令分级、敏感信息遮蔽。

这一层是文档 §6.1「审批由 MCP 服务器强制执行」的落点——Hark 读到的网页、
日志、文件里可能藏着恶意指令，所以判定必须在这里做，不能依赖 Hark 自觉。

命令分级有两种策略（config 里的 command_policy）：

* ``danger-only``（默认）：只有命中「危险命令清单」才走审批，其余直接执行。
  这是用户明确要的模式——审批只在真正危险时出现，日常操作不打扰。
* ``whitelist``（旧行为）：除白名单前缀外一律审批。极其安全但极其啰嗦。

两种模式下，命令都会先按 ``;`` ``&&`` ``||`` ``|`` 换行 拆成独立命令段，
逐段判定后取最严重的那一段。这样 ``dir | findstr x`` 是普通命令，
而 ``dir; Remove-Item x`` 仍然会被拦下——旧实现是把整条命令判成危险，
把无害的管道也一起误伤了。
"""

from __future__ import annotations

import fnmatch
import hmac
import os
import re
import shlex
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

# --------------------------------------------------------------------------
# 敏感信息遮蔽（审计日志用）
# --------------------------------------------------------------------------

_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-+/=]{8,}")
_KV_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key)\b"
    r"\s*[:=]\s*(\"[^\"]*\"|'[^']*'|\S+)"
)
_LONG_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")


def redact(text: str) -> str:
    """遮蔽命令行里可能出现的 token、密码、密钥。"""
    if not text:
        return text
    out = _BEARER_RE.sub(r"\1<redacted>", text)
    out = _KV_RE.sub(lambda m: f"{m.group(1)}=<redacted>", out)
    out = _LONG_B64_RE.sub("<redacted>", out)
    return out


def token_matches(presented: str, candidates: list[str]) -> bool:
    """恒定时间比较；遍历全部候选不提前返回，避免时序泄露。"""
    if not presented or not candidates:
        return False
    ok = False
    for candidate in candidates:
        ok = _compare(presented, candidate) or ok
    return ok


def _compare(presented: str, candidate: str) -> bool:
    """单个候选的恒定时间比较；非 ASCII 等畸形输入按「不匹配」处理。

    hmac.compare_digest 对含非 ASCII 的 str 会抛 TypeError。头里的 token 由客户端决定，
    所以畸形输入必须落成 401，而不是变成 500（500 既像服务故障，又会跳过后续候选的比较）。
    """
    if not candidate:
        return False
    try:
        return hmac.compare_digest(presented, candidate)
    except TypeError:
        return False


# 本次请求用的是哪个 token（名字，不是值）。只服务审计归属：
#   * 由 ASGI 外壳在鉴权通过后写入；
#   * 工具调用链与它在同一个任务上下文里，所以 ContextVar 能一路带下去；
#   * 后台线程（如任务执行器）拿不到，读出来是空串，审计里记成 "-"。
_current_token_name: ContextVar[str] = ContextVar("dsh_mcp_token_name", default="")


def set_token_name(name: str | None) -> None:
    _current_token_name.set(str(name or ""))


def current_token_name() -> str:
    return _current_token_name.get()

# 本次请求的来源 IP。只服务审计与面板展示（面板要显示「最近调用来自哪个 IP」），
# 不参与任何授权判断：经 Cloudflare 隧道过来时它是边缘节点的地址，
# 真正可信的客户端身份是 Cloudflare Access 的 JWT（见 access.py）。
_current_client_ip: ContextVar[str] = ContextVar("dsh_mcp_client_ip", default="")


def set_client_ip(ip: str | None) -> None:
    _current_client_ip.set(str(ip or ""))


def current_client_ip() -> str:
    return _current_client_ip.get()


def match_token_name(presented: str, entries: list[tuple[str, str]]) -> str | None:
    """恒定时间比对，命中则返回该 token 的**名字**，否则 None。

    与 token_matches 一样遍历全部候选、不提前返回：命中位置本身也会影响耗时，
    而这里返回的名字还会进审计日志，不能让它泄漏「第几个候选命中了」。
    """
    if not presented or not entries:
        return None
    hit: str | None = None
    for name, candidate in entries:
        if _compare(presented, candidate):
            hit = name
    return hit


# --------------------------------------------------------------------------
# 路径校验
# --------------------------------------------------------------------------


class PathError(Exception):
    """路径不合法或落在禁止范围内。"""


@dataclass
class PathGuard:
    read_roots: list[str]
    write_roots: list[str]
    denied_patterns: list[str]

    # -- 归一化与格式检查 --
    def resolve(self, raw: str) -> Path:
        if raw is None or not str(raw).strip():
            raise PathError("路径为空")
        if "\x00" in raw:
            raise PathError("路径含空字符")

        text = str(raw).strip()
        if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
            text = text[1:-1]

        if text.startswith("\\\\") or text.startswith("//"):
            raise PathError("不允许 UNC 路径（\\\\server\\share）")
        if text.startswith("\\\\.\\") or text.startswith("//./"):
            raise PathError("不允许设备路径")

        # 备用数据流：盘符之后不应再出现冒号（C:\a.txt:hidden）
        if re.match(r"^[A-Za-z]:", text):
            if ":" in text[2:]:
                raise PathError("不允许备用数据流（ADS）写法")
        elif ":" in text:
            raise PathError("路径含非法冒号")

        if not os.path.isabs(text):
            raise PathError("必须是绝对路径")

        # realpath 会解析符号链接与目录 junction
        return Path(os.path.realpath(text))

    # -- 包含关系与黑名单 --
    @staticmethod
    def _within(path: Path, roots: list[str]) -> bool:
        target = os.path.normcase(str(path))
        for root in roots:
            root_n = os.path.normcase(str(root))
            if target == root_n or target.startswith(root_n.rstrip("\\/") + os.sep):
                return True
        return False

    def _denied_hit(self, path: Path) -> str | None:
        normalized = str(path).replace("\\", "/").lower()
        for pattern in self.denied_patterns:
            if fnmatch.fnmatch(normalized, pattern.lower()):
                return pattern
        return None

    def _check(self, path: Path, roots: list[str], action: str) -> Path:
        hit = self._denied_hit(path)
        if hit:
            raise PathError(f"命中禁止路径规则（{hit}），不可{action}")
        if not self._within(path, roots):
            raise PathError(f"路径不在允许的{action}根目录内：{path}")
        return path

    def check_read(self, raw: str) -> Path:
        return self._check(self.resolve(raw), self.read_roots, "读取")

    def check_write(self, raw: str) -> Path:
        return self._check(self.resolve(raw), self.write_roots, "写入")

    def check_cwd(self, raw: str) -> Path:
        """工作目录：可读即可（命令本身另有分级）。"""
        path = self._check(self.resolve(raw), self.read_roots, "访问")
        if not path.is_dir():
            raise PathError(f"工作目录不存在或不是目录：{path}")
        return path


# --------------------------------------------------------------------------
# 命令分级
# --------------------------------------------------------------------------

POLICY_DANGER_ONLY = "danger-only"
POLICY_WHITELIST = "whitelist"

# 严重程度排序，用于多段命令取最严重的一段
_SEVERITY = {"R": 0, "W": 1, "H": 2, "X": 3}

# 直接拒绝（X）：不可审批。命中即服务器拒绝，没有商量余地。
X_FIRST_TOKENS = {
    "format",
    "format.com",
    "diskpart",
    "bcdedit",
    "runas",
}

X_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bcipher\s+/w\b", re.I),
    re.compile(r"\bSet-MpPreference\b[^\n;|]*-Disable", re.I),
    re.compile(r"\bSet-NetFirewallProfile\b[^\n;|]*-Enabled\s+(False|\$false|0)", re.I),
    re.compile(r"-Verb\s+RunAs\b", re.I),
    re.compile(r"\bDisable-WindowsOptionalFeature\b", re.I),
]

# ---------------------------------------------------------------------------
# 危险命令清单（H 档）：命中即走审批
#
# 判断标准是「会不可逆地破坏数据、改变系统状态、或把控制权交出去」。
# 普通读写、查询、构建、跑脚本都不在内——那些直接放行，否则又变成什么都审。
# ---------------------------------------------------------------------------
DANGER_PATTERNS: list[tuple[re.Pattern, str]] = [
    # --- 破坏性文件操作 ---
    (re.compile(
        r"\b(Remove-Item|Remove-ItemProperty|Clear-Content|del|erase|rmdir|rd|rm"
        r"|shred|sdelete)\b", re.I), "删除/清空类"),
    (re.compile(
        r"\b(Format-Volume|Clear-Disk|Initialize-Disk|New-Partition|Remove-Partition"
        r"|Resize-Partition|mkfs|fdisk|parted|dd)\b", re.I), "磁盘分区类"),
    (re.compile(r"\b(vssadmin|wbadmin|bcdedit|bootrec|cipher)\b", re.I), "系统恢复/引导类"),

    # --- 系统配置 ---
    (re.compile(r"\b(reg|reg\.exe|regedit|regini)\b", re.I), "注册表类"),
    (re.compile(
        r"\b(sc|sc\.exe|Set-Service|New-Service|Remove-Service|Stop-Service"
        r"|Start-Service|Restart-Service)\b", re.I), "服务类"),
    (re.compile(
        r"\b(netsh|New-NetFirewallRule|Set-NetFirewallProfile|Remove-NetFirewallRule"
        r"|Set-NetIPAddress|New-NetRoute|Set-DnsClientServerAddress)\b", re.I), "网络/防火墙类"),
    (re.compile(
        r"\b(schtasks|Register-ScheduledTask|Unregister-ScheduledTask"
        r"|Set-ScheduledTask)\b", re.I), "计划任务类"),
    (re.compile(r"\b(setx|powercfg|bcdboot|Set-ExecutionPolicy)\b", re.I), "持久化/策略类"),

    # 系统时间/时区：改时间会悄悄破坏 TLS 证书校验、许可证、定时任务与日志时序，
    # 而且事后很难发现（本机就发生过一次 +41 天的「时间穿越」）。
    # 只拦「改」的操作：tzutil /g 是读时区、w32tm /query 是读状态，都不该被误伤。
    # 没配审批推送通道时 H 档等于永不执行，误伤的代价是直接打断正常工作。
    (re.compile(
        r"\b(Set-Date|SetSystemTime|Set-TimeZone|timedate\.cpl)\b"
        r"|\btzutil\s+/s\b"
        r"|\bw32tm\s+/(resync|config|register|unregister)\b",
        re.I), "系统时间/时区类"),

    # --- 权限与账户 ---
    (re.compile(r"\b(icacls|cacls|takeown|Set-Acl)\b", re.I), "权限/属主类"),
    (re.compile(r"\bnet\s+(user|localgroup|share|accounts)\b", re.I), "账户/共享类"),
    (re.compile(
        r"\b(New-LocalUser|Remove-LocalUser|Add-LocalGroupMember"
        r"|Remove-LocalGroupMember|Set-LocalUser|Enable-LocalUser)\b", re.I), "账户类"),

    # --- 提权与动态执行 ---
    (re.compile(
        r"\b(Start-Process|Invoke-Command|Invoke-Expression|Invoke-WmiMethod"
        r"|New-PSSession|Enter-PSSession|winrs|psexec|mshta)\b", re.I), "提权/远程执行类"),
    (re.compile(r"\b(iex|sudo|doas|pkexec)\b", re.I), "提权/动态执行类"),
    (re.compile(r"-EncodedCommand\b", re.I), "编码命令类"),
    # 解释器内联代码 = 任意代码执行
    (re.compile(r"\b(python\d*|py|perl|ruby|node)\s+(-c|-e|--eval)\b", re.I), "内联代码执行类"),

    # --- 下载 / 远程 ---
    (re.compile(r"\b(ssh|scp|sftp|telnet|tftp|netsh\s+wlan)\b", re.I), "远程访问类"),
    (re.compile(r"\b(certutil|bitsadmin|regsvr32|rundll32|installutil)\b", re.I), "下载/执行类"),
    (re.compile(
        r"\b(Invoke-WebRequest|Invoke-RestMethod|iwr|irm|curl|wget"
        r"|Start-BitsTransfer)\b", re.I), "网络下载类"),

    # --- 安装 / 发布 ---
    (re.compile(
        r"\b(winget|choco|scoop|msiexec|Install-Module|Install-Package"
        r"|Install-WindowsFeature|Add-WindowsCapability)\b", re.I), "安装类"),
    (re.compile(
        r"\b(pip|pip3|npm|yarn|pnpm|cargo|gem)\s+(install|i|add|uninstall|remove|ci)\b",
        re.I), "包管理类"),
    (re.compile(
        r"\b(git\s+(push|remote)|docker\s+(push|login|run|rm|rmi)"
        r"|kubectl\s+(apply|delete|create|edit|patch)"
        r"|terraform\s+(apply|destroy)|aws\s+\w+|gcloud\s+\w+|az\s+\w+)\b", re.I),
     "发布/云端类"),

    # --- 进程与电源 ---
    (re.compile(r"\b(taskkill|Stop-Process|kill|killall|pkill|tskill)\b", re.I), "结束进程类"),
    (re.compile(r"\b(shutdown|Restart-Computer|Stop-Computer|logoff)\b", re.I), "电源类"),
]

# 命令里出现这些字样就认为在碰凭证/密钥，即使命令本身无害也要过审批。
# 用子串匹配而不是 fnmatch：命令行里的路径写法太杂，子串更可靠。
SENSITIVE_HINTS = [
    ".ssh", "id_rsa", "id_ed25519", "id_ecdsa", "authorized_keys",
    ".pem", ".pfx", ".p12", ".key",
    ".env", ".aws", ".kube/config", ".docker/config.json",
    "credentials", "login data", "cookies.sqlite",
    "config.toml",
]

# 看起来像写入的操作（用于「写到工作目录之外就审批」这条规则）
_WRITE_OP_RE = re.compile(
    r"(>>|>|\b(Out-File|Set-Content|Add-Content|New-Item|Copy-Item|Move-Item"
    r"|Rename-Item|Remove-Item|Clear-Content|tee)\b)", re.I)

# 旧的白名单策略（command_policy = "whitelist"）用；danger-only 下不参与判定。
ALLOW_RULES: list[tuple[re.Pattern, bool]] = [
    (re.compile(r"^(dir|ls)(\s|$)", re.I), True),
    (re.compile(r"^type\s", re.I), True),
    (re.compile(r"^cat\s", re.I), True),
    (re.compile(r"^(pwd|whoami|hostname|ver|uname)\s*$", re.I), False),
    (re.compile(r"^git\s+(status|diff|log|show|branch|rev-parse)\b", re.I), False),
    (re.compile(r"^python(\d+(\.\d+)*)?\s+--version\s*$", re.I), False),
    (re.compile(r"^node\s+--version\s*$", re.I), False),
    (
        re.compile(
            r"^(Get-Process|Get-Service|Get-Date|Get-Location|Get-Command|Get-Member"
            r"|Get-Help|Get-Volume|Get-NetIPAddress|Get-ComputerInfo|Get-CimInstance"
            r"|Get-PSDrive|Get-EventLog|Get-Host)\b",
            re.I,
        ),
        False,
    ),
    (re.compile(r"^(Get-ChildItem|Get-Content|Get-Item|Get-ItemProperty|gci|gc)\b", re.I), True),
]

# 看起来像路径的参数（用于 needs_path 规则与写入越界的额外校验）
_PATHLIKE_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|\.{1,2}[\\/]|/|~)")


@dataclass
class Decision:
    level: str  # R / W / H / X
    allow: bool
    reason: str

    def as_dict(self) -> dict:
        return {"level": self.level, "allow": self.allow, "reason": self.reason}


def _first_token(command: str, shell: str) -> str:
    text = command.strip()
    if shell == "wsl":
        try:
            parts = shlex.split(text)
        except ValueError:
            parts = text.split()
    else:
        # PowerShell 侧只取第一段，不做完整解析
        parts = re.split(r"\s+", text)
    return parts[0].lower() if parts else ""


def _split_segments(text: str, shell: str) -> list[str] | None:
    """按 ; && || | 换行 把命令拆成独立段。引号不配对时返回 None。

    引号内的分隔符不算分隔符：``echo "a;b"`` 是一段。
    PowerShell 里反斜杠不是转义符（``"C:\\x\\"`` 合法），所以只有 wsl 才处理反斜杠转义。
    """
    segments: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    n = len(text)

    while i < n:
        ch = text[i]

        if quote is not None:
            buf.append(ch)
            if ch == quote:
                quote = None
                i += 1
                continue
            if ch == "\\" and quote == '"' and shell == "wsl" and i + 1 < n:
                buf.append(text[i + 1])
                i += 2
                continue
            i += 1
            continue

        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue

        if ch in (";", "|", "\n", "\r", "&"):
            segment = "".join(buf).strip()
            if segment:
                segments.append(segment)
            buf = []
            while i < n and text[i] in (";", "|", "\n", "\r", "&"):
                i += 1
            continue

        buf.append(ch)
        i += 1

    if quote is not None:
        return None

    segment = "".join(buf).strip()
    if segment:
        segments.append(segment)
    return segments


def _sensitive_hit(text: str) -> str | None:
    """命令里是否出现凭证/密钥类路径。"""
    normalized = text.replace("\\", "/").lower()
    for hint in SENSITIVE_HINTS:
        if hint.lower() in normalized:
            return hint
    return None


def _extract_path_args(command: str, shell: str) -> list[str]:
    text = command.strip()
    if shell == "wsl":
        try:
            tokens = shlex.split(text)
        except ValueError:
            tokens = text.split()
    else:
        tokens = text.split()
    out: list[str] = []
    for token in tokens[1:]:
        if token.startswith("-"):
            continue
        if token.startswith("/") and shell != "wsl" and len(token) <= 3:
            continue
        if _PATHLIKE_RE.match(token):
            out.append(token)
    return out


def _classify_segment(segment: str, shell: str, guard: PathGuard, policy: str,
                      danger: list[tuple[re.Pattern, str]],
                      restrict_writes: bool) -> Decision:
    text = segment.strip()
    if not text:
        return Decision("R", True, "空段")

    # 1) 硬拒绝：不可审批
    first = _first_token(text, shell)
    if first in X_FIRST_TOKENS:
        return Decision("X", False, f"禁止的命令：{first}")
    for pattern in X_PATTERNS:
        if pattern.search(text):
            return Decision("X", False, "命中禁止规则（关闭防护/提权类）")

    # 2) 动态子表达式无法静态判定
    if "$(" in text or "`" in text:
        return Decision("H", False, "含动态子表达式（$( ) 或反引号），无法静态判定")

    # 3) 碰凭证/密钥一律审批
    hit = _sensitive_hit(text)
    if hit:
        return Decision("H", False, f"命令引用了敏感路径（{hit}）")

    # 4) 危险命令清单
    for pattern, label in danger:
        if pattern.search(text):
            return Decision("H", False, f"危险命令：{label}")

    # 5) 写到工作目录之外 → 审批（防止误覆盖系统文件）
    if restrict_writes and _WRITE_OP_RE.search(text):
        for raw in _extract_path_args(text, shell):
            try:
                guard.check_write(raw)
            except PathError:
                return Decision("H", False, f"写入路径在工作目录之外：{raw}")

    # 6) 旧的白名单策略
    if policy == POLICY_WHITELIST:
        for pattern, needs_path in ALLOW_RULES:
            if not pattern.match(text):
                continue
            if not needs_path:
                return Decision("R", True, "白名单只读命令")
            paths = _extract_path_args(text, shell)
            if not paths:
                return Decision("R", True, "白名单只读命令（作用于当前目录）")
            try:
                for raw in paths:
                    guard.check_read(raw)
            except PathError as exc:
                return Decision("H", False, f"白名单命令但路径越界：{exc}")
            return Decision("R", True, "白名单只读命令（路径已校验）")
        return Decision("H", False, "非白名单命令（白名单模式）")

    # 7) danger-only：默认放行
    return Decision("R", True, "常规命令（不在危险清单内）")


def classify_command(command: str, shell: str, guard: PathGuard,
                     policy: str = POLICY_DANGER_ONLY,
                     extra_danger: list[str] | None = None,
                     restrict_writes: bool = True) -> Decision:
    """把一条命令判成 R/W/H/X。

    默认策略 ``danger-only``：只审危险命令，其余放行。
    切成 ``whitelist`` 可退回旧行为（除白名单外一律审批）。
    """
    text = (command or "").strip()
    if not text:
        return Decision("X", False, "空命令")

    segments = _split_segments(text, shell)
    if segments is None:
        return Decision("H", False, "引号不配对，无法静态拆解")

    danger = list(DANGER_PATTERNS)
    for raw in (extra_danger or []):
        try:
            danger.append((re.compile(raw, re.I), f"自定义规则 {raw}"))
        except re.error:
            continue

    worst = Decision("R", True, "常规命令（不在危险清单内）")
    for segment in segments:
        decision = _classify_segment(segment, shell, guard, policy, danger, restrict_writes)
        if _SEVERITY.get(decision.level, 0) > _SEVERITY.get(worst.level, 0):
            worst = decision
        if worst.level == "X":
            return worst
    return worst


def looks_binary(data: bytes) -> bool:
    """粗略判断二进制：出现 NUL 字节即视为二进制。"""
    return b"\x00" in data[:4096]
