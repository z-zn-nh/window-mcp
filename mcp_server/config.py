"""配置加载。

优先级：环境变量 > config.toml > 内置默认值。
所有路径在加载时会被 realpath + normcase 归一，避免后续比较出现绕过。
"""

from __future__ import annotations

import os
import re
import tomllib
import urllib.parse
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import ClassVar

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.toml"

# token 名的合法字符集与长度：它会进审计日志（JSONL）和启动日志，不合法字符会污染两者。
TOKEN_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")
TOKEN_NAME_MAX_LEN = 32

# 默认拒绝访问的路径模式（fnmatch，大小写不敏感，分隔符统一为 /）
DEFAULT_DENIED_PATTERNS = [
    "**/.ssh/**",
    "**/*.pem",
    "**/*.key",
    "**/*.pfx",
    "**/*.p12",
    "**/id_rsa*",
    "**/id_ed25519*",
    "**/id_ecdsa*",
    "**/.env",
    "**/.env.*",
    "**/.aws/**",
    "**/.kube/config",
    "**/.docker/config.json",
    "**/appdata/roaming/microsoft/credentials/**",
    "**/appdata/local/google/chrome/user data/**",
    "**/appdata/roaming/mozilla/firefox/profiles/**",
    # 服务器自身的配置与状态：永远不可读写（对应 §6.2 的 X 级）
    "**/config.toml",
    "**/state/**",
    # 具名 token 的值放这里（secrets/<name>.token）：MCP 工具读不到自己的凭据，
    # 否则一个拿着 cue token 的客户端能直接把 cue.token 读走再长期留用。
    "**/secrets/**",
]


def _norm(p: str) -> str:
    return os.path.normcase(os.path.realpath(os.path.expanduser(p)))


@dataclass
class PanelSettings:
    """bot token 管理面板的配置（``config.toml`` 的 ``[server.panel]`` 表）。

    面板跑在**独立端口**上，通过已有命名隧道暴露成 ``admin.example.com``。
    它自己的鉴权与 MCP 的 token 完全无关：

    * ``passphrase`` —— 只要本地管理口令（口令只存 scrypt 哈希，见 ``panel.py``）；
    * ``access``     —— 只信任 Cloudflare Access 的 ``Cf-Access-Jwt-Assertion``
      （验 RS256 签名 + 校验 ``aud`` / ``iss`` / ``exp`` / 邮箱，见 ``access.py``）；
    * ``either``     —— 两者任一即可；
    * ``both``       —— 两者都要。**没配置的那一项自动跳过**，所以在填上
      ``access_aud`` 之前，``both`` 实际等于「只要口令」，不会把自己锁在外面。
    """

    enabled: bool = True
    host: str = "127.0.0.1"          # 只监听本机，绝不 0.0.0.0
    port: int = 8771
    auth_mode: str = "both"
    # 口令文件里放的是 scrypt 哈希（不是明文），ACL 收到只有当前用户
    passphrase_file: str = "secrets/panel.passphrase"
    session_ttl_s: int = 12 * 3600   # 口令登录后的会话有效期
    bots_file: str = "state/bots.json"
    pepper_file: str = "secrets/bots.key"   # bot token 的 HMAC pepper
    # --- 远程审批（三档策略里的 ask 档）---
    # 单次 ask 调用最多阻塞多少秒等手机端批准；超时自动拒绝并回明确错误。
    approval_wait_s: int = 120
    # 面板上「本 bot N 分钟内同类放行」的时长。
    auto_allow_minutes: int = 10
    # 会动鼠标键盘的工具共用的全局锁，最多排队等多久。
    lock_wait_s: int = 120
    # 面板「设置」页能改的运行时旋钮落在这里（改完立刻生效，不用重启）。
    settings_file: str = "state/panel-settings.json"
    # --- 手机推送（ntfy）---
    # 新审批到达时推一条到 ntfy 私有 topic。**只推 bot 名 / 工具名 / 面板链接**，
    # 不带 token，也不带参数明文。topic 留空 = 不推送。
    ntfy_server: str = "https://ntfy.sh"
    ntfy_topic: str = ""
    ntfy_token: str = ""            # 自建 ntfy 才需要；私有 ntfy.sh topic 不需要
    # 通知里「打开面板处理」按钮指向的地址。
    public_url: str = ""
    # --- Cloudflare Access ---
    access_team: str = ""            # 形如 xxx.cloudflareaccess.com
    access_aud: str = ""             # Access 应用页面上的 Application Audience (AUD) Tag
    access_emails: list[str] = field(default_factory=list)
    access_jwks_file: str = ""       # 离线/测试用：本地 JWKS 文件
    access_cache_file: str = "state/access-jwks.json"   # JWKS 落盘缓存，断网也能验
    # 面板里显示工具名时用的前缀；留空则跟随 server.tool_prefix
    tool_prefix: str = ""

    AUTH_MODES = ("passphrase", "access", "either", "both")

    def resolve(self, base: Path) -> "PanelSettings":
        """把相对路径按项目根展开，并做取值校验。"""
        self.host = (self.host or "127.0.0.1").strip()
        self.port = int(self.port)
        self.auth_mode = (self.auth_mode or "both").strip().lower()
        if self.auth_mode not in self.AUTH_MODES:
            raise ValueError(
                f"panel.auth_mode 只能是 {'/'.join(self.AUTH_MODES)}，"
                f"收到 {self.auth_mode!r}")
        self.session_ttl_s = max(60, int(self.session_ttl_s))
        self.approval_wait_s = min(600, max(10, int(self.approval_wait_s)))
        self.lock_wait_s = min(600, max(10, int(self.lock_wait_s)))
        self.auto_allow_minutes = min(24 * 60, max(1, int(self.auto_allow_minutes)))
        self.ntfy_server = (self.ntfy_server or "").strip().rstrip("/")
        self.ntfy_topic = (self.ntfy_topic or "").strip()
        self.ntfy_token = (self.ntfy_token or "").strip()
        self.public_url = (self.public_url or "").strip().rstrip("/")
        self.access_team = (self.access_team or "").strip()
        self.access_aud = (self.access_aud or "").strip()
        self.access_emails = [str(x).strip() for x in (self.access_emails or [])
                              if str(x).strip()]
        self.tool_prefix = (self.tool_prefix or "").strip()
        for name in ("passphrase_file", "bots_file", "pepper_file", "settings_file",
                     "access_jwks_file", "access_cache_file"):
            raw = getattr(self, name)
            if raw:
                path = Path(os.path.expanduser(str(raw)))
                setattr(self, name, str(path if path.is_absolute() else base / path))
        return self

    def needs_passphrase(self) -> bool:
        return self.auth_mode in ("passphrase", "either", "both")

    def needs_access(self) -> bool:
        return self.auth_mode in ("access", "either", "both")


def _build_panel_settings(raw, cfg: "Config") -> PanelSettings:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("config.toml 的 [server.panel] 必须是一张表")
    known = {f.name for f in fields(PanelSettings)}
    unknown = set(raw) - known
    if unknown:
        raise ValueError(
            f"[server.panel] 里出现未知配置项：{', '.join(sorted(unknown))}")
    # 状态 / 密钥文件的默认位置跟随 state_dir：测试里给一个临时 state_dir
    # 就会自动用临时名册，绝不会碰到生产环境的 state/bots.json。
    raw = dict(raw)
    raw.setdefault("bots_file", str(cfg.state_path / "bots.json"))
    raw.setdefault("pepper_file", str(cfg.state_path / "bots.key"))
    raw.setdefault("passphrase_file", str(cfg.state_path / "panel.passphrase"))
    raw.setdefault("access_cache_file", str(cfg.state_path / "access-jwks.json"))
    raw.setdefault("settings_file", str(cfg.state_path / "panel-settings.json"))
    settings = PanelSettings(**raw).resolve(PROJECT_ROOT)
    if not settings.tool_prefix:
        settings.tool_prefix = cfg.tool_prefix or ""
    if settings.enabled and settings.host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(
            f"panel.host 只能是 127.0.0.1 / localhost（面板绝不对外直接监听），"
            f"收到 {settings.host!r}；对外暴露请走命名隧道")
    if settings.enabled and settings.port == cfg.port:
        raise ValueError("panel.port 不能与 server.port 相同（面板必须是独立端口）")
    if settings.access_team and not settings.access_aud:
        cfg.load_warnings.append(
            "panel.access_team 已填但 access_aud 为空：Cloudflare Access 这道门"
            "**暂未启用**（只校验口令）。拿到 Access 应用的 AUD Tag 后填上即可。")
    if settings.access_aud and not settings.access_team:
        cfg.load_warnings.append(
            "panel.access_aud 已填但 access_team 为空：Access 这道门暂未启用。")
    return settings


@dataclass
class Config:
    # --- 网络 ---
    host: str = "127.0.0.1"
    port: int = 8765
    path: str = "/mcp"
    # 暴露给客户端的工具名前缀。两个同名 MCP 并行跑时用它区分；
    # 切换成唯一服务后改成 "" 即可恢复原名。
    tool_prefix: str = ""
    public_base_url: str = ""  # 例如 https://pc.example.com，用于生成审批链接
    # MCP SDK 的 DNS 重绑定保护会校验 Host 头。经隧道/反向代理访问时 Host 会变成
    # 公网域名，必须列进来，否则一律返回 421 Invalid Host header。
    allowed_hosts: list[str] = field(default_factory=list)
    allowed_origins: list[str] = field(default_factory=list)

    # --- 鉴权 ---
    tokens: list[str] = field(default_factory=list)  # 轮换期可同时配置新旧两个
    # 具名 token：name -> token（值直接写在配置里）。名字**只进审计日志**，不参与授权判断；
    # 审计里出现 "token": "cue" 就能知道是哪个客户端干的，而 token 值本身永不落盘。
    named_tokens: dict[str, str] = field(default_factory=dict)
    # 具名 token 的「值放文件」写法：name -> 文件路径（相对路径按项目根解析）。
    # 文件内容只放 token 本身（首尾空白会被去掉）。文件缺失或为空时**跳过该名字**并记一条
    # warning——吊销一个 token 就是删文件 + 重启，不会连累其它 token，也不会让服务起不来。
    token_files: dict[str, str] = field(default_factory=dict)
    # 加载期的非致命问题（启动日志会原样打出来），例如某个 token 文件没读到。
    load_warnings: list[str] = field(default_factory=list)
    admin_token: str = ""  # 为空则复用第一个 token（tokens[0]，没有匿名 token 时用第一个具名 token）
    auth_header: str = "authorization"  # Hark 侧也可指定自定义头名（如 x-api-key）
    auth_scheme: str = "Bearer"  # 为空表示头里直接放裸 token

    # --- 路径规则 ---
    read_roots: list[str] = field(default_factory=list)
    write_roots: list[str] = field(default_factory=list)
    denied_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_DENIED_PATTERNS))

    # --- 命令执行 ---
    default_timeout_s: int = 30
    max_timeout_s: int = 50  # Hark 单次调用默认 60 秒超时，留出余量
    max_output_bytes: int = 20 * 1024
    max_read_bytes: int = 200 * 1024
    wsl_distro: str = ""  # 空表示用默认发行版

    # 命令审批策略：
    #   danger-only（默认）—— 只有命中「危险命令清单」才审批，其余直接执行
    #   whitelist          —— 旧行为：除白名单前缀外一律审批（非常啰嗦）
    command_policy: str = "danger-only"
    # 追加到内置危险清单的自定义正则（想更严就加这里）
    extra_danger_patterns: list[str] = field(default_factory=list)
    # 命令写到工作目录之外时是否转审批（防止误覆盖系统文件）
    restrict_writes_to_roots: bool = True

    # --- 限速 ---
    rate_per_minute: int = 60
    rate_high_per_hour: int = 10

    # --- 审批 ---
    approval_ttl_s: int = 600  # 10 分钟
    dedupe_ttl_s: int = 600

    # --- 截屏 ---
    screenshot_level: str = "R"  # R=自动放行（默认）；H=需审批；X=禁用
    screenshot_max_width: int = 1600
    screenshot_quality: int = 70

    # --- GUI 操作（type_text / click / hotkey / wake_screen）---
    # R（默认）= 免审批直接执行；H = 每次操作都要审批；X = 完全禁用
    gui_level: str = "R"
    gui_max_chars: int = 10000  # 单次 type_text 的字符上限

    # --- UIA 无障碍树（uia_snapshot / uia_wait_for / uia_click / uia_type）---
    # 从 CursorTouch/Windows-MCP 移植，见 mcp_server/vendor/NOTICE.md
    uia_level: str = "R"          # R=免审批（默认）；H=每次操作审批；X=禁用
    uia_max_elements: int = 150   # 单次快照最多标注多少个元素（越大越慢）
    uia_max_windows: int = 6      # 遍历几个顶层窗口
    uia_timeout_s: int = 40       # 单次 UIA 调用硬超时，防某个窗口的无障碍提供程序卡死

    # --- 屏幕常亮 / 屏保 / 电源 ---
    keep_display_awake: bool = True   # 服务器运行期间不让显示器熄屏、系统不睡眠
    disable_screensaver: bool = True  # 启动时关掉屏幕保护程序（只写 HKCU，可逆）
    power_tweaks: bool = True         # 启动时把电源方案里「关显示器/睡眠/休眠」超时设为永不
    # 启动时关掉「动态锁」：配对的手机离开蓝牙范围就自动锁屏。屏幕/屏保/电源
    # 都配成「永不」之后，这一条往往是唯一还在触发锁屏的机制。
    disable_dynamic_lock: bool = True

    # --- 目录 ---
    log_dir: str = ""
    state_dir: str = ""
    work_dir: str = ""

    # --- 通知 ---
    notifier: dict = field(default_factory=dict)

    # --- bot token 管理面板（[server.panel] 表；详见 PanelSettings）---
    panel: dict = field(default_factory=dict)
    # 由 __post_init__ 填好；标成 ClassVar 是为了让 @dataclass 把它当类属性而不是
    # 构造参数——否则它会变成必填字段，config.toml 里也不该出现这个键。
    panel_settings: ClassVar[PanelSettings]

    def __post_init__(self) -> None:
        if not self.work_dir:
            self.work_dir = str(PROJECT_ROOT / "workspace")
        if not self.log_dir:
            self.log_dir = str(PROJECT_ROOT / "logs")
        if not self.state_dir:
            self.state_dir = str(PROJECT_ROOT / "state")
        if not self.read_roots:
            self.read_roots = [self.work_dir]
        if not self.write_roots:
            self.write_roots = [self.work_dir]
        self._validate_token_names()
        if not self.admin_token:
            # 保旧语义：留空 = 复用第一个 token（优先匿名 tokens[0]，等价于加具名 token 之前的配置）。
            if self.tokens and self.tokens[0]:
                self.admin_token = self.tokens[0]
            else:
                entries = self.token_entries()
                if entries:
                    self.admin_token = entries[0][1]
        if not self.allowed_hosts:
            self.allowed_hosts = [
                f"{self.host}:{self.port}",
                f"localhost:{self.port}",
                "127.0.0.1",
                "localhost",
            ]
        if not self.allowed_origins:
            self.allowed_origins = [
                f"http://{self.host}:{self.port}",
                f"http://localhost:{self.port}",
            ]
        # 配了公网地址就自动把它加进允许列表，省得隧道换了域名忘了改
        if self.public_base_url:
            netloc = urllib.parse.urlparse(self.public_base_url).netloc
            if netloc and netloc not in self.allowed_hosts:
                self.allowed_hosts.append(netloc)
            if self.public_base_url not in self.allowed_origins:
                self.allowed_origins.append(self.public_base_url)

        # 等级写错（比如 "danger"）时直接启动失败，好过悄悄按默认值放行
        self.screenshot_level = (self.screenshot_level or "R").upper()
        self.gui_level = (self.gui_level or "R").upper()
        self.uia_level = (self.uia_level or "R").upper()
        for name in ("screenshot_level", "gui_level", "uia_level"):
            value = getattr(self, name)
            if value not in ("R", "H", "X"):
                raise ValueError(f"{name} 只能是 R / H / X，收到 {value!r}")

        # 工具名前缀：只允许字母/数字/下划线，免得拼出非法工具名
        self.tool_prefix = (self.tool_prefix or "").strip()
        if self.tool_prefix and not all(
                c.isalnum() or c == "_" for c in self.tool_prefix):
            raise ValueError(
                f"tool_prefix 只能是字母/数字/下划线，收到 {self.tool_prefix!r}")

        # 面板设置：从 [server.panel] 表解析成结构化对象（含校验）
        self.panel_settings = _build_panel_settings(self.panel, self)

    # --- 派生属性 ---
    @property
    def work_path(self) -> Path:
        return Path(self.work_dir)

    @property
    def log_path(self) -> Path:
        return Path(self.log_dir)

    @property
    def state_path(self) -> Path:
        return Path(self.state_dir)

    @property
    def jobs_path(self) -> Path:
        return self.log_path / "jobs"

    @property
    def approval_file(self) -> Path:
        return self.state_path / "approvals.json"

    @property
    def dedupe_file(self) -> Path:
        return self.state_path / "dedupe.json"

    def ensure_dirs(self) -> None:
        for p in (self.work_path, self.log_path, self.state_path, self.jobs_path):
            p.mkdir(parents=True, exist_ok=True)

    # --- 鉴权：token 名册 ---

    def _validate_token_names(self) -> None:
        """名字会进审计日志，所以先限制成安全字符集；重名会让归属失去意义，直接拒绝启动。"""
        seen: set[str] = set()
        for source in ("named_tokens", "token_files"):
            for name in getattr(self, source):
                text = str(name or "").strip()
                if not text or not TOKEN_NAME_RE.match(text):
                    raise ValueError(
                        f"{source} 里的 token 名不合法：{name!r}"
                        f"（只允许字母/数字/下划线/点/连字符，最长 {TOKEN_NAME_MAX_LEN}）")
                if len(text) > TOKEN_NAME_MAX_LEN:
                    raise ValueError(
                        f"{source} 里的 token 名过长（{len(text)} > {TOKEN_NAME_MAX_LEN}）：{text!r}")
                if text in seen:
                    raise ValueError(f"token 名重复：{text!r}（named_tokens 与 token_files 之间也不许重名）")
                seen.add(text)

    def token_entries(self) -> list[tuple[str, str]]:
        """(名字, token) 列表：鉴权与审计归属都用它。

        具名 token 在前，匿名 `tokens` 按顺序补 `token-1`、`token-2`…：编号取**配置里的位置**
        （tokens[1] 就是 token-2），这样审计里看到名字能直接对回 config.toml 的那一行。
        空白项既不参与比对也不占号。
        """
        entries = [(str(name).strip(), str(value).strip())
                   for name, value in self.named_tokens.items() if str(value).strip()]
        entries += [(f"token-{index}", str(value).strip())
                    for index, value in enumerate(self.tokens, 1) if str(value).strip()]
        return entries

    def token_names(self) -> list[str]:
        return [name for name, _ in self.token_entries()]

    def resolved_read_roots(self) -> list[str]:
        return [_norm(p) for p in self.read_roots]

    def resolved_write_roots(self) -> list[str]:
        return [_norm(p) for p in self.write_roots]


def _coerce(raw: dict) -> dict:
    """只接受 Config 上已声明的字段，避免 TOML 里写错键静默生效。"""
    known = {f.name for f in fields(Config)}
    out = {}
    for key, value in raw.items():
        if key in known:
            out[key] = value
        else:
            raise ValueError(f"config.toml 中出现未知配置项：{key}")
    return out


def load(path: str | os.PathLike | None = None) -> Config:
    cfg_path = Path(path) if path else DEFAULT_CONFIG_PATH
    raw: dict = {}
    if cfg_path.is_file():
        with open(cfg_path, "rb") as fh:
            data = tomllib.load(fh)
        raw = _coerce(data.get("server", data))

    cfg = Config(**raw)

    # 环境变量覆盖
    env_tokens = os.environ.get("MCP_TOKENS") or os.environ.get("MCP_TOKEN")
    if env_tokens:
        cfg.tokens = [t.strip() for t in env_tokens.split(",") if t.strip()]
    if os.environ.get("MCP_ADMIN_TOKEN"):
        cfg.admin_token = os.environ["MCP_ADMIN_TOKEN"]
    if os.environ.get("MCP_PORT"):
        cfg.port = int(os.environ["MCP_PORT"])
    if os.environ.get("MCP_PUBLIC_BASE_URL"):
        cfg.public_base_url = os.environ["MCP_PUBLIC_BASE_URL"].rstrip("/")

    cfg.read_roots = [_norm(p) for p in cfg.read_roots]
    cfg.write_roots = [_norm(p) for p in cfg.write_roots]
    cfg.work_dir = _norm(cfg.work_dir)
    cfg.log_dir = _norm(cfg.log_dir)
    cfg.state_dir = _norm(cfg.state_dir)

    # token_files：值只存在文件里（ACL 收紧到当前用户），配置里只留名字。
    cfg.named_tokens.update(_read_token_files(cfg))
    # 具名 token 是读完文件才齐的，所以 admin_token 的空值回退要在这里再算一次
    if not cfg.admin_token:
        entries = cfg.token_entries()
        if entries:
            cfg.admin_token = entries[0][1]

    # 这里**故意不**因为「没有静态 token」就退出：凭据现在也可以只存在于
    # 面板管理的 bot 名册里（state/bots.json）。真正的可用性检查在 App.__init__ 里做
    # ——那里同时看得到静态名册与 bot 名册，报错也更具体。
    cfg.ensure_dirs()
    return cfg


def _read_token_files(cfg: Config) -> dict[str, str]:
    """把 token_files 里每个路径的**内容**读进来；读不到就跳过并记 warning。

    返回 name -> token。文件内容只取 strip 后的整串（允许结尾换行）。
    注意这里故意不抛异常：删掉某个 token 文件就是吊销该 token 的手段，
    个别文件缺失不该让整个服务器起不来。
    """
    out: dict[str, str] = {}
    for name, raw_path in cfg.token_files.items():
        name = str(name).strip()
        path = Path(os.path.expanduser(str(raw_path)))
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            cfg.load_warnings.append(
                f"token 文件读取失败，已跳过 {name}：{path}（{type(exc).__name__}）")
            continue
        if not value:
            cfg.load_warnings.append(f"token 文件为空，已跳过 {name}：{path}")
            continue
        out[name] = value
    return out
