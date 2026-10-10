"""设置管理面板的本地口令。

用法::

    python panel_passwd.py                      # 交互输入（不回显，输入两遍）
    echo '你的口令' | python panel_passwd.py --stdin
    python panel_passwd.py --generate           # 随机生成，明文写到 PANEL-LOGIN.txt
    python panel_passwd.py --generate --out D:/somewhere/secret.txt
    python panel_passwd.py --path                # 只打印口令文件位置

文件里**只放 scrypt 哈希**，明文永远不落盘（``--generate`` 例外：它把新生成的口令
写到你指定的文件里，好让你能读到一次；读到之后请删掉那个文件）。

口令一旦忘记：直接重跑本脚本设一个新的即可，面板不需要旧口令。
"""

from __future__ import annotations

import argparse
import getpass
import os
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcp_server import config as config_module          # noqa: E402
from mcp_server.panel import PassphraseStore, hash_passphrase   # noqa: E402

WORDS = [
    "amber", "brisk", "cedar", "delta", "ember", "frost", "gauge", "harbor",
    "ivory", "jolly", "kite", "linen", "maple", "noble", "onyx", "pearl",
    "quartz", "raven", "solar", "tulip", "umber", "vivid", "willow", "xenon",
    "yarrow", "zephyr", "basalt", "cobalt", "dune", "fable", "glacier", "heron",
]


def generate_passphrase() -> str:
    """四词 + 四位数字：好念、好抄、熵足够（约 47 bit，配 scrypt 绰绰有余）。"""
    words = [secrets.choice(WORDS) for _ in range(4)]
    return "-".join(words) + "-" + str(secrets.randbelow(9000) + 1000)


def _tighten(path: Path) -> None:
    try:
        user = os.environ.get("USERNAME") or ""
        domain = os.environ.get("USERDOMAIN") or ""
        who = f"{domain}\\{user}" if domain and user else user
        if who:
            import subprocess
            subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{who}:(F)"],
                           capture_output=True, timeout=20,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description="设置 Window MCP 管理面板的口令")
    parser.add_argument("--stdin", action="store_true", help="从标准输入读口令")
    parser.add_argument("--generate", action="store_true",
                        help="随机生成一个口令，并写到一个文件里")
    parser.add_argument("--out", default="", help="--generate 时明文写到哪（默认 PANEL-LOGIN.txt）")
    parser.add_argument("--path", action="store_true", help="只打印口令文件位置")
    parser.add_argument("--config", default="", help="指定 config.toml（默认项目根下的那个）")
    args = parser.parse_args()

    cfg = config_module.load(args.config or None)
    settings = cfg.panel_settings
    store = PassphraseStore(settings.passphrase_file)

    if args.path:
        print(f"口令文件：{settings.passphrase_file}")
        print(f"已配置  ：{'是' if store.configured() else '否'}")
        return 0

    if store.path is None:
        print("config.toml 里没有配置 panel.passphrase_file，无法设置。", file=sys.stderr)
        return 2

    if args.generate:
        passphrase = generate_passphrase()
        store.set(passphrase)
        out = Path(args.out) if args.out else (config_module.PROJECT_ROOT / "PANEL-LOGIN.txt")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            "Window MCP 管理面板 —— 首次登录口令\n"
            "=====================================\n\n"
            f"口令：{passphrase}\n\n"
            "面板地址（本机）：http://127.0.0.1:%d/\n"
            "面板地址（公网）：https://admin.example.com/\n\n"
            "登录一次之后请删掉本文件（里面是明文口令）：\n"
            f'  del "{out}"\n'
            "忘记口令也不要紧：重跑 python panel_passwd.py 设一个新的即可。\n"
            % settings.port,
            encoding="utf-8")
        _tighten(out)
        print(f"已生成并写入口令哈希：{settings.passphrase_file}")
        print(f"明文已写到（请读取后删除）：{out}")
        return 0

    if args.stdin:
        passphrase = sys.stdin.readline().strip()
    else:
        first = getpass.getpass("新口令（至少 8 位）：")
        second = getpass.getpass("再输一遍：")
        if first != second:
            print("两次输入不一致。", file=sys.stderr)
            return 2
        passphrase = first

    if len(passphrase) < 8:
        print("口令太短（至少 8 个字符）。", file=sys.stderr)
        return 2
    store.set(passphrase)
    print(f"已更新口令哈希：{settings.passphrase_file}")
    print("（面板正在运行时无需重启：下次请求就会用新的哈希校验。）")
    # 顺带确认一下哈希格式没写坏
    assert hash_passphrase(passphrase).startswith("scrypt$")
    return 0


if __name__ == "__main__":
    sys.exit(main())
