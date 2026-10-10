"""命令行工具：在没有手机通道时处理审批单。

用法：
    python -m mcp_server.cli list
    python -m mcp_server.cli approve <approval_id>
    python -m mcp_server.cli reject  <approval_id>

服务器按文件 mtime 重新加载审批状态，所以这里的改动会被运行中的服务器看到。
"""

from __future__ import annotations

import sys

from . import config as config_module
from .approvals import ApprovalStore


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cfg = config_module.load()
    store = ApprovalStore(cfg.approval_file, cfg.approval_ttl_s)

    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0

    action = argv[0]
    if action == "list":
        items = store.list_pending()
        if not items:
            print("没有待审批的操作。")
            return 0
        for item in items:
            print(f"[{item.approval_id}] {item.tool}  (剩余 {item.as_dict()['expires_in_s']}s)")
            print(f"    {item.summary}")
        return 0

    if action in ("approve", "reject"):
        if len(argv) < 2:
            print(f"用法：python -m mcp_server.cli {action} <approval_id>")
            return 2
        approval = store.decide(argv[1], action == "approve", actor="cli")
        if approval is None:
            print(f"审批单不存在：{argv[1]}")
            return 1
        print(f"审批号 {approval.approval_id} 现在状态：{approval.status}")
        if approval.status == "approved":
            print("已批准。让 Hark 调用 approval_status 取执行结果。")
        return 0

    print(f"未知命令：{action}")
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
