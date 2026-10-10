# 第三方代码署名（NOTICE）

## CursorTouch/Windows-MCP

本目录下的 `uia/` 与 `tree/` 两个包**移植自** CursorTouch/Windows-MCP：

* 仓库：https://github.com/CursorTouch/Windows-MCP
* 提交：`b04359e`（版本 `v0.8.7-12`）
* 作者：Jeomon George <jeogeoalukka@gmail.com>
* 许可：MIT

### 移植时做的改动（仅此三处，业务逻辑未动）

1. 绝对 import 由 `windows_mcp.uia` / `windows_mcp.tree` 改为
   `mcp_server.vendor.uia` / `mcp_server.vendor.tree`
2. `tree/service.py` 里 `if TYPE_CHECKING:` 下的
   `from windows_mcp.desktop.service import Desktop` 改为 `Desktop = Any`
   —— 上游的 `Desktop` 没有移植，该名字只用于类型标注，运行时不会执行
3. `__pycache__` 未一并搬运

### 未移植的部分

上游的 `tools/`、`desktop/`、`infrastructure/`、`watchdog/`、`notifications/`、
`powershell/`、`process/`、`registry/`、`filesystem/` 一律没有引入。
特别是上游默认开启的 PostHog 遥测（`infrastructure/analytics.py`）**完全不存在于本仓库**。

### 上游 MIT 许可全文

```
MIT License

Copyright (c) 2025 JEOMON GEORGE

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
