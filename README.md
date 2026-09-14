# GitHub Copilot App 汉化工具（二进制替换版）


## 这是什么

针对 **GitHub Copilot App**（Tauri 2 + WebView2 客户端）的简体中文汉化工具。

新 Copilot App 技术栈是 Tauri 2（老 GitHub Desktop 是 Electron，旧思路不适用）。本工具通过
**解析 exe 内嵌的 Tauri 资源表 → 解压 brotli 压缩的前端 bundle → 替换英文界面文本 →
重新压缩回写**，实现真正的界面汉化。

## 核心技术结论

| 项目 | 说明 |
|------|------|
| 目标文件 | `github.exe`（约 342 MB，默认 `D:\Program Files (x86)\GitHub Copilot\`） |
| 技术栈 | Tauri 2 + WebView2 + React |
| 资源存储 | 525 个 JS bundle，brotli 压缩，内嵌在 exe 的 `.rdata` 节区 |
| 界面文本 | 英文硬编码在 JSX 模板字符串里，无全局 i18n 框架 |
| 改动规模 | 30 个 bundle，累计 11364 处替换 |

## 使用

### 前提

- 已安装 GitHub Copilot App
- **已完全退出 Copilot App**（运行中 exe 被锁定，无法写入）
- Python 3.10+（含 `brotli` 依赖，可自动装，见下）

### 三步上手

1. **装 Python**：安装 Python 3.10+，安装时勾选「Add Python to PATH」
2. **装依赖**：双击 `安装依赖.bat`（自动检查版本/PATH/brotli，缺则自动装）
3. **汉化**：双击 `汉化工具.bat` → 选 `[1]`

或命令行：
```
python hanhua_bin.py
```
常用参数：`--exe <路径>` `--dict <词典>` `--list`（只列出 bundle）`--no-backup`（不写安装目录备份）

### 📍 安装路径不同怎么办（换电脑 / 非默认安装位置）

`hanhua_bin.py` 会**自动定位** `github.exe`，无需改代码。定位顺序：

1. Windows 注册表卸载信息里的 `InstallLocation`
2. 常见目录遍历：`C:/D:/E:/F:` 盘的 `Program Files`、`Program Files (x86)`、`%LOCALAPPDATA%`
3. 工具同目录（便携版）

自动定位失败时（非标准目录），用 `--exe` 显式指定：
```
python hanhua_bin.py --exe "C:\你的目录\GitHub Copilot\github.exe"
```

### 首次启动提示

修改后的 exe 数字签名会失效，Windows 首次启动弹 SmartScreen，点「仍要运行」即可（正常现象）。

### 还原英文

现在**已有真原版备份**（`github.exe.原版.bak`），还原方法见 `备份清单.md`。
`汉化工具.bat` 里的 `[2] 还原英文` 依赖安装目录的 `github.exe.bak`（用 `--no-backup` 时不生成），
日常回滚建议直接用 `备份清单.md` 里的 copy 命令，更可靠。

## 文件说明

### 根目录 = 工具本体（`bat + hanhua_bin.py + dict/` 是不可拆的最小单元）

| 文件 | 作用 |
|------|------|
| `汉化工具.bat` | 一键入口（自动定位 Python 后调 `hanhua_bin.py`） |
| `安装依赖.bat` | 依赖向导（检查 Python≥3.10 → PATH → brotli，缺则自动装） |
| `hanhua_bin.py` | 汉化主程序：解压 → 替换 → 重压缩 → 回写 |
| `dict/binary-zh-CN.json` | **主词典**（6679 条，`entries` 为 `[英文, 中文]` 数组） |
| `dict/round*.json` | 历轮增量词典（已合并进主词典，保留作溯源） |
| `使用说明.md` / `备份清单.md` | 本文件 / 回滚快照清单 |
| `github.exe.原版.bak` | **真原版备份**（首次保留，未汉化的干净版本） |
| `github.exe.round*.bak` | 各轮汉化快照（见 `备份清单.md`） |

### `_工作区/` = 汉化过程产物（可随时清理，不影响运行）

历轮一次性脚本、中间数据、各轮报告、健康体检报告都在这里。

## 自定义词典

编辑 `dict/binary-zh-CN.json` 的 `entries` 数组，格式 `["英文", "中文"]`。

**关键规则（务必遵守）：**

- 只支持**模板字符串精确匹配**（`` `原文` ``），避免误伤代码
- 键盘键名（Delete/Enter/Escape/Tab 等）有内置黑名单保护
- **裸单英文词**（`State`/`Is`/`Label`/`Closed`/`Any`/`Edit`/`Copy`/`Export`/`Owner`/`None`/`Off` 等）
  **绝对不要**直接进词典 —— 同名 token 在库里可能是**枚举反查名**或标识符，译了会导致
  序列化/匹配失配。这类一律用 `hanhua_bin.py` 里的 `ANCHORED_PATTERNS`（带上下文锚点）处理，
  或加进 `BUNDLE_TOKEN_BLACKLIST`（按 bundle 屏蔽）。
- 替换后压缩体积超原体积时，会自动借用 asset 间隙（gap）拓展，无需担心体积

## 安全说明与已知限制

1. **原 exe 数字签名失效**（正常现象）。
2. **应用升级后需重新适配**：bundle 文件名哈希会变，asset 表偏移要重新校准。
3. **服务端下发的文案改不到**：实验项标题、部分页签名不在 exe 里（已用字节级证据确认）。
4. **含 `${}` 插值的动态拼接串**不能整串替换，需逐条保占位符手写锚点。
5. **语言/格式名**（JavaScript/Python/SQL/YAML 等）按约定保留英文。
6. **WordEditor 格式工具栏整块未译**（高亮色板/对齐/加粗等），待后续处理。

## 汉化质量保障（Round 39 校对结论）

- 已用**真原版**（`github.exe.原版.bak`）逐处对照，**功能零异常**：
  - 枚举反查名（Edit/Copy/Export/Owner/Keyboard/Custom/None/Off 共 8 处）已修复为保持英文
  - 无由汉化引入的逻辑误译
- 结构完整：525 bundle 全对齐；语法校验 525/525 通过；幂等性成立
- 完整体检报告见 `_工作区/最终体检报告.md`
