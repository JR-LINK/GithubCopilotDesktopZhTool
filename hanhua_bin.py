"""
GitHub Copilot App 汉化工具 - 主程序 v3 (处理所有 JS bundle)
汉化 / 还原 github.exe 中所有 JS bundle 的界面文本

用法:
  python hanhua_bin.py                 # 汉化（原文件备份为 github.exe.<版本>.bak）
  python hanhua_bin.py --restore       # 还原英文
  python hanhua_bin.py --dict xxx.json # 指定词典
  python hanhua_bin.py --layout        # 只打印 PE 布局与资源表定位（排查用）
  python hanhua_bin.py --list          # 只列出将被处理的 JS bundle

版本自适应说明（v3 新增）
  Tauri 的资源表位置写在 exe 的 PE 头里，**每次 App 自动更新都会位移**。
  v2 之前把 BASE/RDATA_VA/RDATA_RAW/ENTRY_START 写死成 1.1.20 的值，
  一旦 App 升到 1.1.21，资源表就定位不到 → 枚举出 0 个 bundle →
  「汉化完成」但实际一个字节都没改。v3 改为运行时从 PE 头动态解析，
  不再依赖版本号，升级后可直接继续用。
"""
import struct
import brotli
import json
import os
import shutil
import sys
import argparse

# ---------------------------------------------------------------------------
# Tauri 2 PE 布局常量
# ---------------------------------------------------------------------------
# ⚠ 下面这些只是**默认后备值**（1.1.20 时的取值）。真正使用时由
# detect_layout() 从 PE 头重新解析；解析失败才退回这里 / KNOWN_LAYOUTS。
BASE = 0x140000000
RDATA_VA = 0x7663000
RDATA_RAW = 0x7661e00
ENTRY_START = 0x83f8400
MAX_ENTRY = 2000  # 资源表条目上限（按 0x20 步长向下扫）

# 已实测过的版本布局，自动探测失败时按版本号兜底
# 值 = (image_base, rdata_va, rdata_raw, entry_start)
KNOWN_LAYOUTS = {
    '1.1.20': (0x140000000, 0x7663000, 0x7661e00, 0x83f8400),
    '1.1.21': (0x140000000, 0x7926000, 0x7925000, 0x86a9358),
}

DEFAULT_DICT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dict', 'binary-zh-CN.json')

# 默认安装路径（向后兼容：本机开发时用这个）
DEFAULT_EXE = r'D:\Program Files (x86)\GitHub Copilot\github.exe'

# 常见安装根目录（用于自动定位 github.exe，适配不同电脑的安装盘符/目录）
# 依次尝试：各盘符的 Program Files / Program Files (x86) / 用户 LocalAppData 等
_INSTALL_ROOTS = []


def _build_install_roots():
    """构造待搜索的安装根目录列表（跨盘符、跨安装位置）。"""
    roots = []
    # 1. 各盘符下的标准 Program Files 目录
    for drive in ('C', 'D', 'E', 'F'):
        for sub in ('Program Files', 'Program Files (x86)'):
            roots.append(r'%s:\%s\GitHub Copilot\github.exe' % (drive, sub))
    # 2. 用户级安装位置（per-user 安装）
    local = os.environ.get('LOCALAPPDATA', '')
    if local:
        roots.append(os.path.join(local, 'Programs', 'GitHub Copilot', 'github.exe'))
        roots.append(os.path.join(local, 'GitHub Copilot', 'github.exe'))
    # 3. 当前工作目录（便携/绿色版：exe 就在工具旁边）
    roots.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'github.exe'))
    return roots


_INSTALL_ROOTS = _build_install_roots()


def _locate_from_registry():
    """尝试从 Windows 注册表卸载信息定位 GitHub Copilot 安装路径。"""
    import winreg
    candidates = []
    keys = [
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    ]
    for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        for key_path in keys:
            try:
                key = winreg.OpenKey(root, key_path)
            except OSError:
                continue
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(key, i)
                    i += 1
                except OSError:
                    break
                try:
                    sub_key = winreg.OpenKey(root, key_path + '\\' + sub)
                    name, _ = winreg.QueryValueEx(sub_key, 'DisplayName')
                    loc, _ = winreg.QueryValueEx(sub_key, 'InstallLocation')
                except OSError:
                    continue
                if isinstance(name, str) and 'GitHub Copilot' in name:
                    p = os.path.join(loc, 'github.exe')
                    if os.path.exists(p):
                        candidates.append(p)
    return candidates


def find_exe():
    """定位 github.exe：注册表 > 常见目录 > 默认路径。返回路径或 None。"""
    for p in _locate_from_registry():
        if os.path.exists(p):
            return p
    for p in _INSTALL_ROOTS:
        if os.path.exists(p):
            return p
    if os.path.exists(DEFAULT_EXE):
        return DEFAULT_EXE
    return None


def va_to_off(va):
    return RDATA_RAW + (va - (BASE + RDATA_VA))


# ---------------------------------------------------------------------------
# PE 布局动态解析（版本自适应的核心）
# ---------------------------------------------------------------------------
def _parse_pe(data):
    """解析 PE 头，返回 (image_base, sections)
    sections: {'段名': (va, vsize, rsize, raw)}
    """
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        raise ValueError('不是有效的 PE 文件')
    coff = e_lfanew + 4
    machine, nsec, _, _, _, opt_size, _ = struct.unpack_from('<HHIIIHH', data, coff)
    opt = coff + 20
    magic = struct.unpack_from('<H', data, opt)[0]
    if magic == 0x20b:      # PE32+
        image_base = struct.unpack_from('<Q', data, opt + 0x18)[0]
    elif magic == 0x10b:    # PE32
        image_base = struct.unpack_from('<I', data, opt + 0x1c)[0]
    else:
        raise ValueError('未知的 PE 可选头 magic: 0x%x' % magic)
    secoff = opt + opt_size
    secs = {}
    for i in range(nsec):
        o = secoff + i * 40
        name = data[o:o + 8].rstrip(b'\x00').decode('latin1')
        vsize, va, rsize, raw = struct.unpack_from('<IIII', data, o + 8)
        secs[name] = (va, vsize, rsize, raw)
    return image_base, secs


def get_file_version(path):
    """读取 exe 的 FileVersion（如 '1.1.21'）；失败返回 None。"""
    try:
        import ctypes
        from ctypes import wintypes
        ver = ctypes.WinDLL('version')
        size = ver.GetFileVersionInfoSizeW(path, None)
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(path, 0, size, buf):
            return None
        r = ctypes.c_void_p()
        ln = wintypes.UINT()
        if not ver.VerQueryValueW(buf, '\\', ctypes.byref(r), ctypes.byref(ln)):
            return None

        class FI(ctypes.Structure):
            _fields_ = [('dwSignature', wintypes.DWORD),
                        ('dwStrucVersion', wintypes.DWORD),
                        ('dwFileVersionMS', wintypes.DWORD),
                        ('dwFileVersionLS', wintypes.DWORD),
                        ('dwProductVersionMS', wintypes.DWORD),
                        ('dwProductVersionLS', wintypes.DWORD)]
        fi = ctypes.cast(r, ctypes.POINTER(FI)).contents
        return '%d.%d.%d' % (fi.dwFileVersionMS >> 16, fi.dwFileVersionMS & 0xFFFF,
                             fi.dwFileVersionLS >> 16)
    except Exception:
        return None


def _find_asset_table(data, image_base, rd_va, rd_raw, rd_vsize, min_js=20):
    """在 .rdata 里自动定位 Tauri asset 表起点（返回文件偏移）。

    entry 结构固定 32 字节：name_ptr(8) name_len(8) data_ptr(8) data_len(8)，
    其中 name_ptr / data_ptr 都是落在 .rdata 内的 VA。

    快速筛法：同一段内所有 VA 的高 32 位相同（如 0x147926000..0x155194178
    的高位都是 0x1），因此按这 4 字节字节模式全文搜一遍即可锁定候选；
    再要求 name_ptr 与 data_ptr 成对出现（间隔 0x10），最后验证连续 run 取最长。
    """
    lo_va = image_base + rd_va
    hi_va = lo_va + rd_vsize
    hiword = struct.pack('<I', lo_va >> 32)

    hits = []
    pos = 0
    while True:
        i = data.find(hiword, pos)
        if i < 0:
            break
        hits.append(i)
        pos = i + 1
    hitset = set(hits)

    def valid(o):
        """o 处是否为合法 entry，是则返回 name"""
        if o < 0 or o + 0x20 > len(data):
            return None
        np_, nl_, dp_, dl_ = struct.unpack_from('<QQQQ', data, o)
        if not (lo_va <= np_ < hi_va) or not (lo_va <= dp_ < hi_va):
            return None
        if nl_ == 0 or nl_ > 500 or dl_ < 50:
            return None
        noff = rd_raw + (np_ - lo_va)
        if noff <= 0 or noff + nl_ > len(data):
            return None
        try:
            nm = data[noff:noff + nl_].decode()
        except Exception:
            return None
        if not nm or not all(32 <= ord(c) < 127 for c in nm):
            return None
        return nm

    best = None  # (start, run_len, js_count)
    for i in hits:
        o = i - 4                      # i 是指针低 4 字节位置，记录起点在其前 4 字节
        if (i + 0x10) not in hitset:   # data_ptr 必须同时命中
            continue
        if valid(o) is None:
            continue
        s = o
        while valid(s - 0x20) is not None:
            s -= 0x20
        n = 0
        js = 0
        p = s
        while True:
            nm = valid(p)
            if nm is None:
                break
            n += 1
            if nm.endswith('.js'):
                js += 1
            p += 0x20
        if js < min_js:
            continue
        if best is None or n > best[1]:
            best = (s, n, js)
    return best


def detect_layout(data, exe_path=None, quiet=False):
    """从 PE 头动态解析 Tauri 资源布局并覆盖全局常量。

    成功返回 (image_base, rdata_va, rdata_raw, entry_start)；失败返回 None。
    """
    global BASE, RDATA_VA, RDATA_RAW, ENTRY_START
    try:
        image_base, secs = _parse_pe(data)
    except Exception as e:
        if not quiet:
            print('[!] 解析 PE 头失败: %s' % e)
        return None
    if '.rdata' not in secs:
        if not quiet:
            print('[!] PE 里找不到 .rdata 段')
        return None

    rd_va, rd_vsize, rd_rsize, rd_raw = secs['.rdata']
    best = _find_asset_table(data, image_base, rd_va, rd_raw, rd_vsize)
    if best is not None:
        BASE, RDATA_VA, RDATA_RAW, ENTRY_START = image_base, rd_va, rd_raw, best[0]
        if not quiet:
            print('[+] 自动识别布局: image_base=0x%x  .rdata VA=0x%x RAW=0x%x  资源表=0x%x (%d 条, 含 %d 个 .js)'
                  % (image_base, rd_va, rd_raw, best[0], best[1], best[2]))
        return image_base, rd_va, rd_raw, best[0]

    # 自动探测失败 → 按文件版本查已知布局表
    ver = get_file_version(exe_path) if exe_path else None
    if ver:
        for k, v in KNOWN_LAYOUTS.items():
            if ver == k or ver.startswith(k + '.'):
                BASE, RDATA_VA, RDATA_RAW, ENTRY_START = v
                if not quiet:
                    print('[+] 自动识别失败，改用已知版本 %s 的布局' % k)
                return v
    if not quiet:
        print('[!] 无法定位资源表（App 版本 %s 尚未适配）' % (ver or '未知'))
    return None


# 跳过文件类型:不是用户界面 JS bundle 的资源
SKIP_NAME_PATTERNS = [
    'monaco-editor/',  # 编辑器内核(只提供 API)
    '.woff', '.woff2', '.ttf', '.otf',  # 字体
    '.png', '.svg', '.jpg', '.jpeg',  # 图标和图片
    '.css',
    'license-notices',  # 许可证声明
    'favicon',
    # 多语言 locale 文件(Monaco NLS) - 保持英文
    '/hi-', '/te-', '/mr-', '/be-', '/is-', '/as-', '/pa-', '/gu-', '/sk-', '/sl-', '/cs-', '/fi-', '/et-',
    '/de-', '/it-', '/ro-', '/ga-', '/sv-', '/hu-', '/nb-', '/nn-', '/no-', '/af-', '/la-',
    '/po-', '/nl-', '/fr-', '/es-', '/pl-', '/pt-', '/tr-', '/vi-', '/id-', '/ms-', '/th-', '/ru-', '/uk-',
    '/bg-', '/el-', '/he-', '/ar-', '/fa-', '/ja-', '/ko-', '/zh-',
    # 单独的极小或不需翻译的
    '/menu-shortcut-claims',
    '/index-',
    '/extensionCanvasWebviewCleanup',
    '/browserPreviewCleanup',
    '/keepAwakeStore',
    '/notificationSoundKeepAlive',
    '/event-',
    '/window-',
    '/dpi-',
    '/image-',
    '/webviewWindow-',
    '/webview-',
    '/nativeFileDrop',
    '/path-',
    '/tray-',
    '/menu-',  # 主菜单(命令行菜单,不是 UI 文案)
    '/wasm-',  # wasm 实现
    # 注意：/assets/telemetry-*.js 曾长期被跳过，误判为"埋点"文件。
    # Round 32 查明：它实际是一个 2.17MB 的应用共享 chunk（含 InboxSectionsStore、
    # 大量 JSX UI 组件、错误文案常量等），router 还会从它 import 符号（ll as ry）。
    # 跳过它导致 90 个词条、270 处文案长期漏译。现已启用（配合 bundle 级黑名单）。
    '/runtimePerfCapture',
    '/perf-timeline',
    '/metricInteractionStarts',
    '/onboardingStore',
    '/chord-helpers',
    '/inputModality',
    '/logger',
    '/appUpdate',
    '/selectAllGuard',
    '/select-',
    '/sortable',
    '/prop-types',
]


def should_skip(name):
    for pat in SKIP_NAME_PATTERNS:
        if pat in name:
            return True
    return False


def load_assets(data):
    """枚举 asset 表全部 entry,只保留 .js bundle(且非 skip)"""
    assets = []
    for i in range(MAX_ENTRY):
        off = ENTRY_START + i * 0x20
        if off + 0x20 > len(data):
            break
        name_ptr = struct.unpack('<Q', data[off:off+8])[0]
        name_len = struct.unpack('<Q', data[off+8:off+16])[0]
        data_ptr = struct.unpack('<Q', data[off+16:off+24])[0]
        data_len = struct.unpack('<Q', data[off+24:off+32])[0]
        if name_ptr == 0 or name_len == 0 or name_len > 500:
            # 找连续空 entry 停止
            if name_len > 500 or name_len == 0:
                continue
        try:
            name = data[va_to_off(name_ptr):va_to_off(name_ptr)+name_len].decode()
        except Exception:
            continue
        if not name.endswith('.js'):
            continue
        if should_skip(name):
            continue
        if data_len < 50:
            continue
        assets.append({
            'index': i,
            'name': name,
            'data_off': va_to_off(data_ptr),
            'data_len': data_len,
            'entry_off': off,
        })
    return assets


def load_dict(dict_path):
    with open(dict_path, 'r', encoding='utf-8') as f:
        d = json.load(f)
    entries = d.get('entries', [])
    entries.sort(key=lambda x: -len(x[0]))
    return entries


# 键盘键名等高风险词
KEY_NAME_BLACKLIST = {
    'Delete', 'Escape', 'Enter', 'Backspace', 'Tab', 'Home', 'End', 'Back',
    'Space', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'PageUp',
    'PageDown', 'Insert', 'Shift', 'Control', 'Alt', 'Meta', 'CapsLock',
}


# ---------------------------------------------------------------------------
# 库哨兵拆字（DEFANG）
# ---------------------------------------------------------------------------
# 某些被压缩进 bundle 的库 helper 会把"UI 文案"当运行时哨兵值使用，例如 Babel 的
# _unsupportedIterableToArray 里用反引号包裹的 Arguments 字面量来识别 arguments /
# TypedArray。直接汉化这个 token 会让 helper 失配 → 解构报错。
# 因此在替换前先把哨兵字面量"拆字"成等价的字符串拼接（运行期值完全不变），
# 这样 UI 上的 Arguments 标签就能安全汉化。
DEFANG_PATTERNS = [
    ('===`Arguments`||', '===`Argumen`+`ts`||'),
]


def apply_defang(text):
    """把库哨兵字面量拆字，返回 (新文本, 命中数)"""
    n = 0
    for old, new in DEFANG_PATTERNS:
        c = text.count(old)
        if c:
            text = text.replace(old, new)
            n += c
    return text, n


# ---------------------------------------------------------------------------
# 锚定替换（ANCHORED）
# ---------------------------------------------------------------------------
# 某些短词（plugins / skills / extensions / connectors / canvas extensions ...）在
# router 里同时充当路由 path、switch case、Set 成员、分类字段（category:/searchLabel:）
# 等标识符 —— 一旦整体汉化，路由跳转、过滤、枚举匹配全部失配。词典里因此不能收录
# 这些裸词。但它们唯一作为"显示文案"的地方是配置对象里的 emptyLabel 字段
# （用于拼 "You don't have any X installed." 空状态文案）。
# 这里用带上下文的锚点做精确替换：只改文案那一处，标识符原样保留。
ANCHORED_PATTERNS = [
    # --- Round 26: 空状态 emptyLabel（同名短词还兼作路由/枚举标识符） ---
    ('emptyLabel:`plugins`',           'emptyLabel:`插件`'),
    ('emptyLabel:`skills`',            'emptyLabel:`技能`'),
    ('emptyLabel:`extensions`',        'emptyLabel:`扩展`'),
    ('emptyLabel:`connectors`',        'emptyLabel:`连接器`'),
    ('emptyLabel:`canvas extensions`', 'emptyLabel:`画布扩展`'),

    # --- Round 27: 卸载/移除确认弹窗 ---
    # (a) 列表项卸载确认：模板串含 ${}，且变量里嵌了空模板 ``，无法用词典命中
    ('`Uninstall ${n?.label??``}?`', '`卸载 ${n?.label??``}？`'),
    ('`Remove ${n?.label??``}?`', '`移除 ${n?.label??``}？`'),
    ('`This will uninstall "${n?.label??``}" and remove its contributed tools and skills.`',
     '`这将卸载 "${n?.label??``}"，并移除其提供的工具与技能。`'),
    ('`This will remove "${n?.label??``}" from your configuration.`',
     '`这将从你的配置中移除 "${n?.label??``}"。`'),
    # (b) 另一处列表项卸载确认（plugin / skill 二分支）
    ('`Uninstall ${n.name}?`', '`卸载 ${n.name}？`'),
    ('`Remove ${n?.name??``}?`', '`移除 ${n?.name??``}？`'),
    ('`This will uninstall "${n.name}" and remove it from the app.`',
     '`这将卸载 "${n.name}" 并将其从应用中移除。`'),
    # (c) 插件详情页
    ('`Uninstall ${D.name}`', '`卸载 ${D.name}`'),
    ('`Update plugin ${D.name}`', '`更新插件 ${D.name}`'),
    ('`Updating… ${D.name}`', '`正在更新… ${D.name}`'),
    # (d) JSX children 数组版（标题问号也要中文化，且 `?` 太短不能进词典）
    ('[`Uninstall `,Ve,`?`]', '[`卸载 `,Ve,`？`]'),
    ('[`This will uninstall “`,P?.label,`” and remove it from the app.`]',
     '[`这将卸载 “`,P?.label,`” 并将其从应用中移除。`]'),
    ('[`Remove `,e.name,`?`]', '[`移除 `,e.name,`？`]'),
    # (e) 纯文本描述
    ('`This will uninstall the plugin and remove its contributed skills and MCP servers.`',
     '`这将卸载该插件，并移除其提供的技能与 MCP 服务器。`'),
    ('`This will remove the personal skill and its files. You can add it back later.`',
     '`这将移除该个人技能及其文件。你可以稍后重新添加。`'),
    # (f) 按钮状态 / 操作
    ('`Removing skill.`', '`正在移除技能。`'),
    ('`Loading skill.`', '`正在加载技能。`'),
    ('`Couldn’t load skill.`', '`无法加载技能。`'),
    ('`Update plugin`', '`更新插件`'),
    ('`Updating…`', '`正在更新…`'),
    ('`Removing…`', '`正在移除…`'),
    ('`Remove from queue`', '`从队列中移除`'),

    # --- Round 28: 错误详情弹窗（Error details）---
    # 模板串：含 ${}，直接写全字面量最直观可控
    ('`Complete diagnostic output for error: ${h}`', '`完整诊断输出（错误：${h}）`'),
    ('`Copy error: ${v}`', '`复制错误：${v}`'),
    ('`Copy error for ${C}`', '`复制 ${C} 的错误`'),

    # --- Round 29: 连接测试（Test connection）/ 主机注册 ---
    # 带 ${} 的模板串
    ('`Test, ${n.label}`', '`测试 ${n.label}`'),
    ('`Testing connection, ${n.name}`', '`正在测试连接 ${n.name}`'),
    ('`Test failed. ${e.message}`', '`测试失败。${e.message}`'),
    # 复数单词 session/sessions 是代码标识符（router 内 84 处），不能进词典；
    # 改中文后无复数变化，直接删掉 ${t} 插值（t 变量仍被赋值但不再使用，无副作用）
    ('`Connected. Protocol version ${e.protocolVersion}. ${e.activeSessions} active ${t}.`',
     '`已连接。协议版本 ${e.protocolVersion}。${e.activeSessions} 个活动会话。`'),
    ('`Connected, ${r}`', '`已连接，${r}`'),
    ('`${t.label.trim()} saved.`', '`${t.label.trim()} 已保存。`'),
    # JSX children 数组片段（中间夹 <code>remote_host</code> 元素）
    ('`Testing is disabled while the `', '`当 `'),
    ('` flag is off.`', '` 功能标志关闭时，测试不可用。`'),
    # --- Round 30: 环境诊断面板 / SSH 目的地 ---
    # 可见性 value：`${visibilityState} · focused` / ` · not focused`
    ('` · focused`', '` · 已聚焦`'),
    ('` · not focused`', '` · 未聚焦`'),
    # SSH 目的地说明是 JSX children 数组，按片段译（保持 children 顺序）
    ('`Connect a Linux, macOS, or Windows machine using an alias from`',
     '`连接 Linux、macOS 或 Windows 机器，使用别名 `'),
    ('`or a destination such as`', '`，或直接指定目标 `'),
    # copilotd 不兼容错误（模板串，含转义反引号 \`${t}\`）
    ('`The installed copilotd on \\`${t}\\` is incompatible. Try adding the host again to update copilotd automatically.`',
     '`\\`${t}\\` 上安装的 copilotd 不兼容。请重新添加该主机以自动更新 copilotd。`'),

    # --- Round 32: 议题/拉取请求页的快捷视图 section 名 ---
    # 裸词 `Created` 在表头/排序/筛选里都应译为"创建时间"（已进词典），
    # 但这里它是"我创建的"这一视图名，语义不同，用锚点先改掉。
    # 两条：英文原文形态（首次汉化）+ 已误译形态（修正在此之前被词典翻译过的实例）
    ('{id:`created`,name:`Created`,query:`state:open author:@me`,collapsed:!1}',
     '{id:`created`,name:`我创建的`,query:`state:open author:@me`,collapsed:!1}'),
    ('{id:`created`,name:`创建时间`,query:`state:open author:@me`,collapsed:!1}',
     '{id:`created`,name:`我创建的`,query:`state:open author:@me`,collapsed:!1}'),

    # --- Round 35: 「我的工作」筛选器（Filter picker / chip / operator / 空态）---
    # 筛选字段登记表 z_i（及子字段表 H_i）里的 label 是**裸单英文词**，与代码里的
    # 同名标识符无法用词典区分（如 `State` 在 mermaid 是图表类型、`Is` 在 dist-* 是
    # HTML 词法 token），因此这里一律用 `id:{label:\`X\`,` 形态的锚点，精确到登记表。
    # 注意：label 后面跟的是 `,description:` 或 `,icon:`，所以锚点以逗号结尾（带 } 会失配）。
    ('is:{label:`Is`,', 'is:{label:`是`,'),
    ('state:{label:`State`,description:`Filter by open/closed`',
     'state:{label:`状态`,description:`按开启/关闭状态筛选`'),
    ('label:{label:`Label`,', 'label:{label:`标签`,'),
    ('author:{label:`Author`,', 'author:{label:`作者`,'),
    ('assignee:{label:`Assignee`,', 'assignee:{label:`负责人`,'),
    ('mentions:{label:`Mentions`,', 'mentions:{label:`提及`,'),
    ('involves:{label:`Involves`,', 'involves:{label:`涉及`,'),
    ('commenter:{label:`Commenter`,', 'commenter:{label:`评论者`,'),
    ('milestone:{label:`Milestone`,', 'milestone:{label:`里程碑`,'),
    ('type:{label:`Type`,', 'type:{label:`类型`,'),
    ('linked:{label:`Linked`,description:`Filter by linked PR/issue`',
     'linked:{label:`已关联`,description:`按关联的 PR/议题筛选`'),
    ('project:{label:`Project`,', 'project:{label:`项目`,'),
    ('updated:{label:`Updated`,', 'updated:{label:`已更新`,'),
    ('review:{label:`Review`,', 'review:{label:`审阅`,'),
    ('base:{label:`Base`,', 'base:{label:`基准`,'),
    ('head:{label:`Head`,', 'head:{label:`头部`,'),
    ('has:{label:`Has`,', 'has:{label:`包含`,'),
    ('in:{label:`In`,description:`Search in title/body/comments`',
     'in:{label:`位于`,description:`在标题/正文/评论中搜索`'),
    ('reason:{label:`Reason`,', 'reason:{label:`原因`,'),
    ('"sub-issue":{label:`Sub-issue`,', '"sub-issue":{label:`子议题`,'),
    # 操作符 is / is not：注意底层 value 是 included/excluded（不是 is），
    # 所以只改显示文案，筛选语义不受影响。
    ('?`is not`:`is`}', '?`不是`:`是`}'),
    ('value:`included`,children:`is`}', 'value:`included`,children:`是`}'),
    ('value:`excluded`,children:`is not`}', 'value:`excluded`,children:`不是`}'),
    ('!1),children:`is`}', '!1),children:`是`}'),
    ('!0),children:`is not`}', '!0),children:`不是`}'),
    # 空态：No items match "${ft.name}".  —— 含 ${} 的模板串，保留插值原样
    ('`No items match "${ft.name}".`', '`没有匹配"${ft.name}"的项目。`'),

    # --- Round 35b: 筛选器条目的**真实**登记表 Ryi()（type:`id`,label:`X`）---
    # 上一段 z_i 是字段元数据（工具提示/二级面板），这一段才是"添加过滤器"弹层里
    # 真正渲染的条目名。两处都要改，否则 chip 与弹层会不一致。
    # 已译的（合并状态/请求了审阅/由…审阅/已请求用户审阅/CI 状态/关闭原因/创建时间/
    # 评论/否/仓库）不在下表。
    ('type:`state`,label:`State`', 'type:`state`,label:`状态`'),
    ('type:`type`,label:`Is`', 'type:`type`,label:`是`'),
    ('type:`label`,label:`Label`', 'type:`label`,label:`标签`'),
    ('type:`issue-type`,label:`Type`', 'type:`issue-type`,label:`类型`'),
    ('type:`author`,label:`Author`', 'type:`author`,label:`作者`'),
    ('type:`assignee`,label:`Assignee`', 'type:`assignee`,label:`负责人`'),
    ('type:`involves`,label:`Involves`', 'type:`involves`,label:`涉及`'),
    ('type:`commenter`,label:`Commenter`', 'type:`commenter`,label:`评论者`'),
    ('type:`mentions`,label:`Mentions`', 'type:`mentions`,label:`提及`'),
    ('type:`milestone`,label:`Milestone`', 'type:`milestone`,label:`里程碑`'),
    ('type:`project`,label:`Project`', 'type:`project`,label:`项目`'),
    ('type:`review`,label:`Review`', 'type:`review`,label:`审阅`'),
    ('type:`linked`,label:`Linked`', 'type:`linked`,label:`已关联`'),
    ('type:`base`,label:`Base`', 'type:`base`,label:`基准`'),
    ('type:`head`,label:`Head`', 'type:`head`,label:`头部`'),
    ('type:`updated`,label:`Updated`', 'type:`updated`,label:`已更新`'),
    ('type:`has`,label:`Has`', 'type:`has`,label:`包含`'),

    # --- Round 36: 项目设置页「移除 X」按钮/aria-label（通用模板，变量名逐个锚定）---
    # `Remove ${x}` 出现 4 次（不同压缩变量名），语义都是"移除 <对象>"，可安全译。
    ('`Remove ${r}`', '`移除 ${r}`'),
    ('`Remove ${n}`', '`移除 ${n}`'),
    ('`Remove ${s}`', '`移除 ${s}`'),
    ('`Remove ${i}`', '`移除 ${i}`'),
    ('`Remove session ${n}`', '`移除会话 ${n}`'),

    # ================= Round 37: 筛选器误译修正 + 漏译选项补齐 =================
    # 背景：核对「添加筛选条件」下拉（z_i / Ryi() 两套登记表 + 选项数组）后发现
    #   1) 5 处语义误译   2) 7 处选项漏译   3) 2 处生硬翻译   4) 2 处同义不一致
    # 注意：本区块的 (a) 组是"已误译形态 → 正确形态"的中→中修正，与更早轮次的
    # "英文原文形态"锚点并存 —— 前者修当前已打补丁的构建，后者保证从旧备份重打也行。

    # (a) 修正既有误译
    #  no: 的含义是"缺少某字段"，不是回答是否的"否"；它自己的 description 就写着
    #  "筛选缺少某字段的条目"。译为"否"会与表单里的"无标签/无里程碑"自相矛盾。
    ('no:{label:`否`,', 'no:{label:`无`,'),
    #  has/no 子选择器的内联标题 —— 这是**第三处**硬编码登记表（既不在 z_i 也不在
    #  Ryi()），原先 has 分支漏译成 `Has`、no 分支误译成"否"，同一表达式里中英混排。
    ('label:e===`has`?`Has`:`否`', 'label:e===`has`?`包含`:`无`'),
    #  base/head 是 git 分支概念；description 里本就写着"按…分支筛选"，标签不能丢"分支"。
    #  "头部"在中文第一反应是"头"，属误译。
    ('base:{label:`基准`,description:`按基线分支筛选', 'base:{label:`基础分支`,description:`按基础分支筛选'),
    ('type:`base`,label:`基准`', 'type:`base`,label:`基础分支`'),
    ('head:{label:`头部`,description:`按头部分支筛选', 'head:{label:`头部分支`,description:`按头部分支筛选'),
    ('type:`head`,label:`头部`', 'type:`head`,label:`头部分支`'),
    #  in: 是搜索范围限定符（in:title / in:body / in:comments），不是"物理位于"。
    #  ⚠ 不能全局替换"位于"：router 里另有一处 YAML 解析错误文案
    #  "流序列对的隐式键必须位于单行"必须保留原样，所以只锚定登记表这一处。
    ('in:{label:`位于`,', 'in:{label:`在…中`,'),
    #  is: 是搜索限定符；单字"是"会被读成布尔值，且与相邻的 no:"否"形成一对假布尔开关。
    ('is:{label:`是`,', 'is:{label:`属于`,'),
    ('type:`type`,label:`是`', 'type:`type`,label:`属于`'),
    #  审阅类：去掉生硬的"了"字；user-review-requested 是"请求**指定用户**审阅"
    #  （对应 review-requested:用户名），原译读起来像"请求用户去审阅"。
    ('`请求了审阅`', '`已请求审阅`'),
    ('`已请求用户审阅`', '`已请求指定用户审阅`'),
    ('description:`按用户审阅请求筛选`', 'description:`按指定用户审阅请求筛选`'),
    #  同一筛选在 z_i 与 Ryi() 里叫法不一致，统一为下拉里那一套。
    ('reason:{label:`原因`,', 'reason:{label:`关闭原因`,'),
    ('status:{label:`状态`,', 'status:{label:`CI 状态`,'),

    # (b) 补齐选项数组漏译（{value:X,label:Y} —— 同一数组里其余项早已是中文）
    ('{value:`unmerged`,label:`Unmerged`', '{value:`unmerged`,label:`未合并`'),
    ('{value:`queued`,label:`Queued`', '{value:`queued`,label:`已排队`'),
    ('{value:`required`,label:`Required`', '{value:`required`,label:`需要审阅`'),
    ('{value:`approved`,label:`Approved`', '{value:`approved`,label:`已批准`'),
    ('{value:`failure`,label:`Failure`', '{value:`failure`,label:`失败`'),
    ('Me=`Any`', 'Me=`任意`'),
    #  Required 在表单里是"必填"徽章，与审阅筛选的 Required 同词不同义，分开锚定
    ('children:`Required`', 'children:`必填`'),
    #  is: / PR 状态里的 Queued、Closed（router；比较用的是小写 `queued`/`closed`，
    #  大写形态纯属展示文案）
    ('e.state===`queued`?`Queued`', 'e.state===`queued`?`已排队`'),
    ('l===`queued`?`Queued`', 'l===`queued`?`已排队`'),
    ('{label:`Queued`,icon:', '{label:`已排队`,icon:'),
    ('{label:`Queued`,tone:`attention`}', '{label:`已排队`,tone:`attention`}'),
    ('children:Ht?`Queued`:', 'children:Ht?`已排队`:'),
    ('`queued`:return{label:`Queued`', '`queued`:return{label:`已排队`'),
    ('e.state===`closed`?`Closed`', 'e.state===`closed`?`已关闭`'),
    ('l===`closed`?`Closed`', 'l===`closed`?`已关闭`'),
    ('{label:`Closed`,tone:`danger`}', '{label:`已关闭`,tone:`danger`}'),
    ('[`closed`,`Closed`]', '[`closed`,`已关闭`]'),
    #  刻意不用宽泛的 `return\`Closed\``（那样一次覆盖 4 处，但"函数返回 Closed"
    #  这种形态将来可能是返回状态键而不是文案）——逐个锚定具体返回点
    ('if(!e)return`Closed`;', 'if(!e)return`已关闭`;'),
    ('Number.isNaN(t.getTime()))return`Closed`;', 'Number.isNaN(t.getTime()))return`已关闭`;'),
    ('`Closed ${Mt(n)??n}`', '`已关闭 ${Mt(n)??n}`'),
    ('{value:`closed`,label:`Closed`', '{value:`closed`,label:`已关闭`'),
    ('{label:`Approved`', '{label:`已批准`'),
    ('`正在批准`:`Approved`', '`正在批准`:`已批准`'),
    ('{approved:`Approved`', '{approved:`已批准`'),
    #  ⚠ 绝不全局替换 Closed：vendor-mermaid 里 `e[e.Closed=1]=`Closed`` 是 TS 枚举
    #    反向映射，改了会破坏解析。上面的锚点都带 `{value:` / `{label:` / return 前缀，
    #    不会命中枚举形态。
    #  状态用词统一：同一"open"在筛选器与表单里分别是"打开"和"开启"
    ('{value:`open`,label:`打开`', '{value:`open`,label:`开启`'),
    ('[`open`,`打开`]', '[`open`,`开启`]'),
    #  顺带补一处：iki 映射里 sessions 分支的 label 仍是 Project，而姊妹分支已是"无项目"
    ('{...e,label:`Project`}', '{...e,label:`项目`}'),

    # (c) telemetry 的状态徽章（姊妹项 未计划/草稿/已合并 早已是中文）
    ('bg-attention-emphasis`,label:`Queued`', 'bg-attention-emphasis`,label:`已排队`'),
    ('`pr-queued`:return`Queued`', '`pr-queued`:return`已排队`'),
    ('`queued`:return`Queued`', '`queued`:return`已排队`'),
    (',label:`Closed`}', ',label:`已关闭`}'),
    ('`closed`:return`Closed`', '`closed`:return`已关闭`'),
    ('default:return`Closed`', 'default:return`已关闭`'),
    ('`issue-duplicate`:return`Duplicate`', '`issue-duplicate`:return`重复`'),

    # (d) 干跑时顺带扫出的同类漏译：全部是 {value:X,label:Y} 选项，
    #     同一数组里其余项早已是中文（因此"漏译"可由姊妹项直接证明）。
    #     语言/格式名（JavaScript / TypeScript / TSX / CSS / JSON / Bash / Python /
    #     Ruby / Go / Rust / SQL / YAML / Markdown / Diff 等）是专名，**保持英文**。
    # 日期筛选运算符（点开"创建时间"就会出现）
    ('{value:`after`,label:`is after`', '{value:`after`,label:`晚于`'),
    ('{value:`onOrAfter`,label:`is on or after`', '{value:`onOrAfter`,label:`不早于`'),
    ('{value:`before`,label:`is before`', '{value:`before`,label:`早于`'),
    ('{value:`onOrBefore`,label:`is on or before`', '{value:`onOrBefore`,label:`不晚于`'),
    ('{value:`on`,label:`is on`', '{value:`on`,label:`等于`'),
    ('{value:`between`,label:`is between`', '{value:`between`,label:`介于`'),
    # 数值比较运算符（姊妹项：大于 / 小于）
    ('{value:`gte`,label:`is at least`', '{value:`gte`,label:`不小于`'),
    ('{value:`lte`,label:`is at most`', '{value:`lte`,label:`不大于`'),
    ('{value:`eq`,label:`is exactly`', '{value:`eq`,label:`等于`'),
    # 画布批注工具
    ('{value:`arrow`,label:`Arrow`', '{value:`arrow`,label:`箭头`'),
    ('{value:`rectangle`,label:`Rectangle`', '{value:`rectangle`,label:`矩形`'),
    ('{value:`pencil`,label:`Pencil`', '{value:`pencil`,label:`铅笔`'),
    ('{value:`comment`,label:`Comment`', '{value:`comment`,label:`评论`'),
    # 会话类型 / 列表（姊妹项：本地 / 新建工作树 / 会话 / 议题 …）
    ('{value:`worktree`,label:`Worktree`', '{value:`worktree`,label:`工作树`'),
    ('{value:`cloud`,label:`Cloud`', '{value:`cloud`,label:`云端`'),
    (',cloud:`Cloud`}', ',cloud:`云端`}'),
    #  Chat 是"快速聊天"动作的显示名，共 6 处（含 quickChat / action-new-chat /
    #  __no_project__ 等不同容器），value 侧全是内部键，label 侧一律可译
    ('label:`Chat`', 'label:`聊天`'),
    ('{value:`chats`,label:`Chats`', '{value:`chats`,label:`聊天`'),
    ('{value:`archived`,label:`Archived`', '{value:`archived`,label:`已归档`'),
    ('{value:`waiting`,label:`Waiting`', '{value:`waiting`,label:`等待中`'),
    ('{value:`link`,label:`Link`', '{value:`link`,label:`链接`'),
    ('{value:`artifacts`,label:`Artifacts`', '{value:`artifacts`,label:`产物`'),
    ('{value:`export`,label:`View only`', '{value:`export`,label:`仅查看`'),
    ('{value:`cloud-family:workflow`,label:`Workflow`', '{value:`cloud-family:workflow`,label:`工作流`'),
    # 满足度 / 优先级（姊妹项：部分满足 / 未满足）
    ('{value:`met`,label:`Met`', '{value:`met`,label:`满足`'),
    ('{value:`unverifiable`,label:`Unverifiable`', '{value:`unverifiable`,label:`无法验证`'),
    ('{value:`high`,label:`High`', '{value:`high`,label:`高`'),
    ('{value:`medium`,label:`Medium`', '{value:`medium`,label:`中`'),
    ('{value:`low`,label:`Low`', '{value:`low`,label:`低`'),
    # 主题配色（姊妹项：色盲友好 / 高对比度）
    # ⚠ 颜色锚点必须连写相邻项，否则会命中 WordEditor 里同样形态的高亮色板
    #   （那是独立的一大块未译区：No color / Bright green / Turquoise / Dark blue
    #    + 对齐 Align left / 加粗 Bold 等整个格式工具栏，留待后续轮次整块处理）。
    ('{value:`neutral`,label:`Neutral`', '{value:`neutral`,label:`中性`'),
    ('{value:`green`,label:`Green`},{value:`blue`,label:`Blue`}',
     '{value:`green`,label:`绿色`},{value:`blue`,label:`蓝色`}'),
    ('{value:`violet`,label:`Violet`},{value:`pink`,label:`Pink`}',
     '{value:`violet`,label:`紫色`},{value:`pink`,label:`粉色`}'),
    ('{value:`red`,label:`Red`},{value:`orange`,label:`Orange`}',
     '{value:`red`,label:`红色`},{value:`orange`,label:`橙色`}'),
    # yellow 是该配色数组的最后一项，用 `}]` 收尾即可限定在 router
    # （WordEditor 的同名项后面跟的是 `,{value:`green`,`label:`Bright green`}`）
    ('{value:`yellow`,label:`Yellow`}]', '{value:`yellow`,label:`黄色`}]'),
    ('{value:`dim`,label:`Dim`', '{value:`dim`,label:`暗色`'),
    ('{value:`colorblind`,label:`Colorblind`', '{value:`colorblind`,label:`色盲友好`'),

    # ================= Round 38: 议题/PR 状态徽章 + 进程/事件表头漏译补齐 =================
    # 背景：体检扫出 4 个残留英文选项 label（Duplicate / Issue created / Outdated /
    #   Resolved）及同批裸词（Investigating / Answered / Staged / Unanswered / State /
    #   Reason / Operation / Attempts / Role / CWD / PID / Comment / Surface / Result /
    #   Time / Latency）。这些是短词或裸字面量，直接进词典会命中代码标识符
    #   （switch case、路由 path、枚举反查、字段名），故一律用带上下文的锚点。
    # ⚠ Issue created 特殊：它在 router 的 zRi() 里被 `e.label===`Issue created`` 做
    #   等值比较（label 值即运行期数据），且 telemetry 的 YAe Map / n.push 里的
    #   `Issue created` 正是该 label 的值来源 —— 这些**保持英文**，否则自动化触发器
    #   类型判定会失配。只译 router 里纯显示的 `children:`Issue created`` 一处。

    # (a) AXr() 议题/PR 状态 switch（router）—— 姊妹项 `error`→`错误`、`default`→`待处理`
    #     早已是中文，这里的英文 return 是漏译。整条 switch 一次锚定，最稳。
    ('switch(e.status){case`investigating`:return`Investigating`;case`answered`:return`Answered`;case`error`:return`错误`;case`resolved`:return`Resolved`;case`staged`:return`Staged`;case`outdated`:return`Outdated`;default:return`待处理`}',
     'switch(e.status){case`investigating`:return`调查中`;case`answered`:return`已答复`;case`error`:return`错误`;case`resolved`:return`已解决`;case`staged`:return`已暂存`;case`outdated`:return`已过时`;default:return`待处理`}'),
    # AXr 的 Unanswered 早退分支（与上面同函数，另一个 token）
    ('if(kXr(e))return`Unanswered`;switch(e.status)', 'if(kXr(e))return`未答复`;switch(e.status)'),

    # (b) 议题状态标签 stateLabel 三元（router；姊妹项 not_planned→未计划）
    ('i.state===`duplicate`?`Duplicate`:void 0', 'i.state===`duplicate`?`重复`:void 0'),

    # (c) issue 详情页「复制」菜单动作（router；Km 是复制图标，语义是 copy 不是 duplicate）
    ('(0,$.jsx)(ej.Title,{children:`Duplicate`})', '(0,$.jsx)(ej.Title,{children:`复制`})'),

    # (d) 审查评论的「已过时 / 已解决」徽章（router；bO variant=attention / span text-done）
    ('bO,{variant:`attention`,children:`Outdated`}', 'bO,{variant:`attention`,children:`已过时`}'),
    ('className:`text-body-small text-muted`,children:`Resolved`',
     'className:`text-body-small text-muted`,children:`已解决`'),
    ('(0,$.jsx)(jJ,{align:`right`,children:`Resolved`})', '(0,$.jsx)(jJ,{align:`right`,children:`已解决`})'),

    # (e) 「已创建议题」标题（router；纯显示，与 label 值无关）
    ('className:`font-medium`,children:`Issue created`', 'className:`font-medium`,children:`已创建议题`'),

    # (f) telemetry 状态徽章与筛选选项数组（姊妹项 未计划/垃圾内容/滥用/偏离主题/低质量 已是中文）
    #   TK 映射对象（EK/IWe 用它把 value 反查成显示名）
    ('var TK={OUTDATED:`Outdated`,RESOLVED:`Resolved`,OFF_TOPIC:`偏离主题`,SPAM:`垃圾内容`,ABUSE:`滥用`,DUPLICATE:`Duplicate`,LOW_QUALITY:`低质量`}',
     'var TK={OUTDATED:`已过时`,RESOLVED:`已解决`,OFF_TOPIC:`偏离主题`,SPAM:`垃圾内容`,ABUSE:`滥用`,DUPLICATE:`重复`,LOW_QUALITY:`低质量`}'),
    #   RWe 选项数组
    ('{value:`OUTDATED`,label:`Outdated`},{value:`DUPLICATE`,label:`Duplicate`},{value:`RESOLVED`,label:`Resolved`}',
     '{value:`OUTDATED`,label:`已过时`},{value:`DUPLICATE`,label:`重复`},{value:`RESOLVED`,label:`已解决`}'),
    #   duplicate 状态徽章（VBe 对象；reopened→已重新打开 已是中文）
    ('bg-neutral-emphasis`,label:`Duplicate`},reopened', 'bg-neutral-emphasis`,label:`重复`},reopened'),

    # (g) 进程/事件/诊断表头（router；全部 `children:`X`` 形态，纯显示列标题）
    ('{width:`88px`,children:`State`}', '{width:`88px`,children:`状态`}'),
    ('(0,$.jsx)(jJ,{children:`State`})', '(0,$.jsx)(jJ,{children:`状态`})'),
    ('(0,$.jsx)(jJ,{children:`Reason`})', '(0,$.jsx)(jJ,{children:`原因`})'),
    ('(0,$.jsx)(jJ,{children:`Operation`})', '(0,$.jsx)(jJ,{children:`操作`})'),
    ('(0,$.jsx)(jJ,{align:`right`,children:`Attempts`})', '(0,$.jsx)(jJ,{align:`right`,children:`尝试次数`})'),
    ('{width:`100px`,sortable:!0,sortDirection:v,onSort:y,children:`Role`}',
     '{width:`100px`,sortable:!0,sortDirection:v,onSort:y,children:`角色`}'),
    ('sortDirection:S,onSort:C,children:`CWD`}', 'sortDirection:S,onSort:C,children:`工作目录`}'),
    ('sortDirection:T,onSort:E,children:`PID`}', 'sortDirection:T,onSort:E,children:`进程号`}'),
    ('(0,$.jsx)(aQ,{children:`Comment`})', '(0,$.jsx)(aQ,{children:`评论`})'),
    ('(0,$.jsx)(jJ,{children:`Surface`})', '(0,$.jsx)(jJ,{children:`界面`})'),
    ('(0,$.jsx)(jJ,{children:`Result`})', '(0,$.jsx)(jJ,{children:`结果`})'),
    ('(0,$.jsx)(jJ,{children:`Time`})', '(0,$.jsx)(jJ,{children:`时间`})'),
    ('(0,$.jsx)(jJ,{align:`right`,children:`Latency`})', '(0,$.jsx)(jJ,{align:`right`,children:`延迟`})'),
]


def apply_anchored(text):
    """带上下文锚点的精确替换，返回 (新文本, 命中数, stats)"""
    stats = {}
    n = 0
    for old, new in ANCHORED_PATTERNS:
        c = text.count(old)
        if c:
            text = text.replace(old, new)
            stats[old] = c
            n += c
    return text, n, stats


# ---------------------------------------------------------------------------
# 按 bundle 屏蔽 token
# ---------------------------------------------------------------------------
# 同一个 token 在不同 bundle 里的角色可能完全不同：在 router 里是 UI 文案，
# 在 vendor bundle 里可能是键盘键码 / 枚举关键字。此处按 bundle 名子串精确屏蔽，
# 只保护该 bundle 里的特定 token（而不是整包跳过，其他文案仍可继续汉化）。
BUNDLE_TOKEN_BLACKLIST = {
    # xterm 键盘键名→键码映射：case`Add`:return 57413（小键盘 + 键）
    '/assets/vendor-terminal': {'Add'},
    # mermaid ArchiMate 图类型枚举：this.VerifyType={...,VERIFY_TEST:`Test`}
    # （翻译会让图表解析/渲染失配；router 里的测试按钮 label 仍可汉化）
    # Round 36 追加 Diagram：class 定义里 `static{q(this,`Diagram`)}` 是图类型**注册名**，
    # 而 router 里 `Diagram` 是显示标签（图表），故按 bundle 保护该 token。
    # Round 39 追加 Off：TS 枚举反查映射 e[e.Off=0]=`Off`，译成"关"会失配。
    '/assets/vendor-mermaid': {'Test', 'Diagram', 'Off'},
    # Round 30: elk 布局引擎(GWT 编译产物)里的字段/包名常量 tF=`Unknown`
    '/assets/vendor-elk': {'Unknown'},
    # Round 30: InvertocatCanvas 桌面宠物动画状态机 name:R.Idle / crossFadeTo(`Idle`)
    # （译了会让动画状态机找不到状态名）
    # Round 32 追加 Eyes：该 bundle 内 `Eyes` 参与等值比较（桌宠视线状态），
    # 但 telemetry 里的反应标签表 roe 仍需要翻译，故按 bundle 保护
    '/assets/InvertocatCanvas': {'Idle', 'Eyes'},
    # Round 32: telemetry 共享 chunk（其实是应用主共享包）启用后按词保护：
    #   Add        —— 差分解析器 switch(e){case`Add`:return`add`}（匹配 *** Add File:）
    #   Default    —— TS 枚举反查映射 e[e.Default=3]=`Default`
    #   None       —— 同上 e[e.None=0]=`None`
    #   Private    —— 同上 e[e.Private=0]=`Private`
    #   Public     —— 同上 e[e.Public=1]=`Public`
    #   Local      —— 特性开关调用 V(`Local`)，译后该分组会消失
    #   just now   —— AV() 时间解析器里做等值比较 t===`just now`
    #   Quick chats—— 持久化分组迁移判断 e===`Quick chats`?`__quick-chats__`:e
    '/assets/telemetry': {'Add', 'Default', 'None', 'Private', 'Public', 'Local',
                          'just now', 'Quick chats'},
    # Round 32: Univer 表格内核里 Sort 同时出现在 TS 枚举反查映射
    # （e[e.Sort=17]=`Sort`）与动作名映射（[$t.Sort]:`Sort`）中，译了会让
    # 反查表取到的动作名与注册名失配，故保护该 bundle 内的 Sort
    # Round 39 追加：原版校对发现 Univer 的 protobuf 枚举反查映射被误译
    #   （e[e.Edit=1]=`编辑` / e[e.Copy=6]=`复制` / e[e.Export=8]=`导出` /
    #    e[e.Owner=2]=`所有者` / e[e.Keyboard=4]=`键盘` / e[e.Custom=16]=`自定义`）。
    #   这些反查字符串若用于序列化/跨模块匹配会失配，故按 bundle 保护英文原词。
    '/assets/UniverWorkbookCanvas': {'Sort', 'Edit', 'Copy', 'Export', 'Owner',
                                     'Keyboard', 'Custom'},
    # Round 39: syntax.worker（Monaco 语法高亮 worker）里的 TS 枚举反查映射
    #   e[e.None=0]=`None` 被误译成"无"，若用于反查/序列化会失配，故保护。
    '/assets/syntax.worker': {'None'},
}


def apply_replacements(text, entries, bundle_name=''):
    """对文本做反引号包裹的精准替换,跳过键名黑名单与 bundle 级 token 屏蔽"""
    skipped = {}
    stats = {}
    total = 0

    blocked = set()
    for pat, toks in BUNDLE_TOKEN_BLACKLIST.items():
        if pat in bundle_name:
            blocked |= toks

    for en, zh in entries:
        if en in KEY_NAME_BLACKLIST or en in blocked:
            skipped[en] = True
            continue
        if en == zh:
            # en==zh 是"显式标记为不翻译"的占位条目（如 GitHub.com），
            # 替换是无操作，直接跳过以免无意义地重压缩整个 bundle
            skipped[en] = True
            continue
        pat = '`' + en + '`'
        cnt = text.count(pat)
        if cnt:
            text = text.replace(pat, '`' + zh + '`')
            stats[en] = cnt
            total += cnt
    return text, stats, total, skipped


def try_decompress_brotli(raw):
    """探测能否 brotli 解压"""
    try:
        return brotli.decompress(raw).decode('utf-8', 'replace')
    except Exception:
        return None


def enumerate_all_data_regions(data):
    """枚举 asset 表里所有 entry 的 data 区（含非 .js 资源），
    返回按 data_off 排序的 [(data_off, data_len, name)]。
    用于计算某个 bundle 后面到下一个资源之间有多少可用 gap。
    """
    regions = []
    for i in range(MAX_ENTRY):
        off = ENTRY_START + i * 0x20
        if off + 0x20 > len(data):
            break
        name_ptr = struct.unpack('<Q', data[off:off+8])[0]
        name_len = struct.unpack('<Q', data[off+8:off+16])[0]
        data_ptr = struct.unpack('<Q', data[off+16:off+24])[0]
        data_len = struct.unpack('<Q', data[off+24:off+32])[0]
        if name_ptr == 0 or name_len == 0 or name_len > 500 or data_ptr == 0:
            continue
        try:
            name = data[va_to_off(name_ptr):va_to_off(name_ptr)+name_len].decode()
        except Exception:
            name = '<bad name>'
        d_off = va_to_off(data_ptr)
        if d_off <= 0 or d_off >= len(data):
            continue
        regions.append((d_off, data_len, name))
    regions.sort(key=lambda x: x[0])
    return regions


def enumerate_all_resource_boundaries(data):
    """枚举 asset 表里所有 entry 的关键文件偏移边界，
    返回按 off 排序的 [(off, kind)] 列表。
    kind ∈ {'name_start', 'name_end', 'data_start', 'data_end'}。

    Tauri 资源在文件里的实际布局：
      [prev_data_end ... cur_name ... cur_name_end ... cur_data ... cur_data_end ... next_name ... ]
    每个 entry 的 name 区紧贴在它自己的 data 区之前（name_off < data_off）。

    因此一个 entry 的"前面可借用范围"是 [prev_data_end, cur_name_off)，
    而它的"后面可拓展上限"是 min(下一个 entry 的 name_off, 自己 data 区起点最远点)。
    """
    points = []
    for i in range(MAX_ENTRY):
        off = ENTRY_START + i * 0x20
        if off + 0x20 > len(data):
            break
        name_ptr = struct.unpack('<Q', data[off:off+8])[0]
        name_len = struct.unpack('<Q', data[off+8:off+16])[0]
        data_ptr = struct.unpack('<Q', data[off+16:off+24])[0]
        data_len = struct.unpack('<Q', data[off+24:off+32])[0]
        if name_ptr == 0 or name_len == 0 or name_len > 500 or data_ptr == 0:
            continue
        n_off = va_to_off(name_ptr)
        d_off = va_to_off(data_ptr)
        if d_off <= 0 or d_off >= len(data) or n_off <= 0 or n_off >= len(data):
            continue
        points.append((n_off, 'name_start'))
        points.append((n_off + name_len, 'name_end'))
        points.append((d_off, 'data_start'))
        points.append((d_off + data_len, 'data_end'))
    return points


def find_extendable_limit(data, data_off, data_len):
    """返回某个数据块后面可安全拓展到的文件偏移上限。
    实际取下一个资源 entry 的 name_off（而不是下一个 data_off），
    因为 Tauri 把 entry 的 name 区物理上放在 data 区之前，紧贴前一个 entry 的 data 末尾。

    修复历史：原版用 data_off 排序，会忽略 name 区。当 router.js 借 gap 时，
    会把下一个 entry（idx64 svg）的 name 区一并写入压缩流，导致 name 被清零。
    """
    points = enumerate_all_resource_boundaries(data)
    # 关键修复：下一个 entry 的 name 区起点可能正好等于 cur_end（紧贴场景）,
    # 这种情况下不能拓展，否则会覆盖 name 区第一字节。所以用 >= 而不是 >。
    # kind 仅考虑 start（name_start/data_start）；end 点是同一 entry 自己的，cur_end 已超过它，不会被踩。
    cur_end = data_off + data_len
    candidates = [off for off, kind in points if off >= cur_end and kind in ('name_start', 'data_start')]
    limit = cur_end
    if candidates:
        limit = min(candidates)
    return limit


def compress_to_fit(text_bytes, orig_len, max_extend=0):
    """逐级 quality 压缩,直到 ≤ orig_len + max_extend;否则返回 None。
    若 max_extend > 0，允许压缩结果比原数据长，但不超过扩展上限。
    """
    budget = orig_len + max_extend
    for q in [11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]:
        c = brotli.compress(text_bytes, quality=q)
        if len(c) <= budget:
            return c, q
    return None, None


def backup_path(exe_path):
    """备份文件名带 App 版本号，避免新版覆盖旧版备份。
    例：github.exe.1.1.21.bak
    """
    ver = get_file_version(exe_path)
    if ver:
        return '%s.%s.bak' % (exe_path, ver)
    return exe_path + '.bak'


def patch(exe_path, dict_path, backup=True):
    if not os.path.exists(exe_path):
        print(f'[!] 未找到目标文件: {exe_path}')
        sys.exit(1)

    data = bytearray(open(exe_path, 'rb').read())
    ver = get_file_version(exe_path)
    print(f'[+] 目标: {exe_path}')
    print(f'[+] App 版本: {ver or "未知"}')

    # 提前检查写入权限：Copilot 运行中会锁住 exe，
    # 这里先探一次，避免压缩跑完几分钟才在最后写入时失败。
    try:
        _probe = open(exe_path, 'r+b')
        _probe.close()
    except PermissionError:
        print('[!] 无法写入目标文件（被占用或权限不足）: %s' % exe_path)
        print('    请先【完全退出 GitHub Copilot】：')
        print('      1) 关闭主窗口')
        print('      2) 右下角托盘图标右键 -> 退出')
        print('    然后重新运行本工具。')
        sys.exit(3)
    except Exception as e:
        print('[!] 打开目标文件失败: %s' % e)
        sys.exit(3)

    # 关键：先按 PE 头动态解析资源布局（版本升级后常量会失效）
    if detect_layout(data, exe_path) is None:
        print('[!] 无法定位资源表，汉化中止（未做任何修改）。')
        print('    说明：该 App 版本可能改动了 PE 结构，需要适配后才能汉化。')
        sys.exit(2)

    assets = load_assets(data)
    print(f'[+] 找到 {len(assets)} 个待处理 JS bundle')
    if not assets:
        print('[!] 枚举到 0 个 JS bundle，汉化中止（未做任何修改）。')
        print('    通常是 App 已更新、资源表布局变化导致定位失败。')
        sys.exit(2)

    entries = load_dict(dict_path)
    print(f'[+] 加载词典 {len(entries)} 条')

    skip_black = {}
    modified_bundles = 0
    total_replacements = 0
    stats_per_bundle = {}
    defang_hits = 0
    anchor_hits = 0

    for asset in assets:
        a = asset
        raw = bytes(data[a['data_off']:a['data_off']+a['data_len']])

        js_text = try_decompress_brotli(raw)
        if js_text is None:
            continue  # 不是 brotli 压缩
        if len(js_text) < 100:
            continue

        # 先把库哨兵字面量拆字（运行期等价），避免它们被当 UI 文案替换
        js_text, df = apply_defang(js_text)
        defang_hits += df

        # 锚定替换：只改 emptyLabel 文案，同名标识符（path/case/category）保持原样
        js_text, ah, astats = apply_anchored(js_text)
        anchor_hits += ah

        new_text, stats, total, skipped = apply_replacements(js_text, entries, a['name'])
        skip_black.update(skipped)
        if astats:
            stats = dict(stats)
            for k, v in astats.items():
                stats[k] = stats.get(k, 0) + v
            total += ah
        if not total and not df:
            continue  # 本 bundle 既无可替换文案、也无需拆字/锚定

        new_bytes = new_text.encode('utf-8')
        orig_len = a['data_len']

        # 计算可拓展上限（借 gap）
        limit = find_extendable_limit(data, a['data_off'], orig_len)
        max_extend = max(0, limit - (a['data_off'] + orig_len))
        # 留 4 字节安全边际
        if max_extend > 4:
            max_extend -= 4
        else:
            max_extend = 0

        compressed, q = compress_to_fit(new_bytes, orig_len, max_extend)
        if compressed is None:
            print(f'  [{a["index"]:4d}] {a["name"]!r} - SKIP: 压缩后仍比可用空间大 (原 {orig_len} B + 可拓展 {max_extend} B),词典太长')
            continue

        new_len = len(compressed)

        # 回写
        off = a['data_off']
        if new_len <= orig_len:
            # 正常情况：塞进原空间，用 0 填充
            data[off:off+orig_len] = compressed + b'\x00' * (orig_len - new_len)
        else:
            # 借 gap 拓展：覆盖原空间 + 把溢出部分写入 gap，并把拓展区到 limit 之间清零
            data[off:off+new_len] = compressed
            data[off+new_len:limit] = b'\x00' * (limit - (off + new_len))

        struct.pack_into('<Q', data, a['entry_off'] + 0x18, new_len)
        modified_bundles += 1
        total_replacements += total
        stats_per_bundle[a['name']] = (total, orig_len, new_len)
        grow = f' +{new_len-orig_len} B 借 gap' if new_len > orig_len else ''
        print(f'  [{a["index"]:4d}] {a["name"]!r}: +{total} 处, {orig_len}->{new_len} B (q={q}){grow}')

    if modified_bundles == 0:
        print('[!] 无任何 bundle 需要汉化（词典未命中）。汉化未生效，未做任何修改。')
        sys.exit(2)

    print(f'\n[+] 共修改 {modified_bundles} 个 bundle, 累计替换 {total_replacements} 处')
    if defang_hits:
        print(f'[+] 库哨兵拆字 {defang_hits} 处')
    if anchor_hits:
        print(f'[+] 锚定替换 {anchor_hits} 处')

    # 备份（文件名带版本号，绝不覆盖历史版本的备份）
    if backup:
        bp = backup_path(exe_path)
        if not os.path.exists(bp):
            shutil.copy2(exe_path, bp)
            print(f'[+] 已备份原文件到 {bp}')
        else:
            print(f'[+] 备份已存在，跳过: {bp}')

    open(exe_path, 'wb').write(bytes(data))
    print(f'[+] 汉化完成！已写入 {exe_path}')
    return stats_per_bundle


def restore(exe_path):
    """还原英文。优先用与当前版本号匹配的备份，避免把新版 exe 覆盖成旧版。"""
    ver = get_file_version(exe_path)
    cands = []
    if ver:
        cands.append('%s.%s.bak' % (exe_path, ver))
    cands.append(exe_path + '.bak')
    for bak in cands:
        if os.path.exists(bak):
            shutil.copy2(bak, exe_path)
            print(f'[+] 已从备份还原: {bak} -> {exe_path}')
            return
    print('[!] 未找到备份文件，尝试过:')
    for b in cands:
        print('    ' + b)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='GitHub Copilot App 汉化工具 v2（处理所有 JS bundle）')
    parser.add_argument('--exe', default=None,
                        help='github.exe 的完整路径（不指定则自动定位安装位置）')
    parser.add_argument('--dict', default=DEFAULT_DICT)
    parser.add_argument('--restore', action='store_true')
    parser.add_argument('--no-backup', action='store_true')
    parser.add_argument('--list', action='store_true', help='只列出所有将被处理的 JS bundle')
    parser.add_argument('--layout', action='store_true',
                        help='只打印 PE 布局与资源表定位结果（排查版本未适配用）')
    args = parser.parse_args()

    # 解析目标 exe 路径：显式指定 > 自动定位 > 报错
    exe_path = args.exe
    if not exe_path:
        exe_path = find_exe()
        if not exe_path:
            print('[!] 未找到 github.exe。请用 --exe 指定它的完整路径，例如：')
            print('    python hanhua_bin.py --exe "C:\\你的安装目录\\GitHub Copilot\\github.exe"')
            print('    或在启动脚本里把路径写死。')
            sys.exit(1)
        print('[+] 自动定位到安装目录: %s' % exe_path)
    elif not os.path.exists(exe_path):
        print('[!] 指定的文件不存在: %s' % exe_path)
        sys.exit(1)

    if args.restore:
        restore(exe_path)
        return

    if args.layout:
        data = open(exe_path, 'rb').read()
        print('[+] App 版本: %s' % (get_file_version(exe_path) or '未知'))
        print('[+] 文件大小: %d 字节' % len(data))
        if detect_layout(data, exe_path) is None:
            sys.exit(2)
        return

    if args.list:
        data = open(exe_path, 'rb').read()
        if detect_layout(data, exe_path) is None:
            sys.exit(2)
        assets = load_assets(data)
        print('[+] 共 %d 个 JS bundle' % len(assets))
        for a in assets:
            print(f'  [{a["index"]:4d}] {a["name"]} (data_len={a["data_len"]})')
        return

    stats = patch(exe_path, args.dict, backup=not args.no_backup)


if __name__ == '__main__':
    main()
