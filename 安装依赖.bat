@echo off
setlocal EnableExtensions
title GitHub Copilot Hanhua - Install Deps
cd /d "%~dp0"

REM ---- 结果标记（0=通过, 1=未通过）----
set "R_VER=1"
set "R_PATH=1"
set "R_BROTLI=1"

echo ============================================
echo   GitHub Copilot Hanhua Tool - Install Deps
echo ============================================
echo.

REM ============================================================
REM  第 1 步：定位 Python 并检查版本 >= 3.10
REM ============================================================
set "PYCMD="

if defined PYTHON set "PYCMD=%PYTHON%"

REM 常见真实安装目录（最可靠，避开微软商店占位符）
if not defined PYCMD if exist "%LocalAppData%\Programs\Python\Python313\python.exe" set "PYCMD=%LocalAppData%\Programs\Python\Python313\python.exe"
if not defined PYCMD if exist "%LocalAppData%\Programs\Python\Python312\python.exe" set "PYCMD=%LocalAppData%\Programs\Python\Python312\python.exe"
if not defined PYCMD if exist "%LocalAppData%\Programs\Python\Python311\python.exe" set "PYCMD=%LocalAppData%\Programs\Python\Python311\python.exe"
if not defined PYCMD if exist "%LocalAppData%\Programs\Python\Python310\python.exe" set "PYCMD=%LocalAppData%\Programs\Python\Python310\python.exe"
if not defined PYCMD if exist "C:\Python313\python.exe" set "PYCMD=C:\Python313\python.exe"
if not defined PYCMD if exist "C:\Python312\python.exe" set "PYCMD=C:\Python312\python.exe"
if not defined PYCMD if exist "C:\Python311\python.exe" set "PYCMD=C:\Python311\python.exe"
if not defined PYCMD if exist "C:\Python310\python.exe" set "PYCMD=C:\Python310\python.exe"

REM py 启动器（官方，绝非商店占位符）
if not defined PYCMD where py >nul 2>nul && set "PYCMD=py"

REM 最后回退 python，但会真实验证
if not defined PYCMD where python >nul 2>nul && set "PYCMD=python"

if not defined PYCMD goto py_missing
"%PYCMD%" -c "import sys" >nul 2>&1
if not %errorlevel%==0 goto py_missing

echo [1/3] Python: %PYCMD%

REM 取版本号（major*100+minor，如 3.13 -> 313）
"%PYCMD%" -c "import sys;print(sys.version_info.major*100+sys.version_info.minor)" > "%TEMP%\_pyver.txt"
set /p PYVER=<"%TEMP%\_pyver.txt"
del "%TEMP%\_pyver.txt" >nul 2>&1

if %PYVER% LSS 310 goto ver_low
set "R_VER=0"
echo   版本检查: OK (^>= 3.10)
goto ver_done

:ver_low
echo   版本检查: 过低 (需 ^>= 3.10，当前 %PYVER%)
echo   [提醒] 请安装 Python 3.10 或更高版本: https://www.python.org/downloads/
echo   仍会继续检查 PATH 与 brotli。

:ver_done
echo.

REM ============================================================
REM  第 2 步：检查是否在 PATH
REM ============================================================
echo [2/3] 检查 PATH ...

REM 判断标准：当前这个 python 能否被 where 直接找到（即在 PATH 里）
where python >nul 2>nul
if %errorlevel%==0 set "R_PATH=0"

if "%R_PATH%"=="0" goto path_ok

REM 不在 PATH：尝试把 python 所在目录加入用户 PATH
echo   未在 PATH 中，尝试加入...
for %%F in ("%PYCMD%") do set "PYDIR=%%~dpF"

REM 用 setx 追加到用户 PATH（注意：setx 会截断超过 1024 字符的 PATH，但通常够用）
setx PATH "%PATH%;%PYDIR%" >nul 2>&1
if not %errorlevel%==0 goto path_manual
echo   已将 Python 目录加入 PATH（%PYDIR%）。
echo   [提示] 需重新打开命令行窗口，PATH 才会生效。
set "R_PATH=0"
goto path_done

:path_manual
echo   [提醒] 自动加入 PATH 失败，请手动操作：
echo          系统设置 -> 环境变量 -> Path -> 新建 -> 添加 %PYDIR%

:path_ok
echo   已确认 Python 在 PATH 中。

:path_done
echo.

REM ============================================================
REM  第 3 步：检查并安装 brotli
REM ============================================================
echo [3/3] 检查 brotli ...

REM 若版本不满足，跳过安装（装了也可能因版本/位数不匹配）
if not "%R_VER%"=="0" goto brotli_skip

"%PYCMD%" -c "import brotli" >nul 2>&1
if %errorlevel%==0 goto brotli_ok

echo   brotli 未安装，正在自动安装（需联网，约 1 分钟）...
"%PYCMD%" -m pip install brotli -i https://pypi.tuna.tsinghua.edu.cn/simple
if not %errorlevel%==0 "%PYCMD%" -m pip install brotli

"%PYCMD%" -c "import brotli" >nul 2>&1
if not %errorlevel%==0 goto brotli_fail
echo   [完成] 已安装 brotli。
set "R_BROTLI=0"
goto brotli_done

:brotli_ok
echo   brotli 已安装，无需重复安装。
set "R_BROTLI=0"
goto brotli_done

:brotli_fail
echo   [提醒] brotli 安装失败，请自行执行: "%PYCMD%" -m pip install brotli
goto brotli_done

:brotli_skip
echo   跳过（Python 版本不满足，先升级 Python）。

:brotli_done
echo.

REM ============================================================
REM  最终统一复查
REM ============================================================
echo ============================================
echo   汉化依赖检查结果
echo ============================================

if "%R_VER%"=="0" (echo   [OK]  Python ^>= 3.10) else (echo   [!!]  Python ^>= 3.10   需自行安装 3.10+)
if "%R_PATH%"=="0" (echo   [OK]  Python 在 PATH 中) else (echo   [!!]  Python 在 PATH 中  需手动加入 PATH)
if "%R_BROTLI%"=="0" (echo   [OK]  brotli 已安装) else (echo   [!!]  brotli 已安装   需自行 pip install brotli)

echo ============================================

set "HAS_FAIL="
if not "%R_VER%"=="0" set "HAS_FAIL=1"
if not "%R_PATH%"=="0" set "HAS_FAIL=1"
if not "%R_BROTLI%"=="0" set "HAS_FAIL=1"

if defined HAS_FAIL goto has_fail
echo   [全部通过] 汉化依赖配置完成！可以双击 汉化工具.bat开始汉化。
goto summary_done

:has_fail
echo   [存在未通过项] 上面打 [!!] 的项目需要你自行配置，配置完成后重新运行本脚本。

:summary_done
echo.
pause
exit /b 0

REM ============================================================
REM  分支标签
REM ============================================================
:py_missing
echo.
echo [错误] 未找到可用的 Python。
echo   请先安装 Python 3.10+（勾选 Add Python to PATH）:
echo   https://www.python.org/downloads/
echo.
pause
exit /b 1

