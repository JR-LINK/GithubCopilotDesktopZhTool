@echo off
setlocal
title GitHub Copilot App Localizer
cd /d "%~dp0"

echo ============================================
echo   GitHub Copilot App - Chinese Localizer
echo   (binary patch for Tauri client)
echo ============================================

REM ---- locate Python (same order as install-deps: real dirs > py > python) ----
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

REM 最后回退 python（可能是商店占位符，下面会验证 brotli）
if not defined PYCMD where python >nul 2>nul && set "PYCMD=python"

if not defined PYCMD (
    echo.
    echo [ERROR] Python not found.
    echo   Install Python 3.10+ and run install-deps first.
    echo   Or set env var PYTHON to your python.exe path.
    echo.
    pause
    exit /b 1
)

REM ---- verify brotli dependency before running ----
"%PYCMD%" -c "import brotli" >nul 2>&1
if not %errorlevel%==0 (
    echo.
    echo [ERROR] Python 缺少 brotli 依赖。
    echo   请先双击运行「安装依赖.bat」装好依赖，再回来汉化。
    echo.
    pause
    exit /b 1
)

REM ---- parse arg (hanhua/restore passed directly, or interactive menu) ----
set "MODE=%1"

if "%MODE%"=="" goto menu
if /i "%MODE%"=="hanhua" goto apply
if /i "%MODE%"=="1" goto apply
if /i "%MODE%"=="restore" goto restore
if /i "%MODE%"=="2" goto restore

:menu
echo.
echo   [1] Apply Chinese  (hanhua)
echo   [2] Restore English
echo   [3] Exit
echo.
set /p choice=Please choose (1/2/3): 

if "%choice%"=="1" goto apply
if "%choice%"=="2" goto restore
if "%choice%"=="3" goto end
goto end

:apply
echo.
echo Applying Chinese, please wait (about 5 min)...
"%PYCMD%" hanhua_bin.py
if not %errorlevel%==0 (
    echo.
    echo [ERROR] 汉化失败，请看上面的报错信息。
    echo   常见原因：GitHub Copilot 还在运行（请完全退出后重试）。
    echo.
    pause
    exit /b 1
)
echo.
echo Done! Restart GitHub Copilot App to see the result.
goto done

:restore
echo.
echo Restoring English...
"%PYCMD%" hanhua_bin.py --restore
if not %errorlevel%==0 (
    echo.
    echo [ERROR] 还原失败，请看上面的报错信息。
    echo.
    pause
    exit /b 1
)
echo.
echo Restored to English.
goto done

:done
echo.
pause
goto end

:end
endlocal
exit /b 0

