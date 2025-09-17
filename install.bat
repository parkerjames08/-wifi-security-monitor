@echo off
REM WiFi Security Monitor - Windows Installation Script
REM Run as Administrator

echo 🛡️  WiFi Security Monitor - Windows Installation
echo =============================================

REM Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ❌ This script must be run as Administrator
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo 📋 Detected OS: Windows

REM Check for Python
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ❌ Python not found. Please install Python 3.8+ from python.org
    pause
    exit /b 1
)

echo ✅ Python found

REM Install Python dependencies
echo 🐍 Installing Python dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

if %errorLevel% neq 0 (
    echo ❌ Failed to install dependencies
    pause
    exit /b 1
)

REM Create directories
echo 📁 Setting up directories...
if not exist "C:\WiFiSecurityMonitor" mkdir "C:\WiFiSecurityMonitor"
if not exist "C:\WiFiSecurityMonitor\logs" mkdir "C:\WiFiSecurityMonitor\logs"

REM Copy files
echo 📋 Copying application files...
xcopy /E /Y . "C:\WiFiSecurityMonitor\"

REM Create desktop shortcut
echo 🖥️  Creating desktop shortcut...
powershell -Command "& {$WScript = New-Object -ComObject WScript.Shell; $Shortcut = $WScript.CreateShortcut('%USERPROFILE%\Desktop\WiFi Security Monitor.lnk'); $Shortcut.TargetPath = 'python'; $Shortcut.Arguments = 'C:\WiFiSecurityMonitor\wifi_monitor.py --web'; $Shortcut.WorkingDirectory = 'C:\WiFiSecurityMonitor'; $Shortcut.Save()}"

REM Create start menu shortcut
echo 📂 Creating start menu shortcut...
if not exist "%APPDATA%\Microsoft\Windows\Start Menu\Programs\WiFi Security Monitor" mkdir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\WiFi Security Monitor"
powershell -Command "& {$WScript = New-Object -ComObject WScript.Shell; $Shortcut = $WScript.CreateShortcut('%APPDATA%\Microsoft\Windows\Start Menu\Programs\WiFi Security Monitor\WiFi Security Monitor.lnk'); $Shortcut.TargetPath = 'python'; $Shortcut.Arguments = 'C:\WiFiSecurityMonitor\wifi_monitor.py --web'; $Shortcut.WorkingDirectory = 'C:\WiFiSecurityMonitor'; $Shortcut.Save()}"

REM Create batch file for easy CLI access
echo 🔧 Creating CLI wrapper...
echo @echo off > C:\WiFiSecurityMonitor\wifi-security-monitor.bat
echo cd /d "C:\WiFiSecurityMonitor" >> C:\WiFiSecurityMonitor\wifi-security-monitor.bat
echo python wifi_monitor.py %%* >> C:\WiFiSecurityMonitor\wifi-security-monitor.bat

REM Add to PATH (requires restart)
echo 🛠️  Adding to system PATH...
setx PATH "%PATH%;C:\WiFiSecurityMonitor" /M >nul 2>&1

echo.
echo ✅ Installation completed successfully!
echo.
echo 📋 What's installed:
echo    • WiFi Security Monitor in C:\WiFiSecurityMonitor
echo    • Desktop shortcut
echo    • Start menu shortcut
echo    • CLI tool: wifi-security-monitor.bat
echo.
echo 🚀 Getting started:
echo    • Double-click desktop shortcut to start web interface
echo    • Or run: python C:\WiFiSecurityMonitor\wifi_monitor.py --web
echo    • CLI scan: wifi-security-monitor.bat --cli --scan 60
echo.
echo ⚠️  Important notes:
echo    • Requires Administrator privileges for WiFi monitoring
echo    • Install WiFi adapter drivers if needed
echo    • Windows Defender may require permissions
echo    • Restart command prompt to use CLI tool
echo.
echo 📖 For more information, see README.md
echo.
pause