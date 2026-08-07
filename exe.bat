@echo off
pushd "%~dp0"
python -m PyInstaller --onefile --windowed --name "MikroTikSyslog" syslog_server_gui.py
popd
pause