@echo off
setlocal
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do call "%%i\VC\Auxiliary\Build\vcvars64.bat"
if not exist build\windows-runtime mkdir build\windows-runtime
set "S=packages\flutter_vless_windows\windows"
cl /nologo /std:c++17 /EHsc /utf-8 /W4 /WX /DNOMINMAX %S%\xray_config_test.cpp /Fe:build\windows-runtime\xray_config_test.exe /Fo:build\windows-runtime\xray_config_test.obj
if errorlevel 1 exit /b 1
build\windows-runtime\xray_config_test.exe
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /EHsc /utf-8 /DNOMINMAX /DWIN32_LEAN_AND_MEAN /I%S% tool\windows\runtime_probe.cpp %S%\v2ray_manager.cpp %S%\proxy_service.cpp %S%\vpn_service.cpp %S%\diagnostics_log.cpp /Fe:build\windows-runtime\runtime_probe.exe /Fo:build\windows-runtime\ /link ws2_32.lib wininet.lib shlwapi.lib version.lib ole32.lib shell32.lib uuid.lib iphlpapi.lib
exit /b %errorlevel%
