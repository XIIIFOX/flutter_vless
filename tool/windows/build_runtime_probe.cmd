@echo off
setlocal
if "%~1"=="" exit /b 2
set "REPO=%CD%"
set "OUT=%~f1"
if not exist "%OUT%" mkdir "%OUT%" || exit /b 1
if defined VCToolsInstallDir goto compiler_ready
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do call "%%i\VC\Auxiliary\Build\vcvars64.bat"
:compiler_ready
pushd "%OUT%" || exit /b 1
set "S=%REPO%\packages\flutter_vless_windows\windows"
cl /nologo /std:c++17 /EHsc /utf-8 /DNOMINMAX /DWIN32_LEAN_AND_MEAN /I"%S%" "%REPO%\tool\windows\runtime_probe.cpp" "%S%\v2ray_manager.cpp" "%S%\proxy_service.cpp" "%S%\vpn_service.cpp" "%S%\diagnostics_log.cpp" "%S%\native_runtime.cpp" "%S%\native_routing_spec.cpp" "%S%\protected_runtime.cpp" "%S%\packet_path_probe.cpp" "%S%\traffic_protection.cpp" /Fe:runtime_probe.exe /link ws2_32.lib wininet.lib shlwapi.lib version.lib ole32.lib shell32.lib uuid.lib iphlpapi.lib advapi32.lib bcrypt.lib fwpuclnt.lib
set "RESULT=%errorlevel%"
popd
exit /b %RESULT%
