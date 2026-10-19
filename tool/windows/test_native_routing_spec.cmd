@echo off
setlocal
pushd "%~dp0..\.."
if errorlevel 1 exit /b 1
set "routing_status=1"
set "S=packages\flutter_vless_windows\windows"
set "O=build\native_routing_cli"
if not exist %O%\optional-xray.exe goto finished
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do call "%%i\VC\Auxiliary\Build\vcvars64.bat"
where cl >nul 2>nul
if errorlevel 1 goto finished
cl /nologo /std:c++17 /EHsc /utf-8 /W4 /WX /DNOMINMAX %S%\native_routing_spec.cpp %S%\native_routing_spec_test.cpp /Fe:%O%\windows-routing-spec-test.exe /Fo:%O%\ /link bcrypt.lib > %O%\windows-routing-spec-compile.log 2>&1
if errorlevel 1 goto finished
%O%\windows-routing-spec-test.exe --export-pair "%CD%\%O%\windows-pair" > %O%\windows-routing-spec-test.log 2>&1
if errorlevel 1 goto finished
%O%\optional-xray.exe native-routing check --config "%CD%\%O%\windows-pair\config.json" --spec "%CD%\%O%\windows-pair\spec.json" > %O%\windows-routing-spec-check.log
set "routing_status=%ERRORLEVEL%"
:finished
popd
exit /b %routing_status%
