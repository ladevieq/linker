@ECHO OFF

:: Unpack Arguments
set release=0
for %%a in (%*) do set "%%a=1"

set BUILD_DIR=build

:: Clean directory
IF EXIST %BUILD_DIR% rmdir %BUILD_DIR%\ /S /Q

mkdir build

set VS2022_COM="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
set VS2022_PRO="C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"

if EXIST %VS2022_COM% (
    call %VS2022_COM%
    goto compilation
)
if EXIST %VS2022_PRO% (
    call %VS2022_PRO%
    goto compilation
)

:compilation
set C_FLAGS=/nologo /W4 /WX /Zi /GS- /GR- /Gs1000000000 /Fo:%BUILD_DIR%\ /Iinclude /Isrc /std:clatest /c /Tc
set L_FLAGS=/WX /SUBSYSTEM:CONSOLE /NODEFAULTLIB /stack:0x100000,0x100000

if "%release%"=="0" (
    set C_FLAGS=/Od %C_FLAGS%
    set L_FLAGS=/DEBUG %L_FLAGS%
)


:: DBG
:: Compile
cl.exe /Fd:%BUILD_DIR%\main.pdb %C_FLAGS% src\main.c
:: clang-cl.exe /Fd:%BUILD_DIR%\main.pdb %C_FLAGS% src\main.c

:: Link
link %L_FLAGS% /OUT:%BUILD_DIR%\main.exe %BUILD_DIR%\main.obj kernel32.lib

:: Test program
:: Compile
cl.exe %C_FLAGS% test\main.c /Fd:%BUILD_DIR%\test.pdb /Fo:%BUILD_DIR%\test.obj
