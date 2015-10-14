@echo off
if NOT "%DRIVERDEV%" == "" goto skip_env
echo Setting up DDK env.
call ddk.bat
set DRIVERDEV=yep

:skip_env
nmake
