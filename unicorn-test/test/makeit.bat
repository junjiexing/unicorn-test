@echo off

    if exist "console.obj" del "console.obj"
    if exist "console.exe" del "console.exe"

    \masm32\bin\ml /c /coff "console.asm"
    if errorlevel 1 goto errasm

    \masm32\bin\PoLink /SUBSYSTEM:CONSOLE "console.obj"
    if errorlevel 1 goto errlink
    dir "console.*"
    goto TheEnd

  :errlink
    echo _
    echo Link error
    goto TheEnd

  :errasm
    echo _
    echo Assembly Error
    goto TheEnd
    
  :TheEnd

pause
