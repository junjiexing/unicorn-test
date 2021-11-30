.486                      ; create 32 bit code
.model flat, stdcall      ; 32 bit memory model
option casemap :none      ; case sensitive

include \masm32\include\windows.inc
include \masm32\include\user32.inc
include \masm32\include\kernel32.inc

includelib \masm32\lib\user32.lib
includelib \masm32\lib\kernel32.lib

.data
	szTitle db "world", 0
	szContent db "hello", 0
	szDbgStr db "hello world",0

.code

start:
   
	invoke MessageBoxA, 0, addr szTitle, addr szContent, MB_OK
	invoke FindWindow, 0, 0
	
	invoke OutputDebugStringA, addr szDbgStr
	
	ret

end start
