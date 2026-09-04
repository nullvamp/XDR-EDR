#include <windows.h>

#ifndef MODULE_VERSION
#define MODULE_VERSION 1
#endif

__declspec(dllexport) int Sprint7ControlledVersion(void)
{
    return MODULE_VERSION;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
