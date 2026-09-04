#include <windows.h>
#include <stdlib.h>
#include <wchar.h>

int wmain(int argc, wchar_t **argv)
{
    if (argc < 2 || argc > 3) return 64;
    HMODULE module = LoadLibraryW(argv[1]);
    if (module == NULL) return (int)GetLastError();
    DWORD holdMilliseconds = argc == 3 ? wcstoul(argv[2], NULL, 10) : 750;
    Sleep(holdMilliseconds);
    return FreeLibrary(module) ? 0 : (int)GetLastError();
}
