#pragma once

#include <winnt.h>

typedef DWORD fWaitForSingleObject(HANDLE, DWORD);
typedef BOOL fCloseHandle(HANDLE);
typedef BOOL fDelete(LPCTSTR);
typedef VOID fSleep(DWORD);
typedef VOID fExitProcess(UINT);
typedef DWORD fGetLastError(void);
typedef HMODULE fLoadLibrary(LPCTSTR);
typedef void* fGetProcAddress(HMODULE, LPCSTR);
