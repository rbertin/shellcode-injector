#include <Windows.h>

#pragma once
class ShellcodeInjector
{
public:
	ShellcodeInjector(void);
	bool Inject(INT pid);
	bool setShellcode(BYTE* bShellcode, UINT length);
	~ShellcodeInjector(void);
private:
	int shellcodeLength;
	BYTE *bpShellcode;
	HANDLE NtCreateThreadEx(HANDLE hProcess, LPVOID lpRemoteThreadStart, LPVOID lpRemoteCallback);
	HANDLE __CreateRemoteThread(HANDLE hProcess, LPVOID lpRemoteThreadStart, LPVOID lpRemoteCallback);
};

typedef struct 
{ 
	ULONG Length; 
	ULONG Unknown1; 
	ULONG Unknown2; 
	PULONG Unknown3; 
	ULONG Unknown4; 
	ULONG Unknown5; 
	ULONG Unknown6; 
	PULONG Unknown7; 
	ULONG Unknown8; 

} UNKNOWN; 

typedef DWORD WINAPI NtCreateThreadEx_PROC( 
	PHANDLE ThreadHandle, 
	ACCESS_MASK DesiredAccess, 
	LPVOID ObjectAttributes, 
	HANDLE ProcessHandle, 
	LPTHREAD_START_ROUTINE lpStartAddress, 
	LPVOID lpParameter, 
	BOOL CreateSuspended, 
	DWORD dwStackSize, 
	DWORD Unknown1, 
	DWORD Unknown2, 
	LPVOID Unknown3 
); 
