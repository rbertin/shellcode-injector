#include "StdAfx.h"
#include "process.h"

Process::Process() 
{
	pe32.dwSize = sizeof(PROCESSENTRY32);
}

bool Process::init()
{
	/*
	 * @msdn:
	 *	TH32CS_SNAPPROCESS : Includes all processes in the system in the snapshot. 
	 *  To enumerate the processes, see Process32First.
	 */

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapShot == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	if (Process32First(hSnapShot, &pe32) == false) 
	{
		if (hSnapShot != INVALID_HANDLE_VALUE) {
			CloseHandle(hSnapShot);
		}
	
		return false;
	}
	
	return true;
}

wchar_t *Process::getProcess() 
{
	if (Process32Next(hSnapShot, &pe32) == false)
	{
		if (hSnapShot != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hSnapShot);
		}

		return false;
	}

	return (pe32.szExeFile);
}

DWORD Process::getPidByName(wchar_t *procName)
{
	wchar_t *current = NULL;

	while ((current = getProcess()) != NULL)
	{
		if (!_tcsicmp(current, procName)) {
			return (pe32.th32ProcessID);
		}
	}

	return (PROCESS_NO_EXISTS);
}

DWORD Process::KillProcessById(DWORD pid)
{
	HANDLE hProcess;

	hProcess = OpenProcess(PROCESS_TERMINATE, 0, pid);
	if (hProcess == ERROR_SUCCESS) 
	{
		CloseHandle(hProcess);
		return (false);
	}

	if (TerminateProcess(hProcess, 0) == 0)
	{
		CloseHandle(hProcess);
		return false;
	}

	CloseHandle(hProcess);
	return KILLING_SUCCESSFUL;
}

DWORD Process::KillProcessByName(wchar_t *procName)
{
	DWORD pid;
	DWORD result;

	do {

		pid = getPidByName(procName);

		if (pid == PROCESS_NO_EXISTS)
			break;

		if (KillProcessById(pid) != KILLING_SUCCESSFUL)
			result = ERROR_ALL_PROCESS_KILLED;

	} while(pid != NULL);
	
	return (result);
}

/****
	Return 0 is the function successful
****/
DWORD Process::SetDebugPrivileges()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES DBGPriv; 

	/****
		@msdn :
		The AdjustTokenPrivileges function enables or disables privileges 
		in the specified access token. Enabling or disabling privileges 
		in an access token requires TOKEN_ADJUST_PRIVILEGES access.
	***/

	if ((OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) == 0) 
	{
		if (hToken != INVALID_HANDLE_VALUE) 
		{
			CloseHandle(hToken);
		}
		return (GetLastError());
	}

	if ((LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &DBGPriv.Privileges[0].Luid) == 0))
	{
		CloseHandle(hToken);
		return (GetLastError());
	}

	/****
		@msdn :
		PrivilegeCount : This must be set to the number of entries in the Privileges array.
	****/
	DBGPriv.PrivilegeCount = 1;
	DBGPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (AdjustTokenPrivileges(hToken, false, &DBGPriv, 0, NULL, NULL) == ERROR_SUCCESS)
	{
		CloseHandle(hToken);
		return (0);
	}

	CloseHandle(hToken);
	return (GetLastError());
}
