#pragma once

#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>

#ifndef DEF_PROCESS
	#define DEF_PROCESS
#endif

class Process
{
	public:

		static const int PROCESS_NO_EXISTS = 1;
		static const int KILLING_SUCCESSFUL = 2;
		static const int ERROR_ALL_PROCESS_KILLED = 3;

		Process();
		bool init();
		wchar_t* getProcess();
		DWORD getPidByName(wchar_t *procName);
		DWORD KillProcessById(DWORD pid);
		DWORD KillProcessByName(wchar_t *procName);
		DWORD SetDebugPrivileges(); 

	private:
		HANDLE hSnapShot;
		PROCESSENTRY32 pe32;
};