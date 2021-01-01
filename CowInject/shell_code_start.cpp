#include "head.h"

//shellcode just like:
/*
HANDLE __stdcall HookCreateFileW(LPCWSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile) {
	CreateFileWT oCreateFileW = (CreateFileWT)0x1234567812345678;
	wcsstrAt oWcsstr = (wcsstrAt)0x1234567891ABCDEF;
	GetModuleFileNameWT oGetModuleFileNameW = (GetModuleFileNameWT)0x1337567891ABCDEF;
	LoadLibraryWT oLoadLibraryW = (LoadLibraryWT)0x1234567891AB1337;
	wchar_t CheatPath[] = { 'C',':','\\','h','u','o','j','i','.','d','l','l','\0' };
	wchar_t NtdllName[] = { 'C',':','\\','n','t','d','l','l','.','d','l','l','\0' };
	//RainbowSix.exe
	wchar_t GameName[] = { 'C','o','n','a','n','S','a','n','d','b','o','x','.','e','x','e','\0' };
	//BEService.exe
	wchar_t AntiCheatName[] = { 'B','E','S','e','r','v','i','c','e','.','e','x','e','\0' };
	wchar_t ExeFile[MAX_PATH];
	oGetModuleFileNameW(NULL, ExeFile, MAX_PATH);
	if (oWcsstr(ExeFile, GameName) != NULL) {
		oLoadLibraryW(CheatPath);
	}
	if (oWcsstr(ExeFile, AntiCheatName) != NULL) {
		return oCreateFileW(oWcsstr(lpFileName, CheatPath) != NULL ? NtdllName : lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	}
	return oCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}
int __stdcall ShellCodeEnd() {
	return 0x1337;
}*/