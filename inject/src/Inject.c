//===============================================================================================//
// Copyright (c) 2013, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted
// provided that the following conditions are met:
//
//     * Redistributions of source code must retain the above copyright notice, this list of
// conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright notice, this list of
// conditions and the following disclaimer in the documentation and/or other materials provided
// with the distribution.
//
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//

#define WIN32_LEAN_AND_MEAN

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4820)
#endif

#include <windows.h>
#include <tlhelp32.h>

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "LoadLibraryR.h"

#ifndef __MINGW32__
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "User32.lib")
#endif

#define PRINT_STATUS(fmt, ...) printf("[*] " fmt "\n", ##__VA_ARGS__)
#define PRINT_SUCCESS(fmt, ...) printf("[+] " fmt "\n", ##__VA_ARGS__)
#define PRINT_ERROR(fmt, ...) printf("[-] " fmt " (LastError: %lu)\n", ##__VA_ARGS__, GetLastError())
#define PRINT_ERROR_NO_CODE(fmt, ...) printf("[-] " fmt "\n", ##__VA_ARGS__)
#define PRINT_OUTPUT(fmt, ...) printf("[>] " fmt "\n", ##__VA_ARGS__)

typedef struct _INJECTION_CONFIG
{
	char *targetProcessIdentifier;
	char *dllPath;
	char *exeToSpawn;
	BOOL spawnProcess;
	BOOL targetIsPid;
	BOOL performWarmup;
} INJECTION_CONFIG;

static VOID ShowHelp(const char *pszProgramName)
{
	printf("Reflective DLL Injector\n");
	printf("Usage: %s [options] [target] [dll_path]\n\n", pszProgramName);
	printf("Targets:\n");
	printf("  <PID>                 Inject into an existing process by its ID.\n");
	printf("  <ProcessName.exe>     Inject into an existing process by its name.\n");
	printf("  (no target specified) Spawns default executable ('%s') and injects.\n\n", "notepad.exe");
	printf("Options:\n");
	printf("  /spawn [ExeName.exe]  Spawn a new process and inject into it.\n");
	printf("                        If ExeName is omitted, '%s' is used.\n", "notepad.exe");
	printf("  /h, /?                Show this help message.\n\n");
	printf("DLL Path:\n");
	printf("  [PathToDLL.dll]       Path to the reflective DLL to inject.\n");
	printf("                        If omitted, a default architecture-specific DLL name is used:\n");
#if defined(_M_IX86)
	printf("                          reflective_dll.Win32.dll\n");
#elif defined(_M_X64) && !defined(_M_ARM64)
	printf("                          reflective_dll.x64.dll\n");
#elif defined(_M_ARM64)
	printf("                          reflective_dll.arm64.dll\n");
#endif
	printf("\nExamples:\n");
	printf("  %s 1234\n", pszProgramName);
	printf("  %s notepad.exe my_reflective_dll.dll\n", pszProgramName);
	printf("  %s /spawn\n", pszProgramName);
	printf("  %s /spawn calc.exe specific_payload.dll\n", pszProgramName);
}

static DWORD GetProcessIdByName(const char *processName)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	DWORD pid = 0;
	DWORD lastErrorSnapshot = 0;
	DWORD lastErrorFirstNext = 0;

	if (snapshot == INVALID_HANDLE_VALUE)
	{
		lastErrorSnapshot = GetLastError();
		SetLastError(lastErrorSnapshot);
		return 0;
	}
	if (Process32First(snapshot, &entry))
	{
		do
		{
			if (_stricmp(entry.szExeFile, processName) == 0)
			{
				pid = entry.th32ProcessID;
				break;
			}
		} while (Process32Next(snapshot, &entry));
		if (pid == 0)
		{
			lastErrorFirstNext = GetLastError();
		}
	}
	else
	{
		lastErrorFirstNext = GetLastError();
	}
	CloseHandle(snapshot);

	if (pid == 0)
	{
		if (lastErrorFirstNext != ERROR_SUCCESS && lastErrorFirstNext != ERROR_NO_MORE_FILES)
		{
			SetLastError(lastErrorFirstNext);
		}
		else if (lastErrorSnapshot != ERROR_SUCCESS)
		{
			SetLastError(lastErrorSnapshot);
		}
		else
		{
			SetLastError(ERROR_NOT_FOUND);
		}
	}
	else
	{
		SetLastError(ERROR_SUCCESS);
	}
	return pid;
}

static BOOL SpawnProcessInternal(const char *exePath, PROCESS_INFORMATION *piOut, BOOL bTryToHide, BOOL bSuspended)
{
	STARTUPINFOA si = {0};
	DWORD dwCreationFlags = 0;

	if (bSuspended)
		dwCreationFlags |= CREATE_SUSPENDED;
	si.cb = sizeof(STARTUPINFOA);
	if (bTryToHide)
	{
		si.dwFlags |= STARTF_USESHOWWINDOW;
		si.wShowWindow = SW_HIDE;
		dwCreationFlags |= CREATE_NO_WINDOW;
	}

	char szCmdLine[MAX_PATH];
	if (strlen(exePath) >= MAX_PATH)
	{
		SetLastError(ERROR_BUFFER_OVERFLOW);
		return FALSE;
	}
	strcpy_s(szCmdLine, sizeof(szCmdLine), exePath);

	if (!CreateProcessA(NULL, szCmdLine, NULL, NULL, FALSE, dwCreationFlags, NULL, NULL, &si, piOut))
	{
		PRINT_ERROR("CreateProcessA failed for %s (Flags: 0x%lX)", exePath, dwCreationFlags);
		return FALSE;
	}
	PRINT_SUCCESS("Process %s spawned (PID: %lu, Handle: 0x%p). Suspended: %s, HiddenAttempt: %s",
				  exePath, piOut->dwProcessId, piOut->hProcess, bSuspended ? "Yes" : "No", bTryToHide ? "Yes" : "No");
	return TRUE;
}

static BOOL AdjustPrivileges(VOID)
{
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tp = {0};
	BOOL bSuccess = FALSE;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
		{
			if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS)
			{
				PRINT_SUCCESS("SE_DEBUG_NAME privilege successfully enabled.");
				bSuccess = TRUE;
			}
			else
			{
				PRINT_STATUS("AdjustTokenPrivileges failed/partially to enable SE_DEBUG_NAME (LastError: %lu). Continuing...", GetLastError());
			}
		}
		else
		{
			PRINT_STATUS("LookupPrivilegeValue for SE_DEBUG_NAME failed (LastError: %lu)", GetLastError());
		}
		CloseHandle(hToken);
	}
	else
	{
		PRINT_STATUS("OpenProcessToken failed (Error: %lu), cannot attempt SE_DEBUG_NAME.", GetLastError());
	}
	return bSuccess;
}

static LPVOID ReadDllFileToBuffer(const char *filePath, DWORD *pdwFileSize)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	LPVOID lpBuffer = NULL;
	DWORD dwBytesRead;

	hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("Failed to open DLL file: %s", filePath);
		return NULL;
	}

	*pdwFileSize = GetFileSize(hFile, NULL);
	if (*pdwFileSize == INVALID_FILE_SIZE || *pdwFileSize == 0)
	{
		PRINT_ERROR_NO_CODE("Invalid file size for DLL: %s", filePath);
		CloseHandle(hFile);
		SetLastError(ERROR_INVALID_DATA);
		return NULL;
	}
	PRINT_STATUS("DLL file size: %lu bytes", *pdwFileSize);

	lpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *pdwFileSize);
	if (!lpBuffer)
	{
		PRINT_ERROR_NO_CODE("Failed to allocate buffer for DLL.");
		CloseHandle(hFile);
		SetLastError(ERROR_OUTOFMEMORY);
		return NULL;
	}

	if (!ReadFile(hFile, lpBuffer, *pdwFileSize, &dwBytesRead, NULL) || dwBytesRead != *pdwFileSize)
	{
		PRINT_ERROR("Failed to read DLL into buffer");
		HeapFree(GetProcessHeap(), 0, lpBuffer);
		CloseHandle(hFile);
		return NULL;
	}
	PRINT_STATUS("DLL read into local buffer at 0x%p.", lpBuffer);
	CloseHandle(hFile);
	return lpBuffer;
}

static BOOL ParseArguments(int argc, char *argv[], INJECTION_CONFIG *config)
{
#if defined(_M_IX86)
	config->dllPath = "reflective_dll.Win32.dll";
#elif defined(_M_X64) && !defined(_M_ARM64)
	config->dllPath = "reflective_dll.x64.dll";
#elif defined(_M_ARM64)
	config->dllPath = "reflective_dll.arm64.dll";
#else
#error "Unsupported architecture for injector default DLL."
#endif
	config->exeToSpawn = "notepad.exe";
	config->spawnProcess = FALSE;
	config->targetIsPid = FALSE;
	config->performWarmup = FALSE;
	config->targetProcessIdentifier = NULL;

	if (argc < 2)
	{
		config->spawnProcess = TRUE;
	}
	else
	{
		int currentArg = 1;
		if (_stricmp(argv[currentArg], "/h") == 0 || _stricmp(argv[currentArg], "/?") == 0)
		{
			ShowHelp(argv[0]);
			return FALSE;
		}

		if (_stricmp(argv[currentArg], "/spawn") == 0)
		{
			config->spawnProcess = TRUE;
			currentArg++;
			if (currentArg < argc && argv[currentArg][0] != '/' &&
				strstr(argv[currentArg], ".dll") == NULL && strstr(argv[currentArg], ".DLL") == NULL)
			{
				config->exeToSpawn = argv[currentArg++];
			}
		}
		else
		{
			config->targetProcessIdentifier = argv[currentArg++];
			char *endptr;
			long val = strtol(config->targetProcessIdentifier, &endptr, 10);
			if (*endptr == '\0' && endptr != config->targetProcessIdentifier && val > 0)
			{
				config->targetIsPid = TRUE;
			}
		}

		if (currentArg < argc)
		{
			config->dllPath = argv[currentArg];
		}
	}

	if (config->spawnProcess && config->exeToSpawn != NULL)
	{
		DWORD existingPid = GetProcessIdByName(config->exeToSpawn);
		if (existingPid == 0 && GetLastError() == ERROR_NOT_FOUND)
		{
			PRINT_STATUS("No existing '%s' detected. Warmup will be performed if target is '%s'.", config->exeToSpawn, config->exeToSpawn);
			config->performWarmup = TRUE;
		}
		else if (existingPid != 0)
		{
			PRINT_STATUS("Existing '%s' (PID: %lu) detected. Skipping warmup.", config->exeToSpawn, existingPid);
		}
		else
		{
			PRINT_STATUS("Could not determine if '%s' is running (Error: %lu). Skipping warmup.", config->exeToSpawn, GetLastError());
		}
	}
	return TRUE;
}

int main(int argc, char *argv[])
{
	HANDLE hRemoteThread = NULL;
	HANDLE hProcess = NULL;
	LPVOID lpDllBuffer = NULL;
	DWORD dwDllFileSize = 0;
	DWORD dwProcessId = 0;
	DWORD dwRemoteThreadExitCode = 0;
	PROCESS_INFORMATION procInfoTarget = {0};
	BOOL bInjectedAndThreadFinished = FALSE;
	INJECTION_CONFIG config;
	DWORD dwTargetInitDelayMs = 2000;

	if (!ParseArguments(argc, argv, &config))
	{
		return (argc > 1 && (_stricmp(argv[1], "/h") == 0 || _stricmp(argv[1], "/?") == 0)) ? 0 : 1;
	}

	do
	{
		if (config.performWarmup)
		{
			PROCESS_INFORMATION piWarmup = {0};
			DWORD dwWarmupWaitTimeoutMs = 1000;
			PRINT_STATUS("Performing warmup spawn of %s...", config.exeToSpawn);
			if (SpawnProcessInternal(config.exeToSpawn, &piWarmup, TRUE, TRUE))
			{
				ResumeThread(piWarmup.hThread);
				WaitForSingleObject(piWarmup.hProcess, dwWarmupWaitTimeoutMs);
				TerminateProcess(piWarmup.hProcess, 0);
				CloseHandle(piWarmup.hThread);
				CloseHandle(piWarmup.hProcess);
				PRINT_STATUS("Warmup process terminated. Proceeding with actual target.");
				Sleep(100);
			}
			else
			{
				PRINT_ERROR("Warmup spawn of %s failed. Continuing without warmup...", config.exeToSpawn);
			}
		}

		if (config.spawnProcess)
		{
			if (!SpawnProcessInternal(config.exeToSpawn, &procInfoTarget, FALSE, TRUE))
				break;
			dwProcessId = procInfoTarget.dwProcessId;
			hProcess = procInfoTarget.hProcess;
		}
		else
		{
			if (config.targetIsPid)
			{
				dwProcessId = strtoul(config.targetProcessIdentifier, NULL, 10);
				PRINT_STATUS("Targeting existing process by PID: %lu", dwProcessId);
			}
			else
			{
				PRINT_STATUS("Targeting existing process by Name: %s", config.targetProcessIdentifier);
				dwProcessId = GetProcessIdByName(config.targetProcessIdentifier);
				if (dwProcessId == 0)
				{
					PRINT_ERROR("Failed to find PID for process name: %s", config.targetProcessIdentifier);
					break;
				}
				PRINT_SUCCESS("Found PID %lu for process name '%s'", dwProcessId, config.targetProcessIdentifier);
			}
			hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
			if (!hProcess)
			{
				PRINT_ERROR("Failed to open the target process %lu", dwProcessId);
				break;
			}
			PRINT_SUCCESS("Opened target process %lu. Handle: 0x%p", dwProcessId, hProcess);
		}
		if (!hProcess)
		{
			PRINT_ERROR_NO_CODE("Failed to acquire a valid process handle for the target.");
			break;
		}

		lpDllBuffer = ReadDllFileToBuffer(config.dllPath, &dwDllFileSize);
		if (!lpDllBuffer)
			break;

		AdjustPrivileges();

		if (config.spawnProcess && procInfoTarget.hThread != NULL)
		{
			PRINT_STATUS("Resuming main thread of target spawned process %s (PID: %lu)...", config.exeToSpawn, procInfoTarget.dwProcessId);
			if (ResumeThread(procInfoTarget.hThread) == (DWORD)-1)
				PRINT_ERROR("Failed to resume main thread of target process %s", config.exeToSpawn);
			else
				PRINT_SUCCESS("Main thread of target process %s resumed.", config.exeToSpawn);

			PRINT_STATUS("Waiting %lu ms for target process to initialize (or input idle)...", dwTargetInitDelayMs);
			WaitForInputIdle(hProcess, dwTargetInitDelayMs);
		}

		DWORD dwReflectiveLoaderFileOffset = GetReflectiveLoaderOffset(lpDllBuffer, "ReflectiveLoader");
		PRINT_STATUS("Injector's GetReflectiveLoaderOffset result: 0x%lX", dwReflectiveLoaderFileOffset);
		if (dwReflectiveLoaderFileOffset == 0)
		{
			PRINT_ERROR_NO_CODE("GetReflectiveLoaderOffset failed.");
			break;
		}
		if (dwReflectiveLoaderFileOffset >= dwDllFileSize)
		{
			PRINT_ERROR_NO_CODE("CRITICAL: Loader offset (0x%lX) beyond file size (0x%lu)!", dwReflectiveLoaderFileOffset, dwDllFileSize);
			break;
		}

		PRINT_STATUS("Attempting to call LoadRemoteLibraryR...");
		hRemoteThread = LoadRemoteLibraryR(hProcess, lpDllBuffer, dwDllFileSize, dwReflectiveLoaderFileOffset, NULL);
		PRINT_STATUS("LoadRemoteLibraryR call completed.");

		if (!hRemoteThread)
		{
			PRINT_ERROR("LoadRemoteLibraryR failed");
			break;
		}
		PRINT_SUCCESS("Remote injection thread created. Handle: 0x%p. Waiting for completion...", hRemoteThread);

		WaitForSingleObject(hRemoteThread, INFINITE);
		PRINT_STATUS("%s", "Remote injection thread completed.");
		bInjectedAndThreadFinished = TRUE;

		if (!GetExitCodeThread(hRemoteThread, &dwRemoteThreadExitCode))
		{
			PRINT_STATUS("GetExitCodeThread failed. Error: %lu", GetLastError());
		}
		else
		{
			PRINT_OUTPUT("Remote injection thread exit code: 0x%08lX", dwRemoteThreadExitCode);
			if (dwRemoteThreadExitCode == 0 || dwRemoteThreadExitCode == 0xC0000005 || dwRemoteThreadExitCode == (DWORD)-1)
			{
				PRINT_ERROR_NO_CODE("ReflectiveLoader likely failed/crashed in remote process. Exit code: 0x%08lX", dwRemoteThreadExitCode);
			}
			else
				PRINT_SUCCESS("Module base address in remote process (from thread exit code): 0x%08lX", dwRemoteThreadExitCode);
		}

	} while (0);

	if (bInjectedAndThreadFinished)
	{
		if (dwRemoteThreadExitCode != 0 && dwRemoteThreadExitCode != 0xC0000005 && dwRemoteThreadExitCode != (DWORD)-1)
			PRINT_SUCCESS("DLL injection appears to have succeeded.");
		else
			PRINT_ERROR_NO_CODE("DLL injection appears to have failed based on thread exit code.");
	}
	else
		PRINT_ERROR_NO_CODE("DLL injection process was aborted before remote thread completion.");

	if (hRemoteThread)
	{
		CloseHandle(hRemoteThread);
	}
	if (lpDllBuffer)
	{
		HeapFree(GetProcessHeap(), 0, lpDllBuffer);
	}
	if (procInfoTarget.hThread != NULL)
	{
		CloseHandle(procInfoTarget.hThread);
	}
	if (hProcess)
	{
		CloseHandle(hProcess);
	}

	PRINT_STATUS("%s", "Injection process finished.");
	return (dwRemoteThreadExitCode != 0 && dwRemoteThreadExitCode != 0xC0000005 && dwRemoteThreadExitCode != (DWORD)-1 && bInjectedAndThreadFinished) ? 0 : 1;
}
