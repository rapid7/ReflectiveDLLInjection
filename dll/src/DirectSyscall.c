#include "DirectSyscall.h"

#pragma optimize("g", off)
#ifdef __MINGW32__
#pragma GCC push_options
#pragma GCC optimize("O0")
#endif

#pragma warning(disable : 4100)
NTSTATUS SyscallStub(Syscall *pSyscall, ...)
{
	return DoSyscall();
}
#pragma warning(default : 4100)

NTSTATUS rdiNtAllocateVirtualMemory(Syscall *pSyscall, HANDLE hProcess, PVOID *pBaseAddress, ULONG_PTR pZeroBits, PSIZE_T pRegionSize, ULONG ulAllocationType, ULONG ulProtect)
{
	return SyscallStub(pSyscall, hProcess, pBaseAddress, pZeroBits, pRegionSize, ulAllocationType, ulProtect);
}

NTSTATUS rdiNtProtectVirtualMemory(Syscall *pSyscall, HANDLE hProcess, PVOID *pBaseAddress, PSIZE_T pNumberOfBytesToProtect, ULONG ulNewAccessProtection, PULONG ulOldAccessProtection)
{
	return SyscallStub(pSyscall, hProcess, pBaseAddress, pNumberOfBytesToProtect, ulNewAccessProtection, ulOldAccessProtection);
}

NTSTATUS rdiNtFlushInstructionCache(Syscall *pSyscall, HANDLE hProcess, PVOID *pBaseAddress, SIZE_T FlushSize)
{
	return SyscallStub(pSyscall, hProcess, pBaseAddress, FlushSize);
}

NTSTATUS rdiNtLockVirtualMemory(Syscall *pSyscall, HANDLE hProcess, PVOID *pBaseAddress, PSIZE_T NumberOfBytesToLock, ULONG MapType)
{
	return SyscallStub(pSyscall, hProcess, pBaseAddress, NumberOfBytesToLock, MapType);
}

#ifdef __MINGW32__
#pragma GCC pop_options
#endif
#pragma optimize("g", on)

BOOL ExtractTrampolineAddress(PVOID pStub, Syscall *pSyscall)
{
	if (pStub == NULL || pSyscall == NULL)
	{
		return FALSE;
	}

#ifdef _WIN64
	if ((*(PUINT32)pStub == 0xb8d18b4c && *(PUINT16)((PBYTE)pStub + 4) == pSyscall->dwSyscallNr) || *(PBYTE)pStub == 0xe9)
	{
		pSyscall->pStub = (LPVOID)((PBYTE)pStub + 8);
		return TRUE;
	}
#else
	if ((*(PBYTE)pStub == 0xb8 && *(PUINT16)((PBYTE)pStub + 1) == pSyscall->dwSyscallNr) || *(PBYTE)pStub == 0xe9)
	{
		pSyscall->pStub = (LPVOID)((PBYTE)pStub + 5);
		return TRUE;
	}
#endif

	return FALSE;
}

BOOL getSyscalls(PVOID pNtdllBase, Syscall *Syscalls[], DWORD dwSyscallArraySize)
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
	PDWORD pAddressOfNames, pAddressOfFunctions;
	PWORD pAddressOfNameOrdinals;
	DWORD dwFunctionIndex, dwSyscallIndex;
	SYSCALL_LIST SyscallListLocal;
	DWORD i;

	if (pNtdllBase == NULL || Syscalls == NULL || dwSyscallArraySize == 0)
	{
		return FALSE;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pNtdllBase;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}

	pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pNtdllBase + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
	{
		return FALSE;
	}

	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pNtdllBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	pAddressOfFunctions = (PDWORD)((PBYTE)pNtdllBase + pExportDirectory->AddressOfFunctions);
	pAddressOfNames = (PDWORD)((PBYTE)pNtdllBase + pExportDirectory->AddressOfNames);
	pAddressOfNameOrdinals = (PWORD)((PBYTE)pNtdllBase + pExportDirectory->AddressOfNameOrdinals);

	SyscallListLocal.dwCount = 0;
	for (dwFunctionIndex = 0; dwFunctionIndex < pExportDirectory->NumberOfNames; dwFunctionIndex++)
	{
		PCHAR pszFunctionName = (PCHAR)((PBYTE)pNtdllBase + pAddressOfNames[dwFunctionIndex]);

		if (*(USHORT *)pszFunctionName == 0x775a)
		{ // "Zw"
			if (SyscallListLocal.dwCount < MAX_SYSCALLS)
			{
				SyscallListLocal.Entries[SyscallListLocal.dwCount].dwCryptedHash = _hash(pszFunctionName);
				SyscallListLocal.Entries[SyscallListLocal.dwCount].pAddress = (PVOID)((PBYTE)pNtdllBase + pAddressOfFunctions[pAddressOfNameOrdinals[dwFunctionIndex]]);
				SyscallListLocal.dwCount++;
			}
			else
			{
				break;
			}
		}
	}

	if (SyscallListLocal.dwCount == 0)
	{
		return FALSE;
	}

	for (i = 0; i < SyscallListLocal.dwCount - 1; i++)
	{
		for (DWORD j = 0; j < SyscallListLocal.dwCount - i - 1; j++)
		{
			if (SyscallListLocal.Entries[j].pAddress > SyscallListLocal.Entries[j + 1].pAddress)
			{
				SYSCALL_ENTRY TempEntry = SyscallListLocal.Entries[j];
				SyscallListLocal.Entries[j] = SyscallListLocal.Entries[j + 1];
				SyscallListLocal.Entries[j + 1] = TempEntry;
			}
		}
	}

	for (dwSyscallIndex = 0; dwSyscallIndex < dwSyscallArraySize; ++dwSyscallIndex)
	{
		if (Syscalls[dwSyscallIndex] == NULL)
			continue;

		BOOL bFound = FALSE;
		for (i = 0; i < SyscallListLocal.dwCount; ++i)
		{
			if (SyscallListLocal.Entries[i].dwCryptedHash == Syscalls[dwSyscallIndex]->dwCryptedHash)
			{
				Syscalls[dwSyscallIndex]->dwSyscallNr = i;
				if (!ExtractTrampolineAddress(SyscallListLocal.Entries[i].pAddress, Syscalls[dwSyscallIndex]))
				{
					return FALSE;
				}
				bFound = TRUE;
				break;
			}
		}
		if (!bFound)
		{
			Syscalls[dwSyscallIndex]->pStub = NULL;
		}
	}

	for (dwSyscallIndex = 0; dwSyscallIndex < dwSyscallArraySize; ++dwSyscallIndex)
	{
		if (Syscalls[dwSyscallIndex] == NULL)
			continue;
		if (Syscalls[dwSyscallIndex]->pStub == NULL)
		{
			return FALSE;
		}
	}

	return TRUE;
}
