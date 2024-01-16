#include "DirectSyscall.h"

// Note that compiler optimizations need to be disabled for SyscallStub() and all the rdi...() API functions
// to make sure the stack is setup in a way that can be handle by DoSyscall() assembly code.
#pragma optimize( "g", off )
#ifdef __MINGW32__
#pragma GCC push_options
#pragma GCC optimize ("O0")
#endif

//
// Main stub that is called by all the native API functions
//
#pragma warning(disable: 4100) // warning C4100: unreferenced formal parameter
NTSTATUS SyscallStub(Syscall* pSyscall, ...) {
	return DoSyscall();
}
#pragma warning(default: 4100)

//
// Native API functions
//
NTSTATUS rdiNtAllocateVirtualMemory(Syscall* pSyscall, HANDLE hProcess, PVOID* pBaseAddress, ULONG_PTR pZeroBits, PSIZE_T pRegionSize, ULONG ulAllocationType, ULONG ulProtect) {
	return SyscallStub(pSyscall, hProcess, pBaseAddress, pZeroBits, pRegionSize, ulAllocationType, ulProtect);
}

NTSTATUS rdiNtProtectVirtualMemory(Syscall* pSyscall, HANDLE hProcess, PVOID* pBaseAddress, PSIZE_T pNumberOfBytesToProtect, ULONG ulNewAccessProtection, PULONG ulOldAccessProtection) {
	return SyscallStub(pSyscall, hProcess, pBaseAddress, pNumberOfBytesToProtect, ulNewAccessProtection, ulOldAccessProtection);
}

NTSTATUS rdiNtFlushInstructionCache(Syscall* pSyscall, HANDLE hProcess, PVOID* pBaseAddress, SIZE_T FlushSize) {
	return SyscallStub(pSyscall, hProcess, pBaseAddress, FlushSize);
}

NTSTATUS rdiNtLockVirtualMemory(Syscall* pSyscall, HANDLE hProcess, PVOID* pBaseAddress, PSIZE_T NumberOfBytesToLock, ULONG MapType) {
	return SyscallStub(pSyscall, hProcess, pBaseAddress, NumberOfBytesToLock, MapType);
}

#ifdef __MINGW32__
#pragma GCC pop_options
#endif
#pragma optimize( "g", on )


//
// Extract the system call trampoline address in ntdll.dll
//
BOOL ExtractTrampolineAddress(PVOID pStub, Syscall *pSyscall) {
	if (pStub == NULL || pSyscall == NULL)
		return FALSE;

	// If the stub starts with the right bytes, check the syscall number to make sure it is the expected stub.
	// Ignore this check if it is hooked (it starts with byte `0xe9`) and assume this is the expected stub.
	// Finally, return the address right after the syscall number or the hook.

#ifdef _WIN64
	// On x64 Windows, the function starts like this:
	// 4C 8B D1          mov r10, rcx
	// B8 96 00 00 00    mov eax, 96h   ; syscall number
	//
	// If it is hooked a `jmp <offset>` will be found instead
	// E9 4B 03 00 80    jmp 7FFE6BCA0000
	// folowed by the 3 remaining bytes from the original code:
	// 00 00 00
	if (*(PUINT32)pStub == 0xb8d18b4c && *(PUINT16)((PBYTE)pStub + 4) == pSyscall->dwSyscallNr || *(PBYTE)pStub == 0xe9) {
		pSyscall->pStub = (LPVOID)((PBYTE)pStub + 8);
		return TRUE;
	}
#else
	// On x86 ntdll, it starts like this:
	// B8 F1 00 00 00    mov     eax, 0F1h   ; syscall number
	//
	// If it is hooked a `jmp <offset>` will be found instead
	// E9 99 00 00 00    jmp     775ECAA1
	if (*(PBYTE)pStub == 0xb8 && *(PUINT16)((PBYTE)pStub + 1) == pSyscall->dwSyscallNr || *(PBYTE)pStub == 0xe9) {
		pSyscall->pStub = (LPVOID)((PBYTE)pStub + 5);
		return TRUE;
	}
#endif

	return FALSE;
}

//
// Retrieve the syscall data for every functions in Syscalls and UtilitySyscalls arrays of Syscall structures.
// It goes through ntdll exports and compare the hash of the function names with the hash contained in the structures.
// For each matching hash, it extract the syscall data and store it in the structure.
//
BOOL getSyscalls(PVOID pNtdllBase, Syscall* Syscalls[], DWORD dwSyscallSize) {
	PIMAGE_DOS_HEADER pDosHdr = NULL;
	PIMAGE_NT_HEADERS pNtHdrs = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;
	PDWORD pdwAddrOfNames = NULL, pdwAddrOfFunctions = NULL;
	PWORD pwAddrOfNameOrdinales = NULL;
	DWORD dwIdxfName = 0, dwIdxSyscall = 0;
	SYSCALL_LIST SyscallList;

	pDosHdr = (PIMAGE_DOS_HEADER)pNtdllBase;
	pNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pNtdllBase + pDosHdr->e_lfanew);
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pNtdllBase + pNtHdrs->OptionalHeader.DataDirectory[0].VirtualAddress);

	pdwAddrOfFunctions = (PDWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfFunctions);
	pdwAddrOfNames = (PDWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfNames);
	pwAddrOfNameOrdinales = (PWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfNameOrdinals);

	// Populate SyscallList with unsorted Zw* entries.
	DWORD i = 0;
	SYSCALL_ENTRY* Entries = SyscallList.Entries;
	for (dwIdxfName = 0; dwIdxfName < pExportDir->NumberOfNames; dwIdxfName++) {
		PCHAR FunctionName = (PCHAR)((PBYTE)pNtdllBase + pdwAddrOfNames[dwIdxfName]);

		// Selecting only system call functions starting with 'Zw'
		if (*(USHORT*)FunctionName == 0x775a)
		{
			Entries[i].dwCryptedHash = _hash(FunctionName);
			Entries[i].pAddress = (PVOID)((PBYTE)pNtdllBase + pdwAddrOfFunctions[pwAddrOfNameOrdinales[dwIdxfName]]);

			if (++i == MAX_SYSCALLS)
				break;
		}
	}

	// Save total number of system calls found
	SyscallList.dwCount = i;

	// Sort the list by address in ascending order.
	for (i = 0; i < SyscallList.dwCount - 1; i++)
	{
		for (DWORD j = 0; j < SyscallList.dwCount - i - 1; j++)
		{
			if (Entries[j].pAddress > Entries[j + 1].pAddress)
			{
				// Swap entries.
				SYSCALL_ENTRY TempEntry;

				TempEntry.dwCryptedHash = Entries[j].dwCryptedHash;
				TempEntry.pAddress = Entries[j].pAddress;

				Entries[j].dwCryptedHash = Entries[j + 1].dwCryptedHash;
				Entries[j].pAddress = Entries[j + 1].pAddress;

				Entries[j + 1].dwCryptedHash = TempEntry.dwCryptedHash;
				Entries[j + 1].pAddress = TempEntry.pAddress;
			}
		}
	}

	// Find the syscall numbers and trampolins we need
	for (dwIdxSyscall = 0; dwIdxSyscall < dwSyscallSize; ++dwIdxSyscall) {
		for (i = 0; i < SyscallList.dwCount; ++i) {
			if (SyscallList.Entries[i].dwCryptedHash == Syscalls[dwIdxSyscall]->dwCryptedHash) {
				Syscalls[dwIdxSyscall]->dwSyscallNr = i;
				if (!ExtractTrampolineAddress(SyscallList.Entries[i].pAddress, Syscalls[dwIdxSyscall]))
					return FALSE;
				break;
			}
		}
	}

	// Last check to make sure we have everything we need
	for (dwIdxSyscall = 0; dwIdxSyscall < dwSyscallSize; ++dwIdxSyscall) {
		if (Syscalls[dwIdxSyscall]->pStub == NULL)
			return FALSE;
	}

	return TRUE;
}
