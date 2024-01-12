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
// Extract the syscall number and the address of the instruction sequence "syscall/retn"
//
BOOL ExtractSysCallData(PVOID pStub, Syscall *pSyscall) {
	INT8 cIdxStub = 0, cOffsetStub = 0;
	PBYTE pbCurrentByte = NULL;

	if (pStub == NULL || pSyscall == NULL)
		return FALSE;

	for (cIdxStub = 0; cIdxStub < SYS_STUB_SIZE; cIdxStub++) {
		pbCurrentByte = (PBYTE)pStub + cIdxStub;

		if (*pbCurrentByte == 0xc3) // Too far
			return FALSE;
#ifdef _WIN64
		// On x64 Windows, the function starts like this:
		// 4C 8B D1          mov r10, rcx
		// B8 96 00 00 00    mov eax, 96h   ; syscall number
		//
		// If it is hooked a `jmp <offset>` will be found instead
		// E9 4B 03 00 80    jmp 7FFE6BCA0000
		// folowed by the 3 remaining bytes from the original code:
		// 00 00 00
		if (*(PUINT32)pbCurrentByte == 0xb8d18b4c || *pbCurrentByte == 0xe9) {

			// Then on Windows 10/11 (x64):
			// F6 04 25 08 03 FE 7F 01    test    byte ptr ds:7FFE0308h, 1
			// 75 03                      jnz     short loc_1800A4E65
			// 0F 05                      syscall            ; XOR'ing these bytes to obfuscate them when comparing below
			// C3                         retn
			if (*(PUINT64)(pbCurrentByte + 8) == 0x017ffe03082504f6 && (*(PUINT32)(pbCurrentByte + 16) ^ 0x01010101) == 0x040e0274 && *(pbCurrentByte + 20) == 0xc3) {
				cOffsetStub = cIdxStub + 18;
				break;
			}

			// On Windows 7 SP1 (x64), Windows Server 2012 (x64), Windows Vista (x64) and Windows XP (x64):
			// 0F 05                        syscall           ; XOR'ing these bytes to obfuscate them when comparing below
			// C3                           retn
			if ((*(PUINT16)(pbCurrentByte + 8) ^ 0x0101) == 0x040e && *(pbCurrentByte + 10) == 0xc3) {
				cOffsetStub = cIdxStub + 8;
				break;
			}
		}
#else
		// On x86 ntdll, it starts like this:
		// B8 F1 00 00 00               mov     eax, 0F1h      ; syscall number
		//
		// If it is hooked a `jmp <offset>` will be found instead
		// E9 99 00 00 00               jmp     775ECAA1
		if (*pbCurrentByte == 0xb8 || *pbCurrentByte == 0xe9) {
			if (

				// Then, on Windows 10/11 WoW64 (x64):
				// BA 00 8F 31 4B               mov     edx, offset _Wow64SystemServiceCall@0 ; we cannot match on the offset since it changes
				// FF D2                        call    edx            ; Wow64SystemServiceCall()
				// C2 10 00                     retn    10h ; this can also be "C3   retn"
				*(pbCurrentByte + 5) == 0xba && *(PUINT16)(pbCurrentByte + 10) == 0xd2ff && (*(pbCurrentByte + 12) == 0xc2 || *(pbCurrentByte + 12) == 0xc3) ||

				// Windows 7 SP1 (x86), Windows Vista (x86) and Windows XP (x86):
				// BA 00 03 FE 7F               mov     edx, 7FFE0300h
				// FF 12                        call    dword ptr[edx]
				// C2 18 00		                retn    18h ; this can also be "C3   retn"
				*(pbCurrentByte + 5) == 0xba && *(PUINT16)(pbCurrentByte + 10) == 0x12ff && (*(pbCurrentByte + 12) == 0xc2 || *(pbCurrentByte + 12) == 0xc3) ||

				// On Windows 7 SP1 WoW64 (x64), it has two variants. So, let's ignore the first instruction and match the remaining bytes.
				// Variant #1:
				// 33 C9                        xor     ecx, ecx
				// 8D 54 24 04                  lea     edx, [esp+arg_0]
				// 64 FF 15 C0 00 00 00         call    large dword ptr fs:0C0h
				// 83 C4 04                     add     esp, 4
				// C2 0C 00                     retn    0Ch ; this can also be "C3   retn"
				*(PUINT64)(pbCurrentByte + 7) == 0xc015ff640424548d && *(PUINT32)(pbCurrentByte + 15) == 0x83000000 && *(PUINT16)(pbCurrentByte + 19) == 0x04c4 && (*(pbCurrentByte + 21) == 0xc2 || *(pbCurrentByte + 21) == 0xc3) ||

				// Variant #2:
				// B9 0C 00 00 00               mov     ecx, 0Ch
				// 8D 54 24 04                  lea     edx, [esp+arg_0]
				// 64 FF 15 C0 00 00 00         call    large dword ptr fs:0C0h
				// 83 C4 04                     add     esp, 4
				// C2 0C 00                     retn    0Ch ; this can also be "C3   retn"
				*(PUINT64)(pbCurrentByte + 10) == 0xc015ff640424548d && *(PUINT32)(pbCurrentByte + 18) == 0x83000000 && *(PUINT16)(pbCurrentByte + 22) == 0x04c4 && (*(pbCurrentByte + 24) == 0xc2 || *(pbCurrentByte + 24) == 0xc3) ||

				// On Windows Server 2012 WoW64 (x64)
				// 64 FF 15 C0 00 00 00         call    large dword ptr fs:0C0h
				// C2 0C 00                     retn    0Ch ; this can also be "C3   retn"
				(*(PUINT64)(pbCurrentByte + 5) == 0xc2000000c015ff64 || *(PUINT64)(pbCurrentByte + 5) == 0xc3000000c015ff64) ||

				// On Windows 10/11 WoW64 (x64) for one function (ZwQueryInformationProcess):
				// E8 00 00 00 00               call    $+5
				// 5A                           pop     edx
				// 80 7A 14 4B                  cmp     byte ptr[edx + 14h], 4Bh; 'K'
				// 75 0E                        jnz     short loc_4B2F4CDF
				// 64 FF 15 C0 00 00 00         call    large dword ptr fs : 0C0h
				// C2 14 00                     retn    14h
				*(PUINT64)(pbCurrentByte + 17) == 0xc2000000c015ff64 ||

				// On Windows 10, Windows 8, Windows 8.1 and Windows 8.1 SP1 (x86):
				// E8 03 00 00 00               call    sub_6A290C2D
				// C2 18 00                     retn    18h
				// 8B D4                        mov     edx, esp
				// 0F 34                        sysenter    ; XOR'ing these bytes to obfuscate them when comparing below
				// C3                           retn
				*(PUINT32)(pbCurrentByte + 5) == 0x000003e8 && *(PUINT16)(pbCurrentByte + 9) == 0xc200 && (*(PUINT32)(pbCurrentByte + 13) ^ 0x01010101) == 0x350ed58a && *(pbCurrentByte + 17) == 0xc3

				) {
				cOffsetStub = cIdxStub + 5;
				break;
			}
		}
#endif

	}

	if (cOffsetStub > 0) {
		pSyscall->pStub = (LPVOID)((PBYTE)pStub + cOffsetStub);
		return TRUE;
	}

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

				if (!ExtractSysCallData(SyscallList.Entries[i].pAddress, Syscalls[dwIdxSyscall]))
					return FALSE;
				Syscalls[dwIdxSyscall]->dwSyscallNr = i;
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
