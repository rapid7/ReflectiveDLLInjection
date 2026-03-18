#include "DirectSyscall.h"

//===============================================================================================//
// The following block of C functions (SyscallStub and all rdi* wrappers) acts as a bridge
// to our assembly trampolines. Compiler optimizations MUST be disabled for this entire
// block to ensure a predictable stack frame that the assembly code can correctly parse.
//
// Failure to do so can or will break the direct syscall mechanism.
//===============================================================================================//

#pragma optimize("g", off)
#ifdef __MINGW32__
#pragma GCC push_options
#pragma GCC optimize("O0")
#endif
// #ifdef ARKARI_OBFUSCATOR
// #pragma GCC push_options
// #pragma GCC optimize("O0")
// #pragma clang optimize off
// #endif

#pragma warning(disable : 4100) // Unreferenced parameter 'pSyscall' is intentionally handled by assembly.
COMPILER_OPTIONS NTSTATUS SyscallStub(Syscall *pSyscall, ULONG_PTR **lpArgs, DWORD dwNumberOfArgs)
{
	return DoSyscall(pSyscall->pStub, pSyscall->dwSyscallNr, lpArgs, dwNumberOfArgs);
}

#pragma warning(default : 4100)

COMPILER_OPTIONS NTSTATUS rdiNtAllocateVirtualMemory(Syscall *pSyscall, HANDLE hProcess, PVOID *pBaseAddress, ULONG_PTR pZeroBits, PSIZE_T pRegionSize, ULONG ulAllocationType, ULONG ulProtect)
{
	ULONG_PTR *lpArgs[] = { (ULONG_PTR *)hProcess, (ULONG_PTR *)pBaseAddress, (ULONG_PTR *)pZeroBits, (ULONG_PTR *)pRegionSize, (ULONG_PTR *)ulAllocationType, (ULONG_PTR *)ulProtect };
	return SyscallStub(pSyscall, &lpArgs, 6);
}
COMPILER_OPTIONS NTSTATUS rdiNtProtectVirtualMemory(Syscall *pSyscall, HANDLE hProcess, PVOID *pBaseAddress, PSIZE_T pNumberOfBytesToProtect, ULONG ulNewAccessProtection, PULONG ulOldAccessProtection)
{
	ULONG_PTR *lpArgs[] = { (ULONG_PTR *)hProcess, (ULONG_PTR *)pBaseAddress, (ULONG_PTR *)pNumberOfBytesToProtect, (ULONG_PTR *)ulNewAccessProtection, (ULONG_PTR *)ulOldAccessProtection };
	return SyscallStub(pSyscall, &lpArgs, 5);
}
COMPILER_OPTIONS NTSTATUS rdiNtFlushInstructionCache(Syscall *pSyscall, HANDLE hProcess, PVOID *pBaseAddress, SIZE_T FlushSize)
{
	ULONG_PTR *lpArgs[] = { (ULONG_PTR *)hProcess, (ULONG_PTR *)pBaseAddress, (ULONG_PTR *)FlushSize };
	return SyscallStub(pSyscall, &lpArgs, 3);
}
COMPILER_OPTIONS NTSTATUS rdiNtLockVirtualMemory(Syscall *pSyscall, HANDLE hProcess, PVOID *pBaseAddress, PSIZE_T NumberOfBytesToLock, ULONG MapType)
{
	ULONG_PTR *lpArgs[] = { (ULONG_PTR *)hProcess, (ULONG_PTR *)pBaseAddress, (ULONG_PTR *)NumberOfBytesToLock, (ULONG_PTR *)MapType };
	return SyscallStub(pSyscall, &lpArgs, 4);
}

//===============================================================================================//
// This function resolves the necessary information for direct syscall invocation. It uses
// a hybrid strategy.
//
// The core premise for all platforms is "Hell's Gate": sorting ntdll's Zw* exports by their
// memory address gives their true syscall number, which is the number the kernel expects.
//
// The verification and stub-finding logic then differs per platform:
//   - x86/x64: The function stubs are predictable. The 'syscall; ret' gadget used for
//     execution is at a fixed offset from the function's start, allowing for reliable
//     hook bypass.
//
//   - ARM64: On modern Windows, the function stubs are not simple wrappers around a generic
//     'svc #0'. Instead, the syscall number is encoded directly into the 'svc #<imm>'
//     instruction itself. This function uses a reverse-engineered formula to predict the
//     exact opcode of a given function's 'svc' instruction, verifying its integrity.
//     The "stub" we execute is the function address itself.
//===============================================================================================//
COMPILER_OPTIONS BOOL getSyscalls(PVOID pNtdllBase, Syscall *Syscalls[], DWORD dwSyscallSize)
{
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pNtdllBase;
	PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pNtdllBase + pDosHdr->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pNtdllBase + pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD pdwAddrOfFunctions = (PDWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfFunctions);
	PDWORD pdwAddrOfNames = (PDWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfNames);
	PWORD pwAddrOfNameOrdinales = (PWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfNameOrdinals);

	SYSCALL_LIST SyscallList;
	SyscallList.dwCount = 0;

	// STEP 1: Enumerate all functions exported from ntdll.dll that begin with "Zw".
	for (DWORD dwIdxfName = 0; dwIdxfName < pExportDir->NumberOfNames; dwIdxfName++)
	{
		PCHAR FunctionName = (PCHAR)((PBYTE)pNtdllBase + pdwAddrOfNames[dwIdxfName]);
		if (*(USHORT *)FunctionName == 0x775a) // "Zw" in little-endian
		{
			if (SyscallList.dwCount >= MAX_SYSCALLS)
				break;
			SyscallList.Entries[SyscallList.dwCount].dwCryptedHash = _hash(FunctionName);
			SyscallList.Entries[SyscallList.dwCount].pAddress = (PVOID)((PBYTE)pNtdllBase + pdwAddrOfFunctions[pwAddrOfNameOrdinales[dwIdxfName]]);
			SyscallList.dwCount++;
		}
	}

	// STEP 2: Sort the list of Zw* functions by their memory address.
	// The index 'i' of a function in this sorted list is its true syscall number. This holds for all architectures.
	for (DWORD i = 0; i < SyscallList.dwCount - 1; i++)
	{
		for (DWORD j = 0; j < SyscallList.dwCount - i - 1; j++)
		{
			if (SyscallList.Entries[j].pAddress > SyscallList.Entries[j + 1].pAddress)
			{
				SYSCALL_ENTRY TempEntry = SyscallList.Entries[j];
				SyscallList.Entries[j] = SyscallList.Entries[j + 1];
				SyscallList.Entries[j + 1] = TempEntry;
			}
		}
	}

	// STEP 3: Find the syscalls required by our loader and populate their structs.
	for (DWORD dwIdxSyscall = 0; dwIdxSyscall < dwSyscallSize; ++dwIdxSyscall)
	{
		for (DWORD i = 0; i < SyscallList.dwCount; ++i)
		{
			if (SyscallList.Entries[i].dwCryptedHash == Syscalls[dwIdxSyscall]->dwCryptedHash)
			{
				Syscalls[dwIdxSyscall]->dwSyscallNr = i; // The index is the true syscall number.

#if defined(_M_ARM64)
				// For ARM64, we verify that the function's machine code matches the expected 'svc'
				// instruction for the given syscall number. The formula was derived from reverse
				// engineering ntdll.dll on Windows 11 ARM64, which shows a predictable pattern.
				//   ntdll!ZwAllocateVirtualMemory:
				//   d4000301  svc  #0x18  ; Syscall number 24 (0x18)
				//   d65f03c0  ret
				DWORD expectedOpcode = 0xd4000001 + (i * 0x20);
				if (*(PDWORD)SyscallList.Entries[i].pAddress == expectedOpcode)
				{
					// The "stub" to call is the function's address itself. The assembly
					// trampoline will call this directly, executing the 'svc' instruction.
					Syscalls[dwIdxSyscall]->pStub = SyscallList.Entries[i].pAddress;
				}
#else
				// For x86/x64, the "stub" is a pointer to the 'syscall; ret' gadget inside
				// the function, which is at a predictable offset. This bypasses API hooks.
#if defined(_M_X64)
				// On x64, the function starts like this:
				//   4C 8B D1        mov r10, rcx
				//   B8 <num>..      mov eax, <syscall_num>
				//   0F 05           syscall
				//   C3              ret
				// The gadget we jump to is at +8 bytes from the start.
				Syscalls[dwIdxSyscall]->pStub = (PVOID)((PBYTE)SyscallList.Entries[i].pAddress + 8);
#elif defined(_M_IX86)
				// On x86, the stub often looks like:
				//   B8 <num>..      mov eax, <syscall_num>
				//   BA <ptr>..      mov edx, <syscall_dispatch_ptr>
				//   FF D2           call edx  <-- This call is 5 bytes.
				// The 'call' instruction itself is used as our gadget. Our trampoline will 'ret'
				// to this location, effectively executing the call to the syscall dispatcher.
				Syscalls[dwIdxSyscall]->pStub = (PVOID)((PBYTE)SyscallList.Entries[i].pAddress + 5);
#endif
#endif
				break;
			}
		}
	}

	// Final validation to ensure all required syscalls were successfully found and verified.
	for (DWORD i = 0; i < dwSyscallSize; ++i)
	{
		if (Syscalls[i]->pStub == NULL)
			return FALSE;
	}

	return TRUE;
}