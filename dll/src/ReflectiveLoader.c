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

#if defined(_M_ARM64) && defined(_MSC_VER)
#include <arm64intr.h> 
#endif

#include "ReflectiveLoader.h" 
#include "DirectSyscall.c"    

HINSTANCE hAppInstance = NULL;

#if !defined(_M_ARM64) 
    #ifdef __MINGW32__
    #define WIN_GET_CALLER() __builtin_extract_return_addr(__builtin_return_address(0))
    #else
    #pragma intrinsic(_ReturnAddress)
    #define WIN_GET_CALLER() _ReturnAddress()
    #endif
    __declspec(noinline) ULONG_PTR caller(VOID) { return (ULONG_PTR)WIN_GET_CALLER(); }
#endif


#ifdef RDIDLL_NOEXPORT
#define RDIDLLEXPORT
#else
#define RDIDLLEXPORT DLLEXPORT
#endif


#if defined(_M_ARM64)


__declspec(noinline) ULONG_PTR GetIp_ARM64(VOID)
{
	return (ULONG_PTR)_ReturnAddress();
}


static ULONG_PTR Arm64ReflectiveLoaderLogic(LPVOID lpLoaderParameter)
{
	LOADLIBRARYA_FN fnLoadLibraryA_arm64 = NULL;
	GETPROCADDRESS_FN fnGetProcAddress_arm64 = NULL;
	VIRTUALALLOC_FN fnVirtualAlloc_arm64 = NULL;
	NTFLUSHINSTRUCTIONCACHE_FN fnNtFlushInstructionCache_arm64 = NULL;

	ULONG_PTR uiDllBase;
	ULONG_PTR uiPeb_arm64;
	ULONG_PTR uiKernel32Base_arm64 = 0;
	ULONG_PTR uiNtdllBase_arm64 = 0;

	uiDllBase = GetIp_ARM64();

	while (TRUE)
	{
		if (((PIMAGE_DOS_HEADER)uiDllBase)->e_magic == IMAGE_DOS_SIGNATURE)
		{
			ULONG_PTR uiHeader = uiDllBase + ((PIMAGE_DOS_HEADER)uiDllBase)->e_lfanew;
			if (((PIMAGE_NT_HEADERS)uiHeader)->Signature == IMAGE_NT_SIGNATURE)
				break;
		}
		uiDllBase--;
		if (!uiDllBase) return 0;
	}

	ULONG_PTR tebBase = 0;
#if defined(_MSC_VER)
	tebBase = __readx18word(0); 
	uiPeb_arm64 = *(ULONG_PTR *)(tebBase + 0x60);
#elif defined(__GNUC__) || defined(__clang__)
	#warning "ARM64 PEB access via X18 needs specific intrinsic for this compiler in Arm64ReflectiveLoaderLogic"
	__asm__ ("mrs %0, TPIDR_EL0" : "=r" (tebBase));
    uiPeb_arm64 = *(ULONG_PTR *)(tebBase + 0x60);
    if(!uiPeb_arm64) return 0;
#else
	#error "Unsupported ARM64 compiler for PEB access via X18 in Arm64ReflectiveLoaderLogic"
	return 0;
#endif

	PPEB_LDR_ARM64 pPebTyped_arm64 = (PPEB_LDR_ARM64)uiPeb_arm64;
	if (!pPebTyped_arm64 || !pPebTyped_arm64->Ldr) return 0;

	PPEB_LDR_DATA_LDR_ARM64 pLdr_arm64 = pPebTyped_arm64->Ldr;
	PLIST_ENTRY pModuleList_arm64 = &(pLdr_arm64->InMemoryOrderModuleList);
	PLIST_ENTRY pCurrentEntry_arm64 = pModuleList_arm64->Flink;

	while (pCurrentEntry_arm64 != pModuleList_arm64)
	{
		PLDR_DATA_TABLE_ENTRY_LDR_ARM64 pEntry_arm64 = (PLDR_DATA_TABLE_ENTRY_LDR_ARM64)CONTAINING_RECORD(pCurrentEntry_arm64, LDR_DATA_TABLE_ENTRY_LDR_ARM64, InMemoryOrderLinks);
		if (pEntry_arm64->BaseDllName.Length > 0 && pEntry_arm64->BaseDllName.Buffer != NULL)
		{
			DWORD dwModuleHash = 0;
			USHORT usCounter = pEntry_arm64->BaseDllName.Length;
			BYTE *pNameByte = (BYTE *)pEntry_arm64->BaseDllName.Buffer;

			do
			{
				dwModuleHash = ror_dword_loader_arm64(dwModuleHash);
				if (*pNameByte >= 'a' && *pNameByte <= 'z')
				{
					dwModuleHash += (*pNameByte - 0x20);
				}
				else
				{
					dwModuleHash += *pNameByte;
				}
				pNameByte++;
			} while (--usCounter);

			if (dwModuleHash == KERNEL32DLL_HASH_ARM64)
			{
				uiKernel32Base_arm64 = (ULONG_PTR)pEntry_arm64->DllBase;
			}
			else if (dwModuleHash == NTDLLDLL_HASH_ARM64)
			{
				uiNtdllBase_arm64 = (ULONG_PTR)pEntry_arm64->DllBase;
			}
		}
		if (uiKernel32Base_arm64 && uiNtdllBase_arm64) break;
		pCurrentEntry_arm64 = pCurrentEntry_arm64->Flink;
	}

	if (!uiKernel32Base_arm64 || !uiNtdllBase_arm64) return 0;

	PIMAGE_NT_HEADERS pOldNtHeaders_arm64 = (PIMAGE_NT_HEADERS)(uiDllBase + ((PIMAGE_DOS_HEADER)uiDllBase)->e_lfanew);

	ULONG_PTR uiExportDir_arm64 = uiKernel32Base_arm64 + ((PIMAGE_NT_HEADERS)(uiKernel32Base_arm64 + ((PIMAGE_DOS_HEADER)uiKernel32Base_arm64)->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory_arm64 = (PIMAGE_EXPORT_DIRECTORY)uiExportDir_arm64;
	ULONG_PTR uiAddressOfNames_arm64 = uiKernel32Base_arm64 + pExportDirectory_arm64->AddressOfNames;
	ULONG_PTR uiAddressOfFunctions_arm64 = uiKernel32Base_arm64 + pExportDirectory_arm64->AddressOfFunctions;
	ULONG_PTR uiAddressOfNameOrdinals_arm64 = uiKernel32Base_arm64 + pExportDirectory_arm64->AddressOfNameOrdinals;

	for (DWORD i = 0; i < pExportDirectory_arm64->NumberOfNames; i++)
	{
		char *cName = (char *)(uiKernel32Base_arm64 + ((DWORD *)uiAddressOfNames_arm64)[i]);
		DWORD dwHashVal = hash_string_loader_arm64(cName);
		if (dwHashVal == LOADLIBRARYA_HASH_ARM64)
			fnLoadLibraryA_arm64 = (LOADLIBRARYA_FN)(uiKernel32Base_arm64 + ((DWORD *)uiAddressOfFunctions_arm64)[((WORD *)uiAddressOfNameOrdinals_arm64)[i]]);
		else if (dwHashVal == GETPROCADDRESS_HASH_ARM64)
			fnGetProcAddress_arm64 = (GETPROCADDRESS_FN)(uiKernel32Base_arm64 + ((DWORD *)uiAddressOfFunctions_arm64)[((WORD *)uiAddressOfNameOrdinals_arm64)[i]]);
		else if (dwHashVal == VIRTUALALLOC_HASH_ARM64)
			fnVirtualAlloc_arm64 = (VIRTUALALLOC_FN)(uiKernel32Base_arm64 + ((DWORD *)uiAddressOfFunctions_arm64)[((WORD *)uiAddressOfNameOrdinals_arm64)[i]]);
		if (fnLoadLibraryA_arm64 && fnGetProcAddress_arm64 && fnVirtualAlloc_arm64) break;
	}

	if (!fnLoadLibraryA_arm64 || !fnGetProcAddress_arm64 || !fnVirtualAlloc_arm64) return 0;

	uiExportDir_arm64 = uiNtdllBase_arm64 + ((PIMAGE_NT_HEADERS)(uiNtdllBase_arm64 + ((PIMAGE_DOS_HEADER)uiNtdllBase_arm64)->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	pExportDirectory_arm64 = (PIMAGE_EXPORT_DIRECTORY)uiExportDir_arm64;
	uiAddressOfNames_arm64 = uiNtdllBase_arm64 + pExportDirectory_arm64->AddressOfNames;
	uiAddressOfFunctions_arm64 = uiNtdllBase_arm64 + pExportDirectory_arm64->AddressOfFunctions;
	uiAddressOfNameOrdinals_arm64 = uiNtdllBase_arm64 + pExportDirectory_arm64->AddressOfNameOrdinals;

	for (DWORD i = 0; i < pExportDirectory_arm64->NumberOfNames; i++)
	{
		char *cName = (char *)(uiNtdllBase_arm64 + ((DWORD *)uiAddressOfNames_arm64)[i]);
		if (hash_string_loader_arm64(cName) == NTFLUSHINSTRUCTIONCACHE_HASH_ARM64)
		{
			fnNtFlushInstructionCache_arm64 = (NTFLUSHINSTRUCTIONCACHE_FN)(uiNtdllBase_arm64 + ((DWORD *)uiAddressOfFunctions_arm64)[((WORD *)uiAddressOfNameOrdinals_arm64)[i]]);
			break;
		}
	}

	if (!fnNtFlushInstructionCache_arm64) return 0;

	ULONG_PTR uiNewImageBase_arm64 = (ULONG_PTR)fnVirtualAlloc_arm64(NULL, pOldNtHeaders_arm64->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!uiNewImageBase_arm64) return 0;

	for (DWORD i = 0; i < pOldNtHeaders_arm64->OptionalHeader.SizeOfHeaders; i++)
	{
		((BYTE *)uiNewImageBase_arm64)[i] = ((BYTE *)uiDllBase)[i];
	}

	PIMAGE_SECTION_HEADER pSectionHeader_arm64 = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&pOldNtHeaders_arm64->OptionalHeader + pOldNtHeaders_arm64->FileHeader.SizeOfOptionalHeader);
	for (WORD i = 0; i < pOldNtHeaders_arm64->FileHeader.NumberOfSections; i++)
	{
		for (DWORD j = 0; j < pSectionHeader_arm64[i].SizeOfRawData; j++)
		{
			((BYTE *)(uiNewImageBase_arm64 + pSectionHeader_arm64[i].VirtualAddress))[j] = ((BYTE *)(uiDllBase + pSectionHeader_arm64[i].PointerToRawData))[j];
		}
	}

	ULONG_PTR uiDelta_arm64 = uiNewImageBase_arm64 - pOldNtHeaders_arm64->OptionalHeader.ImageBase;
	PIMAGE_DATA_DIRECTORY pRelocationData_arm64 = &pOldNtHeaders_arm64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	if (pRelocationData_arm64->Size > 0 && uiDelta_arm64 != 0)
	{
		PIMAGE_BASE_RELOCATION pRelocBlock_arm64 = (PIMAGE_BASE_RELOCATION)(uiNewImageBase_arm64 + pRelocationData_arm64->VirtualAddress);
		while (pRelocBlock_arm64->VirtualAddress)
		{
			DWORD dwEntryCount_arm64 = (pRelocBlock_arm64->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC_LDR_ARM64);
			PIMAGE_RELOC_LDR_ARM64 pRelocEntry_arm64 = (PIMAGE_RELOC_LDR_ARM64)((ULONG_PTR)pRelocBlock_arm64 + sizeof(IMAGE_BASE_RELOCATION));
			for (DWORD k = 0; k < dwEntryCount_arm64; k++)
			{
				if (pRelocEntry_arm64[k].type == IMAGE_REL_BASED_DIR64)
				{
					*(ULONG_PTR *)(uiNewImageBase_arm64 + pRelocBlock_arm64->VirtualAddress + pRelocEntry_arm64[k].offset) += uiDelta_arm64;
				}
			}
			pRelocBlock_arm64 = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pRelocBlock_arm64 + pRelocBlock_arm64->SizeOfBlock);
		}
	}

	PIMAGE_DATA_DIRECTORY pImportData_arm64 = &pOldNtHeaders_arm64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (pImportData_arm64->Size > 0)
	{
		PIMAGE_IMPORT_DESCRIPTOR pImportDesc_arm64 = (PIMAGE_IMPORT_DESCRIPTOR)(uiNewImageBase_arm64 + pImportData_arm64->VirtualAddress);
		while (pImportDesc_arm64->Name)
		{
			char *sModuleName = (char *)(uiNewImageBase_arm64 + pImportDesc_arm64->Name);
			HINSTANCE hModule = fnLoadLibraryA_arm64(sModuleName);
			if (hModule)
			{
				PIMAGE_THUNK_DATA pOriginalFirstThunk_arm64 = (PIMAGE_THUNK_DATA)(uiNewImageBase_arm64 + pImportDesc_arm64->OriginalFirstThunk);
				PIMAGE_THUNK_DATA pFirstThunk_arm64 = (PIMAGE_THUNK_DATA)(uiNewImageBase_arm64 + pImportDesc_arm64->FirstThunk);
				if (!pOriginalFirstThunk_arm64)
					pOriginalFirstThunk_arm64 = pFirstThunk_arm64;

				while (pOriginalFirstThunk_arm64->u1.AddressOfData)
				{
					FARPROC pfnImportedFunc;
					if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk_arm64->u1.Ordinal))
					{
						pfnImportedFunc = fnGetProcAddress_arm64(hModule, (LPCSTR)(pOriginalFirstThunk_arm64->u1.Ordinal & 0xFFFF));
					}
					else
					{
						PIMAGE_IMPORT_BY_NAME pImportByName_arm64 = (PIMAGE_IMPORT_BY_NAME)(uiNewImageBase_arm64 + pOriginalFirstThunk_arm64->u1.AddressOfData);
						pfnImportedFunc = fnGetProcAddress_arm64(hModule, pImportByName_arm64->Name);
					}
					pFirstThunk_arm64->u1.Function = (ULONG_PTR)pfnImportedFunc;
					pOriginalFirstThunk_arm64++;
					pFirstThunk_arm64++;
				}
			}
			pImportDesc_arm64++;
		}
	}

	hAppInstance = (HINSTANCE)uiNewImageBase_arm64;

	DLLMAIN fnDllEntry_arm64 = (DLLMAIN)(uiNewImageBase_arm64 + pOldNtHeaders_arm64->OptionalHeader.AddressOfEntryPoint);
	if (fnDllEntry_arm64)
	{
		fnNtFlushInstructionCache_arm64((HANDLE)-1, NULL, 0);
		fnDllEntry_arm64((HINSTANCE)uiNewImageBase_arm64, DLL_PROCESS_ATTACH, lpLoaderParameter);
	}
	return uiNewImageBase_arm64; 
}

#else 


typedef struct
{
	LOADLIBRARYA pLoadLibraryA;
	GETPROCADDRESS pGetProcAddress;
	PVOID pNtdllBase; 
} RESOLVED_IMPORTS_X86_X64;


static BOOL FindCurrentImageBase_X86_X64(OUT ULONG_PTR *puiCurrentImageBase)
{
	ULONG_PTR uiAddress = caller(); 
	if (puiCurrentImageBase == NULL) return FALSE;

	while (TRUE)
	{
		if (((PIMAGE_DOS_HEADER)uiAddress)->e_magic == IMAGE_DOS_SIGNATURE)
		{
			ULONG_PTR e_lfanew_val = ((PIMAGE_DOS_HEADER)uiAddress)->e_lfanew;
			if (e_lfanew_val >= sizeof(IMAGE_DOS_HEADER) && e_lfanew_val < 1024)
			{
				if (((PIMAGE_NT_HEADERS)(uiAddress + e_lfanew_val))->Signature == IMAGE_NT_SIGNATURE)
				{
					*puiCurrentImageBase = uiAddress;
					return TRUE;
				}
			}
		}
		uiAddress--;
		if (!uiAddress) return FALSE; 
	}
	return FALSE; 
}

static BOOL ResolveCoreImportsFromPeb_X86_X64(OUT RESOLVED_IMPORTS_X86_X64 *pResolvedImports)
{
	ULONG_PTR uiPebLdrData;
	PLIST_ENTRY pModuleListHead;
	PLIST_ENTRY pCurrentListEntry;
    _PPEB_X86_X64 pPeb; 

	if (pResolvedImports == NULL) return FALSE;
	pResolvedImports->pLoadLibraryA = NULL;
	pResolvedImports->pGetProcAddress = NULL;
	pResolvedImports->pNtdllBase = NULL;

#if defined(_M_X64) 
	pPeb = (_PPEB_X86_X64)__readgsqword(0x60);
#elif defined(_M_IX86) 
	pPeb = (_PPEB_X86_X64)__readfsdword(0x30);
#elif defined(WIN_ARM)
    #if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__) 
        pPeb = (_PPEB_X86_X64)(*(DWORD *)((BYTE *)_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30));
    #else
	    #error "WIN_ARM (ARM32) defined, but compiler not recognized for _MoveFromCoprocessor support."
        return FALSE;
    #endif
#else
    #error "Unsupported x86/x64/WIN_ARM sub-architecture for PEB access in ReflectiveLoader"
    return FALSE;
#endif

    if(!pPeb || !pPeb->pLdr) return FALSE;
	uiPebLdrData = (ULONG_PTR)pPeb->pLdr;

	pModuleListHead = &((PPEB_LDR_DATA)uiPebLdrData)->InMemoryOrderModuleList;
	pCurrentListEntry = pModuleListHead->Flink;

	while (pCurrentListEntry != pModuleListHead)
	{
		PLDR_DATA_TABLE_ENTRY pCurrentEntry = CONTAINING_RECORD(pCurrentListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList);
		PBYTE pByteModuleNameBuffer = (PBYTE)pCurrentEntry->BaseDllName.pBuffer;
		USHORT nameLengthInBytes = pCurrentEntry->BaseDllName.Length;
		DWORD currentModuleNameHash = 0;

		if (pByteModuleNameBuffer == NULL || nameLengthInBytes == 0)
		{
			pCurrentListEntry = pCurrentListEntry->Flink;
			continue;
		}
        
        PBYTE tempNamePtr = pByteModuleNameBuffer;
		while (nameLengthInBytes > 0)
		{
			currentModuleNameHash = ror(currentModuleNameHash); 
			BYTE currentByte = *tempNamePtr;
			if (currentByte >= 'a' && currentByte <= 'z')
				currentModuleNameHash += (currentByte - ('a' - 'A'));
			else
				currentModuleNameHash += currentByte;
			tempNamePtr++;
            nameLengthInBytes--;
		}

		if (currentModuleNameHash == KERNEL32DLL_HASH) 
		{
			ULONG_PTR uiModuleBase = (ULONG_PTR)pCurrentEntry->DllBase;
			PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uiModuleBase + ((PIMAGE_DOS_HEADER)uiModuleBase)->e_lfanew);
			PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(uiModuleBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			PDWORD pdwAddressOfNames = (PDWORD)(uiModuleBase + pExportDir->AddressOfNames);
			PWORD pwAddressOfNameOrdinals = (PWORD)(uiModuleBase + pExportDir->AddressOfNameOrdinals);
			PDWORD pdwAddressOfFunctions = (PDWORD)(uiModuleBase + pExportDir->AddressOfFunctions);
			USHORT usFoundCount = 0;

			for (DWORD i = 0; i < pExportDir->NumberOfNames && usFoundCount < 2; i++)
			{
				DWORD dwFuncNameHash = _hash((char *)(uiModuleBase + pdwAddressOfNames[i])); 
				if (dwFuncNameHash == LOADLIBRARYA_HASH) 
				{
					pResolvedImports->pLoadLibraryA = (LOADLIBRARYA)(uiModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinals[i]]);
					usFoundCount++;
				}
				else if (dwFuncNameHash == GETPROCADDRESS_HASH) 
				{
					pResolvedImports->pGetProcAddress = (GETPROCADDRESS)(uiModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinals[i]]);
					usFoundCount++;
				}
			}
		}
		else if (currentModuleNameHash == NTDLLDLL_HASH) 
		{
			pResolvedImports->pNtdllBase = pCurrentEntry->DllBase;
		}

		if (pResolvedImports->pLoadLibraryA && pResolvedImports->pGetProcAddress && pResolvedImports->pNtdllBase)
			return TRUE;

		pCurrentListEntry = pCurrentListEntry->Flink;
	}
	return FALSE;
}

static BOOL SetupAndResolveSyscalls_X86_X64(
	PVOID pNtdllBase,
	OUT Syscall *pZwAllocateVirtualMemory,
	OUT Syscall *pZwProtectVirtualMemory,
	OUT Syscall *pZwFlushInstructionCache
#ifdef ENABLE_STOPPAGING
	, OUT Syscall *pZwLockVirtualMemory
#endif
)
{
#ifdef ENABLE_STOPPAGING
	Syscall *SyscallsToResolve[4];
	const DWORD dwNumSyscalls = 4;
#else
	Syscall *SyscallsToResolve[3];
	const DWORD dwNumSyscalls = 3;
#endif

	pZwAllocateVirtualMemory->dwCryptedHash = ZWALLOCATEVIRTUALMEMORY_HASH;
	pZwAllocateVirtualMemory->dwNumberOfArgs = 6;
	SyscallsToResolve[0] = pZwAllocateVirtualMemory;

	pZwProtectVirtualMemory->dwCryptedHash = ZWPROTECTVIRTUALMEMORY_HASH;
	pZwProtectVirtualMemory->dwNumberOfArgs = 5;
	SyscallsToResolve[1] = pZwProtectVirtualMemory;

	pZwFlushInstructionCache->dwCryptedHash = ZWFLUSHINSTRUCTIONCACHE_HASH;
	pZwFlushInstructionCache->dwNumberOfArgs = 3;
	SyscallsToResolve[2] = pZwFlushInstructionCache;

#ifdef ENABLE_STOPPAGING
    if(pZwLockVirtualMemory) { 
	    pZwLockVirtualMemory->dwCryptedHash = ZWLOCKVIRTUALMEMORY_HASH; 
	    pZwLockVirtualMemory->dwNumberOfArgs = 4;
	    SyscallsToResolve[3] = pZwLockVirtualMemory;
    } else {
        if (dwNumSyscalls == 4) return FALSE;
    }
#endif
	return getSyscalls(pNtdllBase, SyscallsToResolve, dwNumSyscalls);
}

static PVOID AllocateNewImageMemory_X86_X64(PIMAGE_NT_HEADERS pCurrentImageNtHeaders, Syscall *pAllocSyscall
#ifdef ENABLE_STOPPAGING
									, Syscall *pLockSyscall
#endif
)
{
	PVOID pNewImageBase = NULL;
	SIZE_T imageRegionSize = pCurrentImageNtHeaders->OptionalHeader.SizeOfImage;

	if (rdiNtAllocateVirtualMemory(pAllocSyscall, (HANDLE)-1, &pNewImageBase, (ULONG_PTR)0, &imageRegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) != 0)
	{
		return NULL;
	}

#ifdef ENABLE_STOPPAGING
	SIZE_T lockRegionSize = imageRegionSize;
	if (pLockSyscall && pLockSyscall->pStub != NULL)
	{ 
		rdiNtLockVirtualMemory(pLockSyscall, (HANDLE)-1, &pNewImageBase, &lockRegionSize, 1);
	}
#endif
	return pNewImageBase;
}

static void CopyPEHeadersAndSections_X86_X64(ULONG_PTR uiCurrentImageBase, ULONG_PTR uiNewImageBase, PIMAGE_NT_HEADERS pCurrentImageNtHeaders)
{
	ULONG_PTR pSource, pDestination;
	SIZE_T sizeToCopy;

	sizeToCopy = pCurrentImageNtHeaders->OptionalHeader.SizeOfHeaders;
	pSource = uiCurrentImageBase;
	pDestination = uiNewImageBase;
	while (sizeToCopy--)
		*(BYTE *)pDestination++ = *(BYTE *)pSource++;

	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&pCurrentImageNtHeaders->OptionalHeader + pCurrentImageNtHeaders->FileHeader.SizeOfOptionalHeader);
	USHORT usNumberOfSections = pCurrentImageNtHeaders->FileHeader.NumberOfSections;

	while (usNumberOfSections--)
	{
		pDestination = uiNewImageBase + pSectionHeader->VirtualAddress;
		pSource = uiCurrentImageBase + pSectionHeader->PointerToRawData;
		sizeToCopy = pSectionHeader->SizeOfRawData;
		while (sizeToCopy--)
			*(BYTE *)pDestination++ = *(BYTE *)pSource++;
		pSectionHeader++;
	}
}

static BOOL ProcessImageImports_X86_X64(ULONG_PTR uiNewImageBase, PIMAGE_NT_HEADERS pNewImageNtHeaders, RESOLVED_IMPORTS_X86_X64 *pImports)
{
	PIMAGE_DATA_DIRECTORY pImportDataDir = &pNewImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (pImportDataDir->VirtualAddress == 0 || pImportDataDir->Size == 0)
		return TRUE;

	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(uiNewImageBase + pImportDataDir->VirtualAddress);

	while (pImportDescriptor->Characteristics)
	{
		ULONG_PTR uiImportedLibBase = (ULONG_PTR)pImports->pLoadLibraryA((LPCSTR)(uiNewImageBase + pImportDescriptor->Name));
		if (!uiImportedLibBase)
		{
			pImportDescriptor++;
			continue;
		}

		PIMAGE_THUNK_DATA pOriginalFirstThunk = NULL;
		if (pImportDescriptor->OriginalFirstThunk)
			pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(uiNewImageBase + pImportDescriptor->OriginalFirstThunk);

		PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(uiNewImageBase + pImportDescriptor->FirstThunk);
		PIMAGE_THUNK_DATA pThunkToReadFrom = pOriginalFirstThunk ? pOriginalFirstThunk : pFirstThunk;

		while (pThunkToReadFrom->u1.AddressOfData)
		{
			if (IMAGE_SNAP_BY_ORDINAL(pThunkToReadFrom->u1.Ordinal))
			{
				PIMAGE_NT_HEADERS pImportedNtHeaders = (PIMAGE_NT_HEADERS)(uiImportedLibBase + ((PIMAGE_DOS_HEADER)uiImportedLibBase)->e_lfanew);
				PIMAGE_EXPORT_DIRECTORY pImportedExportDir = (PIMAGE_EXPORT_DIRECTORY)(uiImportedLibBase + pImportedNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
				PDWORD pAddressOfFunctions = (PDWORD)(uiImportedLibBase + pImportedExportDir->AddressOfFunctions);
				ULONG_PTR uiFunctionAddress = uiImportedLibBase + pAddressOfFunctions[IMAGE_ORDINAL(pThunkToReadFrom->u1.Ordinal) - pImportedExportDir->Base];
				pFirstThunk->u1.Function = uiFunctionAddress;
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(uiNewImageBase + pThunkToReadFrom->u1.AddressOfData);
				pFirstThunk->u1.Function = (ULONG_PTR)pImports->pGetProcAddress((HMODULE)uiImportedLibBase, (LPCSTR)pImportByName->Name);
			}
			pFirstThunk++;
			pThunkToReadFrom++;
		}
		pImportDescriptor++;
	}
	return TRUE;
}

static BOOL ProcessImageRelocations_X86_X64(ULONG_PTR uiNewImageBase, PIMAGE_NT_HEADERS pNewImageNtHeaders, PIMAGE_NT_HEADERS pCurrentImageNtHeaders)
{
	ULONG_PTR relocationDelta = uiNewImageBase - pCurrentImageNtHeaders->OptionalHeader.ImageBase;
	if (relocationDelta == 0) return TRUE;

	PIMAGE_DATA_DIRECTORY pRelocDataDir = &pNewImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (pRelocDataDir->VirtualAddress == 0 || pRelocDataDir->Size == 0) return TRUE;

	PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)(uiNewImageBase + pRelocDataDir->VirtualAddress);
	ULONG_PTR uiRelocEnd = (ULONG_PTR)pBaseRelocation + pRelocDataDir->Size;

	while ((ULONG_PTR)pBaseRelocation < uiRelocEnd && pBaseRelocation->SizeOfBlock)
	{
		ULONG_PTR relocBlockBaseVA = uiNewImageBase + pBaseRelocation->VirtualAddress;
		DWORD numEntriesInBlock = (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC_X86_X64); 
		PIMAGE_RELOC_X86_X64 pCurrentRelocEntry = (PIMAGE_RELOC_X86_X64)((ULONG_PTR)pBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));

		while (numEntriesInBlock--)
		{
			ULONG_PTR patchTargetAddress = relocBlockBaseVA + pCurrentRelocEntry->offset;
			switch (pCurrentRelocEntry->type)
			{
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				*(DWORD *)patchTargetAddress += (DWORD)relocationDelta;
				break;
			case IMAGE_REL_BASED_DIR64:
                #if defined(_M_X64) 
				    *(ULONG_PTR *)patchTargetAddress += relocationDelta;
                #endif
				break;
#if defined(WIN_ARM) 
			case IMAGE_REL_BASED_ARM_MOV32T: 
			{
				#if defined(ARM_MOV_MASK) && defined(ARM_MOVT) && defined(ARM_MOV_MASK2)
                DWORD dwInstruction = *(DWORD *)(patchTargetAddress + sizeof(DWORD)); 
				dwInstruction = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
				if ((dwInstruction & ARM_MOV_MASK) == ARM_MOVT) 
				{
					WORD wImm = (WORD)(dwInstruction & 0x000000FF);
					wImm |= (WORD)((dwInstruction & 0x00007000) >> 4);
					wImm |= (WORD)((dwInstruction & 0x04000000) >> 15);
					wImm |= (WORD)((dwInstruction & 0x000F0000) >> 4);
					DWORD dwAddress = ((WORD)HIWORD(relocationDelta) + wImm) & 0xFFFF;
					DWORD newInstruction = (DWORD)(dwInstruction & ARM_MOV_MASK2); 
					newInstruction |= (DWORD)(dwAddress & 0x00FF);
					newInstruction |= (DWORD)(dwAddress & 0x0700) << 4;
					newInstruction |= (DWORD)(dwAddress & 0x0800) << 15;
					newInstruction |= (DWORD)(dwAddress & 0xF000) << 4;
					*(DWORD *)(patchTargetAddress + sizeof(DWORD)) = MAKELONG(HIWORD(newInstruction), LOWORD(newInstruction));
				}
                #else
                #warning "ARM32 relocation macros (ARM_MOV_MASK, etc.) not defined. Skipping IMAGE_REL_BASED_ARM_MOV32T."
                #endif
				break;
			}
#endif
			case IMAGE_REL_BASED_HIGH:
				*(WORD *)patchTargetAddress += HIWORD(relocationDelta);
				break;
			case IMAGE_REL_BASED_LOW:
				*(WORD *)patchTargetAddress += LOWORD(relocationDelta);
				break;
			default:
				break;
			}
			pCurrentRelocEntry++;
		}
		pBaseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pBaseRelocation + pBaseRelocation->SizeOfBlock);
	}
	return TRUE;
}

static BOOL ApplySectionProtections_X86_X64(ULONG_PTR uiNewImageBase, PIMAGE_NT_HEADERS pNewImageNtHeaders, Syscall *pProtectSyscall)
{
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNewImageNtHeaders);
	USHORT usNumberOfSections = pNewImageNtHeaders->FileHeader.NumberOfSections;
	DWORD dwOldProtect;

	while (usNumberOfSections--)
	{
		PVOID pSectionBaseAddress = (PVOID)(uiNewImageBase + pSectionHeader->VirtualAddress);
		SIZE_T sizeToProtect = pSectionHeader->SizeOfRawData;
		DWORD dwSectionProtection = 0;
		DWORD characteristics = pSectionHeader->Characteristics;

		if (characteristics & IMAGE_SCN_MEM_WRITE)
			dwSectionProtection = PAGE_WRITECOPY;
		if (characteristics & IMAGE_SCN_MEM_READ)
			dwSectionProtection = PAGE_READONLY;
		if ((characteristics & IMAGE_SCN_MEM_WRITE) && (characteristics & IMAGE_SCN_MEM_READ))
			dwSectionProtection = PAGE_READWRITE;
		if (characteristics & IMAGE_SCN_MEM_EXECUTE)
			dwSectionProtection = PAGE_EXECUTE;
		if ((characteristics & IMAGE_SCN_MEM_EXECUTE) && (characteristics & IMAGE_SCN_MEM_WRITE))
			dwSectionProtection = PAGE_EXECUTE_WRITECOPY;
		if ((characteristics & IMAGE_SCN_MEM_EXECUTE) && (characteristics & IMAGE_SCN_MEM_READ))
			dwSectionProtection = PAGE_EXECUTE_READ;
		if ((characteristics & IMAGE_SCN_MEM_EXECUTE) && (characteristics & IMAGE_SCN_MEM_WRITE) && (characteristics & IMAGE_SCN_MEM_READ))
			dwSectionProtection = PAGE_EXECUTE_READWRITE;

		if (sizeToProtect > 0 && dwSectionProtection != 0)
		{
			if (rdiNtProtectVirtualMemory(pProtectSyscall, (HANDLE)-1, &pSectionBaseAddress, &sizeToProtect, dwSectionProtection, &dwOldProtect) != 0)
			{
				return FALSE;
			}
		}
		pSectionHeader++;
	}
	return TRUE;
}

static BOOL ExecuteDllEntryPoint_X86_X64(ULONG_PTR uiNewImageBase, PIMAGE_NT_HEADERS pNewImageNtHeaders, LPVOID lpParameter, Syscall *pFlushCacheSyscall)
{
	if (pNewImageNtHeaders->OptionalHeader.AddressOfEntryPoint == 0) return TRUE;

	ULONG_PTR entryPointVA = uiNewImageBase + pNewImageNtHeaders->OptionalHeader.AddressOfEntryPoint;
    
	rdiNtFlushInstructionCache(pFlushCacheSyscall, (HANDLE)-1, NULL, 0);

#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
	return ((DLLMAIN)entryPointVA)((HINSTANCE)uiNewImageBase, DLL_PROCESS_ATTACH, lpParameter) == TRUE;
#else
	return ((DLLMAIN)entryPointVA)((HINSTANCE)uiNewImageBase, DLL_PROCESS_ATTACH, NULL) == TRUE;
#endif
}

#endif 


#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
RDIDLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
#else
RDIDLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(VOID)
#endif
{
#if defined(_M_ARM64)
    #ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
        return Arm64ReflectiveLoaderLogic(lpParameter);
    #else
        return Arm64ReflectiveLoaderLogic(NULL); 
    #endif
#else
	ULONG_PTR uiCurrentImageBase;
	PIMAGE_NT_HEADERS pCurrentImageNtHeaders;

	RESOLVED_IMPORTS_X86_X64 ResolvedImports_x86_x64;
	Syscall ZwAllocateVirtualMemorySyscallObj;
	Syscall ZwProtectVirtualMemorySyscallObj;
	Syscall ZwFlushInstructionCacheSyscallObj;
#ifdef ENABLE_STOPPAGING
	Syscall ZwLockVirtualMemorySyscallObj;
#endif

	PVOID pNewImageBase = NULL;
	PIMAGE_NT_HEADERS pNewImageNtHeaders;

	if (!FindCurrentImageBase_X86_X64(&uiCurrentImageBase)) return 0;
	pCurrentImageNtHeaders = (PIMAGE_NT_HEADERS)(uiCurrentImageBase + ((PIMAGE_DOS_HEADER)uiCurrentImageBase)->e_lfanew);

	if (!ResolveCoreImportsFromPeb_X86_X64(&ResolvedImports_x86_x64)) return 0;

	if (!SetupAndResolveSyscalls_X86_X64(ResolvedImports_x86_x64.pNtdllBase,
								 &ZwAllocateVirtualMemorySyscallObj,
								 &ZwProtectVirtualMemorySyscallObj,
								 &ZwFlushInstructionCacheSyscallObj
#ifdef ENABLE_STOPPAGING
								 ,&ZwLockVirtualMemorySyscallObj
#endif
								 )) return 0;

	pNewImageBase = AllocateNewImageMemory_X86_X64(pCurrentImageNtHeaders, &ZwAllocateVirtualMemorySyscallObj
#ifdef ENABLE_STOPPAGING
										   ,&ZwLockVirtualMemorySyscallObj
#endif
	);
	if (pNewImageBase == NULL) return 0;

	CopyPEHeadersAndSections_X86_X64(uiCurrentImageBase, (ULONG_PTR)pNewImageBase, pCurrentImageNtHeaders);
	pNewImageNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pNewImageBase + ((PIMAGE_DOS_HEADER)pNewImageBase)->e_lfanew);

	if (!ProcessImageImports_X86_X64((ULONG_PTR)pNewImageBase, pNewImageNtHeaders, &ResolvedImports_x86_x64)) return 0;
	if (!ProcessImageRelocations_X86_X64((ULONG_PTR)pNewImageBase, pNewImageNtHeaders, pCurrentImageNtHeaders)) return 0;
	if (!ApplySectionProtections_X86_X64((ULONG_PTR)pNewImageBase, pNewImageNtHeaders, &ZwProtectVirtualMemorySyscallObj)) return 0;

	hAppInstance = (HINSTANCE)pNewImageBase; 

	ExecuteDllEntryPoint_X86_X64((ULONG_PTR)pNewImageBase, pNewImageNtHeaders,
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
						 lpParameter, 
#else
						 NULL,        
#endif
						 &ZwFlushInstructionCacheSyscallObj);

	return (ULONG_PTR)pNewImageBase + pNewImageNtHeaders->OptionalHeader.AddressOfEntryPoint;
#endif 
}


#ifndef REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
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