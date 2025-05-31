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

#include "ReflectiveLoader.h"
#include "DirectSyscall.c"

HINSTANCE hAppInstance = NULL;

#ifdef __MINGW32__
#define WIN_GET_CALLER() __builtin_extract_return_addr(__builtin_return_address(0))
#else
#pragma intrinsic(_ReturnAddress)
#define WIN_GET_CALLER() _ReturnAddress()
#endif

__declspec(noinline) ULONG_PTR caller(VOID) { return (ULONG_PTR)WIN_GET_CALLER(); }

#ifdef RDIDLL_NOEXPORT
#define RDIDLLEXPORT
#else
#define RDIDLLEXPORT DLLEXPORT
#endif

typedef struct
{
	LOADLIBRARYA pLoadLibraryA;
	GETPROCADDRESS pGetProcAddress;
	PVOID pNtdllBase;
} RESOLVED_IMPORTS;

static BOOL FindCurrentImageBase(OUT ULONG_PTR *puiCurrentImageBase)
{
	ULONG_PTR uiAddress = caller();
	if (puiCurrentImageBase == NULL)
		return FALSE;

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
		if (!uiAddress)
			return FALSE;
	}
	return FALSE;
}

static BOOL ResolveCoreImportsFromPeb(OUT RESOLVED_IMPORTS *pResolvedImports)
{
	ULONG_PTR uiPebLdrData;
	PLIST_ENTRY pModuleListHead;
	PLIST_ENTRY pCurrentListEntry;

	if (pResolvedImports == NULL)
		return FALSE;
	pResolvedImports->pLoadLibraryA = NULL;
	pResolvedImports->pGetProcAddress = NULL;
	pResolvedImports->pNtdllBase = NULL;

#ifdef _WIN64
	uiPebLdrData = (ULONG_PTR)((_PPEB)__readgsqword(0x60))->pLdr;
#else
#ifdef WIN_ARM
	uiPebLdrData = (ULONG_PTR)((_PPEB)(*(DWORD *)((BYTE *)_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30)))->pLdr;
#else
	uiPebLdrData = (ULONG_PTR)((_PPEB)__readfsdword(0x30))->pLdr;
#endif
#endif

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

		do
		{
			currentModuleNameHash = ror(currentModuleNameHash);
			BYTE currentByte = *pByteModuleNameBuffer;
			if (currentByte >= 'a' && currentByte <= 'z')
				currentModuleNameHash += (currentByte - ('a' - 'A'));
			else
				currentModuleNameHash += currentByte;
			pByteModuleNameBuffer++;
		} while (--nameLengthInBytes);

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

static BOOL SetupAndResolveSyscalls(
	PVOID pNtdllBase,
	OUT Syscall *pZwAllocateVirtualMemory,
	OUT Syscall *pZwProtectVirtualMemory,
	OUT Syscall *pZwFlushInstructionCache
#ifdef ENABLE_STOPPAGING
	,
	OUT Syscall *pZwLockVirtualMemory
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
	pZwLockVirtualMemory->dwCryptedHash = ZWLOCKVIRTUALMEMORY_HASH;
	pZwLockVirtualMemory->dwNumberOfArgs = 4;
	SyscallsToResolve[3] = pZwLockVirtualMemory;
#endif

	return getSyscalls(pNtdllBase, SyscallsToResolve, dwNumSyscalls);
}

static PVOID AllocateNewImageMemory(PIMAGE_NT_HEADERS pCurrentImageNtHeaders, Syscall *pAllocSyscall
#ifdef ENABLE_STOPPAGING
									,
									Syscall *pLockSyscall
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
	if (pLockSyscall->pStub != NULL)
	{ // Check if ZwLockVirtualMemory was resolved
		rdiNtLockVirtualMemory(pLockSyscall, (HANDLE)-1, &pNewImageBase, &lockRegionSize, 1);
	}
#endif
	return pNewImageBase;
}

static void CopyPEHeadersAndSections(ULONG_PTR uiCurrentImageBase, ULONG_PTR uiNewImageBase, PIMAGE_NT_HEADERS pCurrentImageNtHeaders)
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

static BOOL ProcessImageImports(ULONG_PTR uiNewImageBase, PIMAGE_NT_HEADERS pNewImageNtHeaders, RESOLVED_IMPORTS *pImports)
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

static BOOL ProcessImageRelocations(ULONG_PTR uiNewImageBase, PIMAGE_NT_HEADERS pNewImageNtHeaders, PIMAGE_NT_HEADERS pCurrentImageNtHeaders)
{
	ULONG_PTR relocationDelta = uiNewImageBase - pCurrentImageNtHeaders->OptionalHeader.ImageBase;
	if (relocationDelta == 0)
		return TRUE;

	PIMAGE_DATA_DIRECTORY pRelocDataDir = &pNewImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (pRelocDataDir->VirtualAddress == 0 || pRelocDataDir->Size == 0)
		return TRUE;

	PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)(uiNewImageBase + pRelocDataDir->VirtualAddress);
	ULONG_PTR uiRelocEnd = (ULONG_PTR)pBaseRelocation + pRelocDataDir->Size;

	while ((ULONG_PTR)pBaseRelocation < uiRelocEnd && pBaseRelocation->SizeOfBlock)
	{
		ULONG_PTR relocBlockBaseVA = uiNewImageBase + pBaseRelocation->VirtualAddress;
		DWORD numEntriesInBlock = (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
		PIMAGE_RELOC pCurrentRelocEntry = (PIMAGE_RELOC)((ULONG_PTR)pBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));

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
				*(ULONG_PTR *)patchTargetAddress += relocationDelta;
				break;
#ifdef WIN_ARM
			case IMAGE_REL_BASED_ARM_MOV32T:
			{
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

static BOOL ApplySectionProtections(ULONG_PTR uiNewImageBase, PIMAGE_NT_HEADERS pNewImageNtHeaders, Syscall *pProtectSyscall)
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

static BOOL ExecuteDllEntryPoint(ULONG_PTR uiNewImageBase, PIMAGE_NT_HEADERS pNewImageNtHeaders, LPVOID lpParameter, Syscall *pFlushCacheSyscall)
{
	if (pNewImageNtHeaders->OptionalHeader.AddressOfEntryPoint == 0)
		return TRUE;

	ULONG_PTR entryPointVA = uiNewImageBase + pNewImageNtHeaders->OptionalHeader.AddressOfEntryPoint;

	rdiNtFlushInstructionCache(pFlushCacheSyscall, (HANDLE)-1, NULL, 0);

#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
	return ((DLLMAIN)entryPointVA)((HINSTANCE)uiNewImageBase, DLL_PROCESS_ATTACH, lpParameter) == TRUE;
#else
	return ((DLLMAIN)entryPointVA)((HINSTANCE)uiNewImageBase, DLL_PROCESS_ATTACH, NULL) == TRUE;
#endif
}

#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
RDIDLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
#else
RDIDLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(VOID)
#endif
{
	ULONG_PTR uiCurrentImageBase;
	PIMAGE_NT_HEADERS pCurrentImageNtHeaders;

	RESOLVED_IMPORTS ResolvedImports;
	Syscall ZwAllocateVirtualMemorySyscallObj;
	Syscall ZwProtectVirtualMemorySyscallObj;
	Syscall ZwFlushInstructionCacheSyscallObj;
#ifdef ENABLE_STOPPAGING
	Syscall ZwLockVirtualMemorySyscallObj;
#endif

	PVOID pNewImageBase = NULL;
	PIMAGE_NT_HEADERS pNewImageNtHeaders;

	if (!FindCurrentImageBase(&uiCurrentImageBase))
		return 0;
	pCurrentImageNtHeaders = (PIMAGE_NT_HEADERS)(uiCurrentImageBase + ((PIMAGE_DOS_HEADER)uiCurrentImageBase)->e_lfanew);

	if (!ResolveCoreImportsFromPeb(&ResolvedImports))
		return 0;

	if (!SetupAndResolveSyscalls(ResolvedImports.pNtdllBase,
								 &ZwAllocateVirtualMemorySyscallObj,
								 &ZwProtectVirtualMemorySyscallObj,
								 &ZwFlushInstructionCacheSyscallObj
#ifdef ENABLE_STOPPAGING
								 ,
								 &ZwLockVirtualMemorySyscallObj
#endif
								 ))
		return 0;

	pNewImageBase = AllocateNewImageMemory(pCurrentImageNtHeaders, &ZwAllocateVirtualMemorySyscallObj
#ifdef ENABLE_STOPPAGING
										   ,
										   &ZwLockVirtualMemorySyscallObj
#endif
	);
	if (pNewImageBase == NULL)
		return 0;

	CopyPEHeadersAndSections(uiCurrentImageBase, (ULONG_PTR)pNewImageBase, pCurrentImageNtHeaders);
	pNewImageNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pNewImageBase + ((PIMAGE_DOS_HEADER)pNewImageBase)->e_lfanew);

	if (!ProcessImageImports((ULONG_PTR)pNewImageBase, pNewImageNtHeaders, &ResolvedImports))
		return 0;
	if (!ProcessImageRelocations((ULONG_PTR)pNewImageBase, pNewImageNtHeaders, pCurrentImageNtHeaders))
		return 0;
	if (!ApplySectionProtections((ULONG_PTR)pNewImageBase, pNewImageNtHeaders, &ZwProtectVirtualMemorySyscallObj))
		return 0;

	hAppInstance = (HINSTANCE)pNewImageBase;

	ExecuteDllEntryPoint((ULONG_PTR)pNewImageBase, pNewImageNtHeaders,
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
						 lpParameter,
#else
						 NULL,
#endif
						 &ZwFlushInstructionCacheSyscallObj);

	return (ULONG_PTR)pNewImageBase + pNewImageNtHeaders->OptionalHeader.AddressOfEntryPoint;
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
