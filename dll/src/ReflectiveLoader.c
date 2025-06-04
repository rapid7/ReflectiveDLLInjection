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
    LOADLIBRARYA_FN fnLoadLibraryA = NULL;
    GETPROCADDRESS_FN fnGetProcAddress = NULL;
    VIRTUALALLOC_FN fnVirtualAlloc = NULL;
    NTFLUSHINSTRUCTIONCACHE_FN fnNtFlushInstructionCache = NULL;

    ULONG_PTR uiDllBase;
    ULONG_PTR uiPeb;
    ULONG_PTR uiKernel32Base = 0;
    ULONG_PTR uiNtdllBase = 0;

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

#if defined(_MSC_VER)
    uiPeb = __readx18qword(0x60);
#elif defined(__GNUC__) || defined(__clang__)
    #warning "ARM64 PEB access via X18 needs specific intrinsic for __readx18qword for this compiler in Arm64ReflectiveLoaderLogic"
    // Fallback or error for __readx18qword not being available for GCC/Clang directly for PEB+0x60.
    // A common way is via TEB:
    ULONG_PTR tebBase = 0;
	__asm__ ("mrs %0, TPIDR_EL0" : "=r" (tebBase)); // Read TEB base from TPIDR_EL0
    if(!tebBase) return 0;
    uiPeb = *(ULONG_PTR *)(tebBase + 0x60); // PEB is at TEB + 0x60
    if(!uiPeb) return 0;
#else
	#error "Unsupported ARM64 compiler for PEB access (__readx18qword) in Arm64ReflectiveLoaderLogic"
	return 0;
#endif

    PPEB_LDR_DATA_LDR pLdr = ((PPEB_LDR)uiPeb)->Ldr;
    if (!pLdr) return 0;

    PLIST_ENTRY pModuleList = &(pLdr->InMemoryOrderModuleList);
    PLIST_ENTRY pCurrentEntry = pModuleList->Flink;

    while (pCurrentEntry != pModuleList)
    {
        PLDR_DATA_TABLE_ENTRY_LDR pEntry = (PLDR_DATA_TABLE_ENTRY_LDR)CONTAINING_RECORD(pCurrentEntry, LDR_DATA_TABLE_ENTRY_LDR, InMemoryOrderLinks);
        if (pEntry->BaseDllName.Length > 0 && pEntry->BaseDllName.Buffer != NULL)
        {
            DWORD dwModuleHash = 0;
            USHORT usCounter = pEntry->BaseDllName.Length;
            BYTE *pNameByte = (BYTE *)pEntry->BaseDllName.Buffer;

            do
            {
                dwModuleHash = ror_dword_loader(dwModuleHash);
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

            if (dwModuleHash == KERNEL32DLL_HASH)
            {
                uiKernel32Base = (ULONG_PTR)pEntry->DllBase;
            }
            else if (dwModuleHash == NTDLLDLL_HASH)
            {
                uiNtdllBase = (ULONG_PTR)pEntry->DllBase;
            }
        }
        if (uiKernel32Base && uiNtdllBase)
            break;
        pCurrentEntry = pCurrentEntry->Flink;
    }

    if (!uiKernel32Base || !uiNtdllBase)
        return 0;

    PIMAGE_NT_HEADERS pOldNtHeaders = (PIMAGE_NT_HEADERS)(uiDllBase + ((PIMAGE_DOS_HEADER)uiDllBase)->e_lfanew);
    ULONG_PTR uiExportDir = uiKernel32Base + ((PIMAGE_NT_HEADERS)(uiKernel32Base + ((PIMAGE_DOS_HEADER)uiKernel32Base)->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)uiExportDir;
    ULONG_PTR uiAddressOfNames = uiKernel32Base + pExportDirectory->AddressOfNames;
    ULONG_PTR uiAddressOfFunctions = uiKernel32Base + pExportDirectory->AddressOfFunctions;
    ULONG_PTR uiAddressOfNameOrdinals = uiKernel32Base + pExportDirectory->AddressOfNameOrdinals;

    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++)
    {
        char *cName = (char *)(uiKernel32Base + ((DWORD *)uiAddressOfNames)[i]);
        DWORD dwHashVal = hash_string_loader(cName);
        if (dwHashVal == LOADLIBRARYA_HASH)
            fnLoadLibraryA = (LOADLIBRARYA_FN)(uiKernel32Base + ((DWORD *)uiAddressOfFunctions)[((WORD *)uiAddressOfNameOrdinals)[i]]);
        else if (dwHashVal == GETPROCADDRESS_HASH)
            fnGetProcAddress = (GETPROCADDRESS_FN)(uiKernel32Base + ((DWORD *)uiAddressOfFunctions)[((WORD *)uiAddressOfNameOrdinals)[i]]);
        else if (dwHashVal == VIRTUALALLOC_HASH)
            fnVirtualAlloc = (VIRTUALALLOC_FN)(uiKernel32Base + ((DWORD *)uiAddressOfFunctions)[((WORD *)uiAddressOfNameOrdinals)[i]]);
        if (fnLoadLibraryA && fnGetProcAddress && fnVirtualAlloc)
            break;
    }

    if (!fnLoadLibraryA || !fnGetProcAddress || !fnVirtualAlloc)
        return 0;

    uiExportDir = uiNtdllBase + ((PIMAGE_NT_HEADERS)(uiNtdllBase + ((PIMAGE_DOS_HEADER)uiNtdllBase)->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)uiExportDir;
    uiAddressOfNames = uiNtdllBase + pExportDirectory->AddressOfNames;
    uiAddressOfFunctions = uiNtdllBase + pExportDirectory->AddressOfFunctions;
    uiAddressOfNameOrdinals = uiNtdllBase + pExportDirectory->AddressOfNameOrdinals;

    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++)
    {
        char *cName = (char *)(uiNtdllBase + ((DWORD *)uiAddressOfNames)[i]);
        if (hash_string_loader(cName) == NTFLUSHINSTRUCTIONCACHE_HASH)
        {
            fnNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE_FN)(uiNtdllBase + ((DWORD *)uiAddressOfFunctions)[((WORD *)uiAddressOfNameOrdinals)[i]]);
            break;
        }
    }

    if (!fnNtFlushInstructionCache)
        return 0;

    ULONG_PTR uiNewImageBase = (ULONG_PTR)fnVirtualAlloc(NULL, pOldNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!uiNewImageBase)
        return 0;

    for (DWORD i = 0; i < pOldNtHeaders->OptionalHeader.SizeOfHeaders; i++)
    {
        ((BYTE *)uiNewImageBase)[i] = ((BYTE *)uiDllBase)[i];
    }

    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&pOldNtHeaders->OptionalHeader + pOldNtHeaders->FileHeader.SizeOfOptionalHeader);
    for (WORD i = 0; i < pOldNtHeaders->FileHeader.NumberOfSections; i++)
    {
        for (DWORD j = 0; j < pSectionHeader[i].SizeOfRawData; j++)
        {
            ((BYTE *)(uiNewImageBase + pSectionHeader[i].VirtualAddress))[j] = ((BYTE *)(uiDllBase + pSectionHeader[i].PointerToRawData))[j];
        }
    }

    ULONG_PTR uiDelta = uiNewImageBase - pOldNtHeaders->OptionalHeader.ImageBase;
    PIMAGE_DATA_DIRECTORY pRelocationData = &pOldNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (pRelocationData->Size > 0 && uiDelta != 0)
    {
        PIMAGE_BASE_RELOCATION pRelocBlock = (PIMAGE_BASE_RELOCATION)(uiNewImageBase + pRelocationData->VirtualAddress);
        while (pRelocBlock->VirtualAddress)
        {
            DWORD dwEntryCount = (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC_LDR);
            PIMAGE_RELOC_LDR pRelocEntry = (PIMAGE_RELOC_LDR)((ULONG_PTR)pRelocBlock + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD k = 0; k < dwEntryCount; k++)
            {
                if (pRelocEntry[k].type == IMAGE_REL_BASED_DIR64)
                {
                    *(ULONG_PTR *)(uiNewImageBase + pRelocBlock->VirtualAddress + pRelocEntry[k].offset) += uiDelta;
                }
            }
            pRelocBlock = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pRelocBlock + pRelocBlock->SizeOfBlock);
        }
    }

    PIMAGE_DATA_DIRECTORY pImportData = &pOldNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (pImportData->Size > 0)
    {
        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(uiNewImageBase + pImportData->VirtualAddress);
        while (pImportDesc->Name)
        {
            char *sModuleName = (char *)(uiNewImageBase + pImportDesc->Name);
            HINSTANCE hModule = fnLoadLibraryA(sModuleName);
            if (hModule)
            {
                PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(uiNewImageBase + pImportDesc->OriginalFirstThunk);
                PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(uiNewImageBase + pImportDesc->FirstThunk);
                if (!pOriginalFirstThunk)
                    pOriginalFirstThunk = pFirstThunk;

                while (pOriginalFirstThunk->u1.AddressOfData)
                {
                    FARPROC pfnImportedFunc;
                    if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal))
                    {
                        pfnImportedFunc = fnGetProcAddress(hModule, (LPCSTR)(pOriginalFirstThunk->u1.Ordinal & 0xFFFF));
                    }
                    else
                    {
                        PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(uiNewImageBase + pOriginalFirstThunk->u1.AddressOfData);
                        pfnImportedFunc = fnGetProcAddress(hModule, pImportByName->Name);
                    }
                    pFirstThunk->u1.Function = (ULONG_PTR)pfnImportedFunc;
                    pOriginalFirstThunk++;
                    pFirstThunk++;
                }
            }
            pImportDesc++;
        }
    }

    hAppInstance = (HINSTANCE)uiNewImageBase;

    DLLMAIN_FN fnDllEntry = (DLLMAIN_FN)(uiNewImageBase + pOldNtHeaders->OptionalHeader.AddressOfEntryPoint);
    if (fnDllEntry)
    {
        fnNtFlushInstructionCache((HANDLE)-1, NULL, 0);
        fnDllEntry((HINSTANCE)uiNewImageBase, DLL_PROCESS_ATTACH, lpLoaderParameter);
    }
    return uiNewImageBase;
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
    _PPEB pPeb;

	if (pResolvedImports == NULL) return FALSE;
	pResolvedImports->pLoadLibraryA = NULL;
	pResolvedImports->pGetProcAddress = NULL;
	pResolvedImports->pNtdllBase = NULL;

#if defined(_M_X64)
	pPeb = (_PPEB)__readgsqword(0x60);
#elif defined(_M_IX86)
	pPeb = (_PPEB)__readfsdword(0x30);
#elif defined(WIN_ARM)
    #if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
		pPeb = (_PPEB)(*(DWORD *)((BYTE *)_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30));
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


RDIDLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
{
#if defined(_M_ARM64)
	return Arm64ReflectiveLoaderLogic(lpParameter);
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
						 lpParameter,
						 &ZwFlushInstructionCacheSyscallObj);

	return (ULONG_PTR)pNewImageBase;
#endif
}
