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
//===============================================================================================//
// Our loader will set this to a pseudo correct HINSTANCE/HMODULE value
HINSTANCE hAppInstance = NULL;
//===============================================================================================//
#ifdef __MINGW32__
#define WIN_GET_CALLER() __builtin_extract_return_addr(__builtin_return_address(0))
#else
#pragma intrinsic(_ReturnAddress)
#define WIN_GET_CALLER() _ReturnAddress()
#endif
// This function can not be inlined by the compiler or we will not get the address we expect. Ideally
// this code will be compiled with the /O2 and /Ob1 switches. Bonus points if we could take advantage of
// RIP relative addressing in this instance but I dont believe we can do so with the compiler intrinsics
// available (and no inline asm available under x64).
__declspec(noinline) ULONG_PTR caller( VOID ) { return (ULONG_PTR)WIN_GET_CALLER(); }
//===============================================================================================//

// Note 1: If you want to have your own DllMain, define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN,
//         otherwise the DllMain at the end of this file will be used.

// Note 2: If you are injecting the DLL via LoadRemoteLibraryR, define REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR,
//         otherwise it is assumed you are calling the ReflectiveLoader via a stub.

#ifdef RDIDLL_NOEXPORT
#define RDIDLLEXPORT
#else
#define RDIDLLEXPORT DLLEXPORT
#endif

// When initializing an array using `{0}`, the compiler replaces this statement with the compiler intrinsic function memset to zero out the memory.
// This is fine in a normal context, but here, it fails with an Access Violation since the compiler intrinsic function contains pointers to undefined memory locations.
// The reason is because this custom loader lives in a local memory space, any addresses pointing to anything outside of the ".text" section will be wrong.
// Forcing the use of a non-intrinsic custom version of memset seems to fix this.
#pragma function(memset)
void* __cdecl memset(void* s, int c, size_t n)
{
	BYTE* buf = (BYTE*)s;
	while (n--)
		*buf++ = (BYTE)c;
	return s;
}

// This is our position independent reflective DLL loader/injector
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
RDIDLLEXPORT ULONG_PTR WINAPI ReflectiveLoader( LPVOID lpParameter )
#else
RDIDLLEXPORT ULONG_PTR WINAPI ReflectiveLoader( VOID )
#endif
{
	// the functions we need
	UtilityFunctions stUtilityFunctions = { 0 };

	// the initial location of this image in memory
	ULONG_PTR uiLibraryAddress;
	// the kernels base address and later this images newly loaded base address
	ULONG_PTR uiBaseAddress;

	// variables for processing the kernels export table
	ULONG_PTR uiAddressArray;
	ULONG_PTR uiNameArray;
	ULONG_PTR uiExportDir;

	// variables for loading this image
	ULONG_PTR uiHeaderValue;
	ULONG_PTR uiValueA;
	ULONG_PTR uiValueB;
	ULONG_PTR uiValueC;
	ULONG_PTR uiValueD;
	ULONG_PTR uiValueE;
	DWORD dwProtect;

	PVOID pNtdllBase = NULL, pKernel32 = NULL;

	// The NTDLL exported functions our loader needs. This array of Syscall structures will be completed later.
#ifdef ENABLE_STOPPAGING
	Syscall Syscalls[4];
#else
	Syscall Syscalls[3];
#endif
	Syscalls[0].dwCryptedHash = NTALLOCATEVIRTUALMEMORY_HASH;
	Syscalls[0].dwNumberOfArgs = 6;
	Syscalls[0].hooked = FALSE;
	Syscalls[1].dwCryptedHash = NTPROTECTVIRTUALMEMORY_HASH;
	Syscalls[1].dwNumberOfArgs = 5;
	Syscalls[1].hooked = FALSE;
	Syscalls[2].dwCryptedHash = NTFLUSHINSTRUCTIONCACHE_HASH;
	Syscalls[2].dwNumberOfArgs = 3;
	Syscalls[2].hooked = FALSE;
#ifdef ENABLE_STOPPAGING
	Syscalls[3].dwCryptedHash = NTLOCKVIRTUALMEMORY_HASH;
	Syscalls[3].dwNumberOfArgs = 4;
	Syscalls[3].hooked = FALSE;
#endif


	// STEP 0: calculate our images current base address

	// we will start searching backwards from our callers return address.
	uiLibraryAddress = caller();

	// loop through memory backwards searching for our images base address
	// we dont need SEH style search as we shouldnt generate any access violations with this
	while( TRUE )
	{
		if( ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE )
		{
			uiHeaderValue = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
			// some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
			// we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
			if( uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024 )
			{
				uiHeaderValue += uiLibraryAddress;
				// break if we have found a valid MZ/PE header
				if( ((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature == IMAGE_NT_SIGNATURE )
					break;
			}
		}
		uiLibraryAddress--;
	}


	// STEP 1: process kernel32 exports for the functions our loader needs and setup the direct syscalls functions
	findModules(&pNtdllBase, &pKernel32);
	if (pNtdllBase == NULL || pKernel32 == NULL)
		return 0;

	getKernel32Functions(pKernel32, &stUtilityFunctions);

	if (!getSyscalls(pNtdllBase, Syscalls, (sizeof(Syscalls) / sizeof(Syscalls[0])), &stUtilityFunctions))
		return 0;


	// STEP 2: load our image into a new permanent location in memory...

	// get the VA of the NT Header for the PE to be loaded
	uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will
	// relocate the image. Also zeros all memory and marks it as READ and WRITE to avoid any problems.
	SIZE_T RegionSize = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage;
	uiBaseAddress = (ULONG_PTR) NULL;

	if (msfNtAllocateVirtualMemory(&Syscalls[0], (HANDLE)-1, &((PVOID)uiBaseAddress), (ULONG_PTR)0, &RegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) != 0)
		return 0;


#ifdef ENABLE_STOPPAGING
	// prevent our image from being swapped to the pagefile
	// This fails on Windows Server 2012 with error 0xC00000A1 STATUS_WORKING_SET_QUOTA, but it doesn't seem to be an issue.
	msfNtLockVirtualMemory(&Syscalls[3], (HANDLE)-1, &((PVOID)uiBaseAddress), &RegionSize, 1); // MapType 1 = MAP_PROCESS
#endif

	// we must now copy over the headers
	uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
	uiValueB = uiLibraryAddress;
	uiValueC = uiBaseAddress;

	while( uiValueA-- )
		*(BYTE *)uiValueC++ = *(BYTE *)uiValueB++;

	// STEP 3: load in all of our sections...

	// uiValueA = the VA of the first section
	uiValueA = ( (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader );

	// iterate through all sections, loading them into memory.
	uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
	while( uiValueE-- )
	{
		// uiValueB is the VA for this section
		uiValueB = ( uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress );

		// uiValueC if the VA for this sections data
		uiValueC = ( uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData );

		// copy the section over
		uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;


		while( uiValueD-- )
			*(BYTE *)uiValueB++ = *(BYTE *)uiValueC++;

		// get the VA of the next section
		uiValueA += sizeof( IMAGE_SECTION_HEADER );
	}

	// STEP 4: process our images import table...

	// uiValueB = the address of the import directory
	uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];

	// we assume there is an import table to process
	// uiValueC is the first entry in the import table
	uiValueC = ( uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress );

	// iterate through all imports until a null RVA is found (Characteristics is mis-named)
	while( ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Characteristics )
	{
		// use LoadLibraryA to load the imported module into memory
		uiLibraryAddress = (ULONG_PTR)stUtilityFunctions.pLoadLibraryA( (LPCSTR)( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name ) );

		if ( !uiLibraryAddress )
		{
			uiValueC += sizeof( IMAGE_IMPORT_DESCRIPTOR );
			continue;
		}

		// uiValueD = VA of the OriginalFirstThunk
		uiValueD = ( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk );

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		uiValueA = ( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk );

		// itterate through all imported functions, importing by ordinal if no name present
		while( DEREF(uiValueA) )
		{
			// sanity check uiValueD as some compilers only import by FirstThunk
			if( uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG )
			{
				// get the VA of the modules NT Header
				uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

				// uiNameArray = the address of the modules export directory entry
				uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

				// get the VA of the export directory
				uiExportDir = ( uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress );

				// get the VA for the array of addresses
				uiAddressArray = ( uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions );

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				uiAddressArray += ( ( IMAGE_ORDINAL( ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal ) - ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->Base ) * sizeof(DWORD) );

				// patch in the address for this imported function
				DEREF(uiValueA) = ( uiLibraryAddress + DEREF_32(uiAddressArray) );
			}
			else
			{
				// get the VA of this functions import by name struct
				uiValueB = ( uiBaseAddress + DEREF(uiValueA) );

				// use GetProcAddress and patch in the address for this imported function
				DEREF(uiValueA) = (ULONG_PTR)stUtilityFunctions.pGetProcAddress( (HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name );
			}
			// get the next imported function
			uiValueA += sizeof( ULONG_PTR );
			if( uiValueD )
				uiValueD += sizeof( ULONG_PTR );
		}

		// get the next import
		uiValueC += sizeof( IMAGE_IMPORT_DESCRIPTOR );
	}

	// STEP 5: process all of our images relocations...

	// calculate the base address delta and perform relocations (even if we load at desired image base)
	uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

	// uiValueB = the address of the relocation directory
	uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

	// check if their are any relocations present
	if( ((PIMAGE_DATA_DIRECTORY)uiValueB)->Size )
	{
		uiValueE = ((PIMAGE_BASE_RELOCATION)uiValueB)->SizeOfBlock;

		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		uiValueC = ( uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress );

		// and we itterate through all entries...
		while( uiValueE && ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock )
		{
			// uiValueA = the VA for this relocation block
			uiValueA = ( uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress );

			// uiValueB = number of entries in this relocation block
			uiValueB = ( ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) ) / sizeof( IMAGE_RELOC );

			// uiValueD is now the first entry in the current relocation block
			uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

			// we itterate through all the entries in the current block...
			while( uiValueB-- )
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64 )
					*(ULONG_PTR *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
				else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW )
					*(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;
#ifdef WIN_ARM
				// Note: On ARM, the compiler optimization /O2 seems to introduce an off by one issue, possibly a code gen bug. Using /O1 instead avoids this problem.
				else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_ARM_MOV32T )
				{
					register DWORD dwInstruction;
					register DWORD dwAddress;
					register WORD wImm;
					// get the MOV.T instructions DWORD value (We add 4 to the offset to go past the first MOV.W which handles the low word)
					dwInstruction = *(DWORD *)( uiValueA + ((PIMAGE_RELOC)uiValueD)->offset + sizeof(DWORD) );
					// flip the words to get the instruction as expected
					dwInstruction = MAKELONG( HIWORD(dwInstruction), LOWORD(dwInstruction) );
					// sanity chack we are processing a MOV instruction...
					if( (dwInstruction & ARM_MOV_MASK) == ARM_MOVT )
					{
						// pull out the encoded 16bit value (the high portion of the address-to-relocate)
						wImm  = (WORD)( dwInstruction & 0x000000FF);
						wImm |= (WORD)((dwInstruction & 0x00007000) >> 4);
						wImm |= (WORD)((dwInstruction & 0x04000000) >> 15);
						wImm |= (WORD)((dwInstruction & 0x000F0000) >> 4);
						// apply the relocation to the target address
						dwAddress = ( (WORD)HIWORD(uiLibraryAddress) + wImm ) & 0xFFFF;
						// now create a new instruction with the same opcode and register param.
						dwInstruction  = (DWORD)( dwInstruction & ARM_MOV_MASK2 );
						// patch in the relocated address...
						dwInstruction |= (DWORD)(dwAddress & 0x00FF);
						dwInstruction |= (DWORD)(dwAddress & 0x0700) << 4;
						dwInstruction |= (DWORD)(dwAddress & 0x0800) << 15;
						dwInstruction |= (DWORD)(dwAddress & 0xF000) << 4;
						// now flip the instructions words and patch back into the code...
						*(DWORD *)( uiValueA + ((PIMAGE_RELOC)uiValueD)->offset + sizeof(DWORD) ) = MAKELONG( HIWORD(dwInstruction), LOWORD(dwInstruction) );
					}
				}
#endif
				else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH )
					*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
				else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW )
					*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);

				// get the next entry in the current relocation block
				uiValueD += sizeof( IMAGE_RELOC );
			}

			uiValueE -= ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
			// get the next entry in the relocation directory
			uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
		}
	}

	// iterate through all sections, applying protections
	uiValueA = ( (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader );

	uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;

	// Characteristics processing courtesy of Dark Vort∑x, 2021-06-01
	// see: https://bruteratel.com/research/feature-update/2021/06/01/PE-Reflection-Long-Live-The-King/
	while( uiValueE-- )
	{
		// uiValueB is the VA for this section
		uiValueB = ( uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress );

		// get the sections memory protections value
		dwProtect = 0;
		if (((PIMAGE_SECTION_HEADER)uiValueA)->Characteristics & IMAGE_SCN_MEM_WRITE) {
			dwProtect = PAGE_WRITECOPY;
		}
		if (((PIMAGE_SECTION_HEADER)uiValueA)->Characteristics & IMAGE_SCN_MEM_READ) {
			dwProtect = PAGE_READONLY;
		}
		if ((((PIMAGE_SECTION_HEADER)uiValueA)->Characteristics & IMAGE_SCN_MEM_WRITE) && (((PIMAGE_SECTION_HEADER)uiValueA)->Characteristics & IMAGE_SCN_MEM_READ)) {
			dwProtect = PAGE_READWRITE;
		}
		if (((PIMAGE_SECTION_HEADER)uiValueA)->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			dwProtect = PAGE_EXECUTE;
		}
		if ((((PIMAGE_SECTION_HEADER)uiValueA)->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (((PIMAGE_SECTION_HEADER)uiValueA)->Characteristics & IMAGE_SCN_MEM_WRITE)) {
			dwProtect = PAGE_EXECUTE_WRITECOPY;
		}
		if ((((PIMAGE_SECTION_HEADER)uiValueA)->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (((PIMAGE_SECTION_HEADER)uiValueA)->Characteristics & IMAGE_SCN_MEM_READ)) {
			dwProtect = PAGE_EXECUTE_READ;
		}
		if ((((PIMAGE_SECTION_HEADER)uiValueA)->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (((PIMAGE_SECTION_HEADER)uiValueA)->Characteristics & IMAGE_SCN_MEM_WRITE) && (((PIMAGE_SECTION_HEADER)uiValueA)->Characteristics & IMAGE_SCN_MEM_READ)) {
			dwProtect = PAGE_EXECUTE_READWRITE;
		}

		uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;

		if (uiValueD)
			msfNtProtectVirtualMemory(&Syscalls[1], (HANDLE)-1, &((PVOID)uiValueB), &uiValueD, dwProtect, &dwProtect);

		// get the VA of the next section
		uiValueA += sizeof( IMAGE_SECTION_HEADER );
	}


	// STEP 6: call our images entry point

	// uiValueA = the VA of our newly loaded DLL/EXE's entry point
	uiValueA = ( uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint );

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	msfNtFlushInstructionCache(&Syscalls[2], (HANDLE) -1, NULL, 0);

	// call our respective entry point, fudging our hInstance value
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
	// if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)
	((DLLMAIN)uiValueA)( (HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, lpParameter );
#else
	// if we are injecting an DLL via a stub we call DllMain with no parameter
	((DLLMAIN)uiValueA)( (HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, NULL );
#endif

	// STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.
	return uiValueA;
}
//===============================================================================================//
#ifndef REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;

	switch( dwReason )
    {
		case DLL_QUERY_HMODULE:
			if( lpReserved != NULL )
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
//===============================================================================================//
