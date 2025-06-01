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

#ifndef _REFLECTIVEDLLINJECTION_REFLECTIVELOADER_H
#define _REFLECTIVEDLLINJECTION_REFLECTIVELOADER_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

#if _MSC_VER >= 1914
#pragma warning(disable : 5045)
#endif
#pragma warning(disable : 4820)
#pragma warning(disable : 4668)
#pragma warning(disable : 4255)

#define DLL_QUERY_HMODULE 6

#define DEREF(name) *(UINT_PTR *)(name)
#define DEREF_64(name) *(DWORD64 *)(name)
#define DEREF_32(name) *(DWORD *)(name)
#define DEREF_16(name) *(WORD *)(name)
#define DEREF_8(name) *(BYTE *)(name)

typedef ULONG_PTR(WINAPI *REFLECTIVELOADER)(LPVOID);
typedef BOOL(WINAPI *DLLMAIN)(HINSTANCE, DWORD, LPVOID);

#ifndef DLLEXPORT
#ifdef _MSC_VER
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT __attribute__((dllexport))
#endif
#endif

#include "DirectSyscall.h"

#if defined(_M_ARM64)

typedef HMODULE(WINAPI *LOADLIBRARYA_FN)(LPCSTR);
typedef FARPROC(WINAPI *GETPROCADDRESS_FN)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI *VIRTUALALLOC_FN)(LPVOID, SIZE_T, DWORD, DWORD);
typedef DWORD(NTAPI *NTFLUSHINSTRUCTIONCACHE_FN)(HANDLE, PVOID, ULONG);

#define KERNEL32DLL_HASH 0x6A4ABC5B
#define NTDLLDLL_HASH 0x3CFA685D

#define LOADLIBRARYA_HASH 0xEC0E4E8E
#define GETPROCADDRESS_HASH 0x7C0DFCAA
#define VIRTUALALLOC_HASH 0x91AFCA54
#define NTFLUSHINSTRUCTIONCACHE_HASH 0x534C0AB8

#define HASH_KEY 13

#pragma intrinsic(_rotr)
static __forceinline DWORD ror_dword_loader(DWORD d)
{
    return _rotr(d, HASH_KEY);
}

static __forceinline DWORD hash_string_loader(char *c)
{
    register DWORD h = 0;
    do
    {
        h = ror_dword_loader(h);
        h += *c;
    } while (*++c);
    return h;
}

typedef struct _UNICODE_STRING_LDR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING_LDR, *PUNICODE_STRING_LDR;

typedef struct _PEB_LDR_DATA_LDR
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA_LDR, *PPEB_LDR_DATA_LDR;

typedef struct _LDR_DATA_TABLE_ENTRY_LDR
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING_LDR FullDllName;
    UNICODE_STRING_LDR BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union _anon_union_1
    {
        LIST_ENTRY HashLinks;
        struct _anon_struct_1
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        } Links;
    };
    union _anon_union_2
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY_LDR, *PLDR_DATA_TABLE_ENTRY_LDR;

#pragma warning(push)
#pragma warning(disable : 4201)
typedef struct _PEB_LDR
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAware : 1;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA_LDR Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ProcessImagesHotPatched : 1;
            ULONG ReservedBits0 : 24;
        };
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID SharedData;
    PVOID *ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID *ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    PVOID LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ActiveProcessAffinityMask;
    ULONG GdiHandleBuffer[60];
    PVOID PostProcessInitRoutine;
    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;
    UNICODE_STRING_LDR CSDVersion;
    PVOID ActivationContextData;
    PVOID ProcessAssemblyStorageMap;
    PVOID SystemDefaultActivationContextData;
    PVOID SystemAssemblyStorageMap;
    SIZE_T MinimumStackCommit;
    PVOID SparePointers[2];
    PVOID PatchLoaderData;
    PVOID ChpeV2ProcessInfo;
    ULONG AppModelFeatureState;
    ULONG SpareUlongs[2];
    USHORT ActiveConsoleId;
    USHORT AppCompatVersionInfo;
    PVOID ExtendedProcessInfo;
} PEB_LDR, *PPEB_LDR;
#pragma warning(pop)

typedef struct _IMAGE_RELOC_LDR
{
    WORD offset : 12;
    WORD type : 4;
} IMAGE_RELOC_LDR, *PIMAGE_RELOC_LDR;

typedef BOOL(WINAPI *DLLMAIN_FN)(HINSTANCE, DWORD, LPVOID);

#else

#define ENABLE_STOPPAGING

#ifdef ENABLE_STOPPAGING
typedef NTSTATUS(WINAPI *NTLOCKVIRTUALMEMORY_X86_X64)(HANDLE, PVOID *, PSIZE_T, ULONG);
#define ZWLOCKVIRTUALMEMORY_HASH 0x8169ADC3
#endif

typedef struct
{
    WORD offset : 12;
    WORD type : 4;
} IMAGE_RELOC_X86_X64, *PIMAGE_RELOC_X86_X64;

#define ARM_MOVT 0xF2C00000
#define ARM_MOV_MASK 0xFFF0F000
#define ARM_MOV_MASK2 0xFFF0F000

#define KERNEL32DLL_HASH_X86_X64 KERNEL32DLL_HASH
#define NTDLLDLL_HASH_X86_X64 NTDLLDLL_HASH
#define LOADLIBRARYA_HASH_X86_X64 LOADLIBRARYA_HASH
#define GETPROCADDRESS_HASH_X86_X64 GETPROCADDRESS_HASH

#endif

#endif