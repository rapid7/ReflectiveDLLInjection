#pragma once

// C5045 warning was introduced in Visual Studio 2017 version 15.7
// See https://devblogs.microsoft.com/cppblog/spectre-mitigations-in-msvc/
// See https://learn.microsoft.com/en-us/cpp/preprocessor/predefined-macros?view=msvc-170
#if _MSC_VER >= 1914
#pragma warning(disable: 5045) // warning C5045: Compiler will insert Spectre mitigation for memory load if /Qspectre switch specified
#endif
#pragma warning(disable: 4820) // warning C4820: X bytes padding added after construct Y
#pragma warning(disable: 4668) // warning C4820: 'symbol' is not defined as a preprocessor macro, replacing with '0' for 'directives'
#pragma warning(disable: 4255) // warning C4820: 'function' : no function prototype given: converting '()' to '(void)'

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

#ifdef _WIN64
#define SYS_STUB_SIZE 32
#else
#define SYS_STUB_SIZE 16
#endif

#define HASH_KEY      13
#define EXE_PATH_SIZE 256

// Syscalls index in UtilitySyscalls array
#define NTALLOCATEVIRTUALMEMORY_SYSCALL 0
#define NTREADVIRTUALMEMORY_SYSCALL     1
#define NTCLOSE_SYSCALL                 2
#define NTTERMINATEPROCESS_SYSCALL      3
#define NTFREEVIRTUALMEMORY_SYSCALL     4

#define KERNEL32DLL_HASH             0x6A4ABC5B
#define NTDLLDLL_HASH                0x3CFA685D

#define NTREADVIRTUALMEMORY_HASH     0x3AEFA5AA
#define NTCLOSE_HASH                 0xDCD44C5F
#define NTTERMINATEPROCESS_HASH      0x7929BBF3
#define NTFREEVIRTUALMEMORY_HASH     0xDB63B5AB
#define NTFLUSHINSTRUCTIONCACHE_HASH 0x534C0AB8
#define NTALLOCATEVIRTUALMEMORY_HASH 0xD33BCABD
#define NTPROTECTVIRTUALMEMORY_HASH  0x8C394D89

#define CREATEPROCESSA_HASH          0x16B3FE72 // TODO
#define GETSYSTEMDIRECTORYA_HASH     0xB8E579C1 // TODO
#define LOADLIBRARYA_HASH            0xEC0E4E8E // TODO
#define GETPROCADDRESS_HASH          0x7C0DFCAA // TODO

//===============================================================================================//
#pragma intrinsic( _rotr )

__forceinline DWORD ror(DWORD d)
{
    return _rotr(d, HASH_KEY);
}

__forceinline DWORD _hash(char* c)
{
    register DWORD h = 0;
    do
    {
        h = ror(h);
        h += *c;
    } while (*++c);

    return h;
}
//===============================================================================================//


#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

// These funtions will only be used during the hooking bypass (ColdGate) and only if NtAllocateVirtualMemory is hooked. It will execute it as is, even if it is hooked.
typedef NTSTATUS(WINAPI* NTALLOCATEVIRTUALMEMORY)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(WINAPI* NTREADVIRTUALMEMORY)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(WINAPI* NTCLOSE)(HANDLE);
typedef NTSTATUS(WINAPI* NTTERMINATEPROCESS)(HANDLE, NTSTATUS);
typedef NTSTATUS(WINAPI* NTFREEVIRTUALMEMORY)(HANDLE, PVOID*, PSIZE_T, ULONG);
typedef DWORD(NTAPI* NTFLUSHINSTRUCTIONCACHE)(HANDLE, PVOID, ULONG);

typedef BOOL(WINAPI* CREATEPROCESSA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION); // TODO
typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR); // TODO
typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR); // TODO
typedef UINT(WINAPI* GETSYSTEMDIRECTORYA)(LPSTR lpBuffer, UINT uSize);

typedef struct {
    DWORD dwCryptedHash;
    DWORD dwNumberOfArgs;
    DWORD dwSyscallNr;
    BOOL  hooked;
    PVOID pColdGate;
} Syscall;

#define UTILITY_SYSCALLS_SIZE 5
typedef struct {
    Syscall* NtAllocateVirtualMemorySyscall;
    Syscall* NtReadVirtualMemorySyscall;
    Syscall* NtCloseSyscall;
    Syscall* NtTerminateProcessSyscall;
    Syscall* NtFreeVirtualMemorySyscall;
} UtilitySyscalls;

// TODO: Ideally, we should separate what is used by ReflectiveLoader.c and by ColdGate.c to avoid dependencies between them.
//   This would allow the reuse of ColdGate independently for other projects.
// TODO: Have a custom implementation of these function to avoid using Kernel32 and reduce the dependency issue.
#define UTILITY_FUNC_NB 4
typedef struct {
    // These 2 functions are used by ReflectiveLoader()
    LOADLIBRARYA   pLoadLibraryA;
    GETPROCADDRESS pGetProcAddress;
    // Thes last 2 function are use during the unhooking process (Freeze technique)
    GETSYSTEMDIRECTORYA pGetSystemDirectoryA;
    CREATEPROCESSA pCreateProcessA;
} UtilityFunctions;


// The structure definitions below come from the original ReflectiveLoader.h
//===============================================================================================//
typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

// WinDbg> dt -v ntdll!_LDR_DATA_TABLE_ENTRY
//__declspec( align(8) ) 
typedef struct _LDR_DATA_TABLE_ENTRY
{
    //LIST_ENTRY InLoadOrderLinks; // As we search from PPEB_LDR_DATA->InMemoryOrderModuleList we dont use the first entry.
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

// WinDbg> dt -v ntdll!_PEB_LDR_DATA
typedef struct _PEB_LDR_DATA //, 7 elements, 0x28 bytes
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

// WinDbg> dt -v ntdll!_PEB_FREE_BLOCK
typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

// struct _PEB is defined in Winternl.h but it is incomplete
// WinDbg> dt -v ntdll!_PEB
typedef struct __PEB // 65 elements, 0x210 bytes
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;

//===============================================================================================//

BOOL findModules(PVOID* pNtdllBase, PVOID* pKernel32);
BOOL getKernel32Functions(PVOID pNtdllBase, UtilityFunctions* pUtilityFunctions);
BOOL getSyscalls(PVOID pNtdllBase, Syscall* Syscalls[], DWORD dwNumberOfSyscalls, UtilityFunctions* pUtilityFunctions);
extern NTSTATUS DoSyscall(VOID);

//
// Native API functions
//
NTSTATUS rdiNtAllocateVirtualMemory(Syscall* pSyscall, HANDLE hProcess, PVOID* pBaseAddress, ULONG_PTR pZeroBits, PSIZE_T pRegionSize, ULONG ulAllocationType, ULONG ulProtect);
NTSTATUS rdiNtProtectVirtualMemory(Syscall* pSyscall, HANDLE hProcess, PVOID* pBaseAddress, PSIZE_T pNumberOfBytesToProtect, ULONG ulNewAccessProtection, PULONG ulOldAccessProtection);
NTSTATUS rdiNtFlushInstructionCache(Syscall* pSyscall, HANDLE hProcess, PVOID* pBaseAddress, SIZE_T FlushSize);
NTSTATUS rdiNtLockVirtualMemory(Syscall* pSyscall, HANDLE hProcess, PVOID* pBaseAddress, PSIZE_T NumberOfBytesToLock, ULONG MapType);
NTSTATUS rdiNtReadVirtualMemory(Syscall * pSyscall, HANDLE hProcess, PVOID pBaseAddress, PVOID pBuffer, SIZE_T NumberOfBytesToRead, PSIZE_T pNumberOfBytesRead);
NTSTATUS rdiNtClose(Syscall * pSyscall, HANDLE hProcess);
NTSTATUS rdiNtTerminateProcess(Syscall * pSyscall, HANDLE hProcess, NTSTATUS ntExitStatus);
NTSTATUS rdiNtFreeVirtualMemory(Syscall * pSyscall, HANDLE hProcess, PVOID * pBaseAddress, PSIZE_T pRegionSize, ULONG uFreeType);
