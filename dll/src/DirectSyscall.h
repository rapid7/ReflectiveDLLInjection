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

#define KERNEL32DLL_HASH             0x6A4ABC5B
#define NTDLLDLL_HASH                0x3CFA685D

#define ZWALLOCATEVIRTUALMEMORY_HASH 0xD33D4AED
#define ZWPROTECTVIRTUALMEMORY_HASH  0xBC3F4D89
#define ZWFLUSHINSTRUCTIONCACHE_HASH 0x534D8AE8

#define LOADLIBRARYA_HASH            0xEC0E4E8E
#define GETPROCADDRESS_HASH          0x7C0DFCAA

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

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);

typedef struct {
    DWORD dwCryptedHash;
    DWORD dwNumberOfArgs;
    DWORD dwSyscallNr;
    PVOID pStub;
} Syscall;

// TODO: Have a custom implementation of these function to avoid using Kernel32 and reduce the dependency issue.
#define UTILITY_FUNC_NB 2
typedef struct {
    // These 2 functions are used by ReflectiveLoader()
    LOADLIBRARYA   pLoadLibraryA;
    GETPROCADDRESS pGetProcAddress;
} UtilityFunctions;

typedef struct {
    DWORD dwCryptedHash;
    PVOID pAddress;
} SYSCALL_ENTRY;

#define MAX_SYSCALLS 600
typedef struct {
    DWORD dwCount;
    SYSCALL_ENTRY Entries[MAX_SYSCALLS];
} SYSCALL_LIST;


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

BOOL getSyscalls(PVOID pNtdllBase, Syscall* Syscalls[], DWORD dwNumberOfSyscalls);
extern NTSTATUS DoSyscall(VOID);

//
// Native API functions
//
NTSTATUS rdiNtAllocateVirtualMemory(Syscall* pSyscall, HANDLE hProcess, PVOID* pBaseAddress, ULONG_PTR pZeroBits, PSIZE_T pRegionSize, ULONG ulAllocationType, ULONG ulProtect);
NTSTATUS rdiNtProtectVirtualMemory(Syscall* pSyscall, HANDLE hProcess, PVOID* pBaseAddress, PSIZE_T pNumberOfBytesToProtect, ULONG ulNewAccessProtection, PULONG ulOldAccessProtection);
NTSTATUS rdiNtFlushInstructionCache(Syscall* pSyscall, HANDLE hProcess, PVOID* pBaseAddress, SIZE_T FlushSize);
NTSTATUS rdiNtLockVirtualMemory(Syscall* pSyscall, HANDLE hProcess, PVOID* pBaseAddress, PSIZE_T NumberOfBytesToLock, ULONG MapType);
