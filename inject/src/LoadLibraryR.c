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

#include "LoadLibraryR.h"

#ifdef __MINGW32__
#define __try
#define __except(x) if (0)
#endif

static DWORD RvaToFileOffset(DWORD dwRva, PIMAGE_NT_HEADERS pNtHeaders)
{
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	WORD wNumberOfSections = pNtHeaders->FileHeader.NumberOfSections;
	WORD wIndex;

	if (dwRva < pNtHeaders->OptionalHeader.SizeOfHeaders)
	{
		return dwRva;
	}

	if (wNumberOfSections == 0)
	{
		return 0;
	}

	for (wIndex = 0; wIndex < wNumberOfSections; wIndex++)
	{
		if (dwRva >= pSectionHeader[wIndex].VirtualAddress &&
			dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].Misc.VirtualSize))
		{
			if (pSectionHeader[wIndex].PointerToRawData != 0 &&
				(dwRva - pSectionHeader[wIndex].VirtualAddress) < pSectionHeader[wIndex].SizeOfRawData)
			{
				return pSectionHeader[wIndex].PointerToRawData + (dwRva - pSectionHeader[wIndex].VirtualAddress);
			}
			else
			{
				return 0;
			}
		}
	}
	return 0;
}

DWORD GetReflectiveLoaderOffset(LPVOID lpReflectiveDllBuffer, LPCSTR cpExportedFunctionName)
{
	UINT_PTR uiBaseAddress;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	UINT_PTR uiExportDirRVA;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
	DWORD dwExportDirFileOffset;
	UINT_PTR uiNameArrayRVA, uiAddressArrayRVA, uiNameOrdinalsRVA;
	DWORD dwNameArrayFileOffset, dwAddressArrayFileOffset, dwNameOrdinalsFileOffset;
	DWORD dwLoopIndex;
	DWORD *pdwNameRVAs = NULL;
	WORD *pwNameOrdinals = NULL;
	DWORD *pdwFunctionRVAs = NULL;

	if (!lpReflectiveDllBuffer || !cpExportedFunctionName)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;
	pDosHeader = (PIMAGE_DOS_HEADER)uiBaseAddress;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		SetLastError(ERROR_BAD_EXE_FORMAT);
		return 0;
	}

	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		SetLastError(ERROR_BAD_EXE_FORMAT);
		return 0;
	}

	if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		uiExportDirRVA = ((PIMAGE_NT_HEADERS32)pNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}
	else if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		uiExportDirRVA = ((PIMAGE_NT_HEADERS64)pNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}
	else
	{
		SetLastError(ERROR_BAD_EXE_FORMAT);
		return 0;
	}

	if (uiExportDirRVA == 0)
	{
		SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND);
		return 0;
	}
	dwExportDirFileOffset = RvaToFileOffset((DWORD)uiExportDirRVA, pNtHeaders);
	if (dwExportDirFileOffset == 0 && uiExportDirRVA != 0)
	{
		SetLastError(ERROR_INVALID_ADDRESS);
		return 0;
	}
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiBaseAddress + dwExportDirFileOffset);

	uiNameArrayRVA = pExportDirectory->AddressOfNames;
	uiAddressArrayRVA = pExportDirectory->AddressOfFunctions;
	uiNameOrdinalsRVA = pExportDirectory->AddressOfNameOrdinals;

	if (uiAddressArrayRVA == 0)
	{
		SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND);
		return 0;
	}
	dwAddressArrayFileOffset = RvaToFileOffset((DWORD)uiAddressArrayRVA, pNtHeaders);
	if (dwAddressArrayFileOffset == 0 && uiAddressArrayRVA != 0)
	{
		SetLastError(ERROR_INVALID_ADDRESS);
		return 0;
	}
	pdwFunctionRVAs = (DWORD *)(uiBaseAddress + dwAddressArrayFileOffset);

	if ((((DWORD_PTR)cpExportedFunctionName) >> 16) != 0)
	{
		if (uiNameArrayRVA == 0 || uiNameOrdinalsRVA == 0 || pExportDirectory->NumberOfNames == 0)
		{
			SetLastError(ERROR_PROC_NOT_FOUND);
			return 0;
		}
		dwNameArrayFileOffset = RvaToFileOffset((DWORD)uiNameArrayRVA, pNtHeaders);
		if (dwNameArrayFileOffset == 0 && uiNameArrayRVA != 0)
		{
			SetLastError(ERROR_INVALID_ADDRESS);
			return 0;
		}
		pdwNameRVAs = (DWORD *)(uiBaseAddress + dwNameArrayFileOffset);

		dwNameOrdinalsFileOffset = RvaToFileOffset((DWORD)uiNameOrdinalsRVA, pNtHeaders);
		if (dwNameOrdinalsFileOffset == 0 && uiNameOrdinalsRVA != 0)
		{
			SetLastError(ERROR_INVALID_ADDRESS);
			return 0;
		}
		pwNameOrdinals = (WORD *)(uiBaseAddress + dwNameOrdinalsFileOffset);
	}

	if ((((DWORD_PTR)cpExportedFunctionName) >> 16) == 0)
	{
		DWORD dwOrdinalBase = pExportDirectory->Base;
		DWORD dwTargetOrdinal = IMAGE_ORDINAL((DWORD_PTR)cpExportedFunctionName);

		if (dwTargetOrdinal < dwOrdinalBase || dwTargetOrdinal >= (dwOrdinalBase + pExportDirectory->NumberOfFunctions))
		{
			SetLastError(ERROR_PROC_NOT_FOUND);
			return 0;
		}
		DWORD dwFunctionRVA = pdwFunctionRVAs[dwTargetOrdinal - dwOrdinalBase];
		if (dwFunctionRVA == 0)
		{
			SetLastError(ERROR_PROC_NOT_FOUND);
			return 0;
		}
		return RvaToFileOffset(dwFunctionRVA, pNtHeaders);
	}
	else
	{
		if (!pdwNameRVAs || !pwNameOrdinals)
		{
			SetLastError(ERROR_PROC_NOT_FOUND);
			return 0;
		}
		for (dwLoopIndex = 0; dwLoopIndex < pExportDirectory->NumberOfNames; dwLoopIndex++)
		{
			DWORD dwNameRVA = pdwNameRVAs[dwLoopIndex];
			if (dwNameRVA == 0)
				continue;

			DWORD dwNameFileOffset = RvaToFileOffset(dwNameRVA, pNtHeaders);
			if (dwNameFileOffset == 0 && dwNameRVA != 0)
				continue;

			char *cpCurrentExportedFunctionName = (char *)(uiBaseAddress + dwNameFileOffset);
			if (strcmp(cpCurrentExportedFunctionName, cpExportedFunctionName) == 0)
			{
				WORD wNameOrdinal = pwNameOrdinals[dwLoopIndex];
				if (wNameOrdinal >= pExportDirectory->NumberOfFunctions)
				{
					SetLastError(ERROR_PROC_NOT_FOUND);
					return 0;
				}
				DWORD dwFunctionRVA = pdwFunctionRVAs[wNameOrdinal];
				if (dwFunctionRVA == 0)
				{
					SetLastError(ERROR_PROC_NOT_FOUND);
					return 0;
				}
				return RvaToFileOffset(dwFunctionRVA, pNtHeaders);
			}
		}
	}
	SetLastError(ERROR_PROC_NOT_FOUND);
	return 0;
}

HMODULE WINAPI LoadLibraryR(LPVOID lpBuffer, DWORD dwLength, LPCSTR cpReflectiveLoaderName)
{
	HMODULE hResult = NULL;
	DWORD dwReflectiveLoaderOffset;
	DWORD dwOldProtect1, dwOldProtect2;
	REFLECTIVELOADER pReflectiveLoader;

	if (lpBuffer == NULL || dwLength == 0 || cpReflectiveLoaderName == NULL)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return NULL;
	}

	__try
	{
		dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer, cpReflectiveLoaderName);
		if (dwReflectiveLoaderOffset != 0)
		{
			pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)lpBuffer + dwReflectiveLoaderOffset);
			if (VirtualProtect(lpBuffer, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtect1))
			{
				hResult = (HMODULE)pReflectiveLoader(NULL);
				VirtualProtect(lpBuffer, dwLength, dwOldProtect1, &dwOldProtect2);
			}
			else
			{
				hResult = NULL;
			}
		}
		else
		{
			hResult = NULL;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		SetLastError(GetExceptionCode());
		hResult = NULL;
	}
	return hResult;
}

HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength,
								 DWORD dwReflectiveLoaderFileOffset, LPVOID lpParameter)
{
	LPVOID lpRemoteLibraryBuffer = NULL;
	LPTHREAD_START_ROUTINE lpRemoteReflectiveLoader = NULL;
	HANDLE hRemoteThread = NULL;
	DWORD dwThreadId;
	DWORD dwOldProtection;
	DWORD dwLastError = ERROR_SUCCESS;

	if (!hProcess || !lpBuffer || !dwLength || dwReflectiveLoaderFileOffset == 0)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return NULL;
	}
	if (dwReflectiveLoaderFileOffset >= dwLength)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return NULL;
	}

	__try
	{
		do
		{
			lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
			if (!lpRemoteLibraryBuffer)
			{
				dwLastError = GetLastError();
				break;
			}

			if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
			{
				dwLastError = GetLastError();
				break;
			}

			if (!VirtualProtectEx(hProcess, lpRemoteLibraryBuffer, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtection))
			{
				dwLastError = GetLastError();
				break;
			}

			lpRemoteReflectiveLoader = (LPTHREAD_START_ROUTINE)((UINT_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderFileOffset);

			hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, lpRemoteReflectiveLoader, lpParameter, 0, &dwThreadId);
			if (!hRemoteThread)
			{
				dwLastError = GetLastError();
			}

		} while (0);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		dwLastError = GetExceptionCode();
		hRemoteThread = NULL;
	}

	if (!hRemoteThread)
	{
		if (lpRemoteLibraryBuffer && hProcess)
		{
			VirtualFreeEx(hProcess, lpRemoteLibraryBuffer, 0, MEM_RELEASE);
		}
		if (dwLastError != ERROR_SUCCESS)
		{
			SetLastError(dwLastError);
		}
	}
	return hRemoteThread;
}
