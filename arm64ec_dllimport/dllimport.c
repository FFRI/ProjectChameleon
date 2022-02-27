/*
 * Copyright 2022 David Xanatos, xanasoft.com
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 */
 
#include <Ntstatus.h>
#define WIN32_NO_STATUS
typedef long NTSTATUS;

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// ntimage.h

typedef struct _IMAGE_ARM64EC_METADATA {
	ULONG  Version;
	ULONG  CodeMap;
	ULONG  CodeMapCount;
	ULONG  CodeRangesToEntryPoints;
	ULONG  RedirectionMetadata;
	ULONG  tbd__os_arm64x_dispatch_call_no_redirect;
	ULONG  tbd__os_arm64x_dispatch_ret;
	ULONG  tbd__os_arm64x_dispatch_call;
	ULONG  tbd__os_arm64x_dispatch_icall;
	ULONG  tbd__os_arm64x_dispatch_icall_cfg;
	ULONG  AlternateEntryPoint;
	ULONG  AuxiliaryIAT;
	ULONG  CodeRangesToEntryPointsCount;
	ULONG  RedirectionMetadataCount;
	ULONG  GetX64InformationFunctionPointer;
	ULONG  SetX64InformationFunctionPointer;
	ULONG  ExtraRFETable;
	ULONG  ExtraRFETableSize;
	ULONG  __os_arm64x_dispatch_fptr;
	ULONG  AuxiliaryIATCopy;
} IMAGE_ARM64EC_METADATA;

typedef struct _IMAGE_ARM64EC_REDIRECTION_ENTRY {
	ULONG Source;
	ULONG Destination;
} IMAGE_ARM64EC_REDIRECTION_ENTRY;

// ntimage.h


typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation
} MEMORY_INFORMATION_CLASS;

//#include "../../wow64ext/misc_winnt.h"
//#ifndef BUILD_ARCH_X64
//#include "../../wow64ext/wow64ext.h"
//#else

NTSYSCALLAPI NTSTATUS NTAPI NtReadVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_Out_writes_bytes_(BufferSize) PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesRead
);

NTSYSCALLAPI NTSTATUS NTAPI NtQueryVirtualMemory(
	IN  HANDLE ProcessHandle,
	IN  PVOID BaseAddress,
	IN  MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT PVOID MemoryInformation,
	IN  SIZE_T MemoryInformationLength,
	OUT PSIZE_T ReturnLength);

#define NtReadVirtualMemory64(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead) \
	NtReadVirtualMemory(ProcessHandle, (PVOID)(BaseAddress), Buffer, BufferSize, NumberOfBytesRead)

#define NtQueryVirtualMemory64(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength) \
	NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength)

//#endif

ULONG64 FindDllBase(_In_ HANDLE ProcessHandle, const WCHAR* dll)
{
	char buffer[512];

	for (PVOID baseAddress = NULL;;)
	{
		MEMORY_BASIC_INFORMATION64 basicInfo;
		if (!NT_SUCCESS(NtQueryVirtualMemory64(
			ProcessHandle,
			baseAddress,
			MemoryBasicInformation,
			&basicInfo,
			sizeof(MEMORY_BASIC_INFORMATION64),
			NULL
		)))
		{
			break;
		}

		baseAddress = (PVOID)((ULONG_PTR)(baseAddress)+(ULONG_PTR)(basicInfo.RegionSize));

		if (NT_SUCCESS(NtQueryVirtualMemory64(
			ProcessHandle,
			basicInfo.AllocationBase,
			MemoryMappedFilenameInformation,
			buffer,
			sizeof(buffer),
			NULL
		)))
		{
			UNICODE_STRING* FullImageName = (UNICODE_STRING*)buffer;
			if (FullImageName->Length > 19 * sizeof(WCHAR)) {

				WCHAR* path = FullImageName->Buffer
					+ FullImageName->Length / sizeof(WCHAR)
					- 19;
				if (_wcsicmp(path, dll) == 0) {

					return (ULONG64)basicInfo.AllocationBase;
				}
			}
		}
	}

	return 0;
}

DWORD64 FindDllExport2(HANDLE hProcess, DWORD64 DllBase, IMAGE_DATA_DIRECTORY *dir0, const UCHAR* ProcName)
{
	NTSTATUS status;
	BYTE* buffer;

	DWORD64 proc = NULL;

	buffer = HeapAlloc(GetProcessHeap(), 0, dir0->Size);
	status = NtReadVirtualMemory64(hProcess, DllBase + dir0->VirtualAddress, buffer, dir0->Size, NULL);

	IMAGE_EXPORT_DIRECTORY* exports = buffer;
	ULONG* names = (ULONG*)((DWORD64)buffer + exports->AddressOfNames - dir0->VirtualAddress);
	USHORT* ordinals = (USHORT*)((DWORD64)buffer + exports->AddressOfNameOrdinals - dir0->VirtualAddress);
	ULONG* functions = (ULONG*)((DWORD64)buffer + exports->AddressOfFunctions - dir0->VirtualAddress);


	for (ULONG i = 0; i < exports->NumberOfNames; ++i) {
	
		UCHAR* name = (UCHAR*)((DWORD64)exports + names[i] - dir0->VirtualAddress);
		
		if(strcmp(name, ProcName) == 0)
		{
			if (ordinals[i] < exports->NumberOfFunctions) {

				proc = DllBase + functions[ordinals[i]];
				break;
			}
		}
	}

	HeapFree(GetProcessHeap(), 0, buffer);

	return proc;
}

DWORD64 ResolveWoWRedirection(HANDLE hProcess, DWORD64 DllBase, DWORD64 proc, DWORD64 CHPEMetadataPointer)
{
	NTSTATUS status;

	IMAGE_ARM64EC_METADATA MetaData;
	status = NtReadVirtualMemory64(hProcess, CHPEMetadataPointer, &MetaData, sizeof(MetaData), NULL);

	ULONG size = MetaData.RedirectionMetadataCount * sizeof(IMAGE_ARM64EC_REDIRECTION_ENTRY);
	BYTE* buffer = HeapAlloc(GetProcessHeap(), 0, size);
	status = NtReadVirtualMemory64(hProcess, DllBase + MetaData.RedirectionMetadata, buffer, size, NULL);
	IMAGE_ARM64EC_REDIRECTION_ENTRY* RedirectionMetadata = buffer;

	for (ULONG i = 0; i < MetaData.RedirectionMetadataCount; i++) {
		if ((proc - DllBase) == RedirectionMetadata[i].Source) {
			proc = DllBase + RedirectionMetadata[i].Destination;
			break;
		}
	}

	HeapFree(GetProcessHeap(), 0, buffer);

	return proc;
}

DWORD64 FindDllExport(HANDLE hProcess, DWORD64 DllBase, const UCHAR* ProcName)
{
	NTSTATUS status;
	DWORD64 proc = NULL;

	IMAGE_DOS_HEADER* dos_hdr;
	IMAGE_NT_HEADERS* nt_hdrs;

	BYTE Buffer1[0x10000];
	status = NtReadVirtualMemory64(hProcess, DllBase, Buffer1, sizeof(Buffer1), NULL);

	BOOLEAN resolve_wow = ProcName[0] == '#';
	if (resolve_wow)
		ProcName++;

	dos_hdr = Buffer1;

	if (dos_hdr->e_magic != 'MZ' && dos_hdr->e_magic != 'ZM')
		return NULL;
	nt_hdrs = (IMAGE_NT_HEADERS*)((UCHAR*)dos_hdr + dos_hdr->e_lfanew);
	if (nt_hdrs->Signature != IMAGE_NT_SIGNATURE)     // 'PE\0\0'
		return NULL;

	if (nt_hdrs->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {

		IMAGE_NT_HEADERS32* nt_hdrs_32 = (IMAGE_NT_HEADERS32*)nt_hdrs;
		IMAGE_OPTIONAL_HEADER32* opt_hdr_32 = &nt_hdrs_32->OptionalHeader;

		if (opt_hdr_32->NumberOfRvaAndSizes) {

			IMAGE_DATA_DIRECTORY* dir0 = &opt_hdr_32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			proc = FindDllExport2(hProcess, DllBase, dir0, ProcName);

			IMAGE_DATA_DIRECTORY* dir10 = &opt_hdr_32->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
			if (resolve_wow && dir10->VirtualAddress && dir10->Size >= FIELD_OFFSET(IMAGE_LOAD_CONFIG_DIRECTORY32, CHPEMetadataPointer) + sizeof(ULONG)) {

				IMAGE_LOAD_CONFIG_DIRECTORY32 LoadConfig;
				status = NtReadVirtualMemory64(hProcess, DllBase + dir10->VirtualAddress, &LoadConfig, min(sizeof(LoadConfig), dir10->Size), NULL);

				if (LoadConfig.CHPEMetadataPointer)
					proc = ResolveWoWRedirection(hProcess, DllBase, proc, LoadConfig.CHPEMetadataPointer);
			}
		}
	}

	else if (nt_hdrs->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {

		IMAGE_NT_HEADERS64* nt_hdrs_64 = (IMAGE_NT_HEADERS64*)nt_hdrs;
		IMAGE_OPTIONAL_HEADER64* opt_hdr_64 = &nt_hdrs_64->OptionalHeader;

		if (opt_hdr_64->NumberOfRvaAndSizes) {

			IMAGE_DATA_DIRECTORY* dir0 = &opt_hdr_64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			proc = FindDllExport2(hProcess, DllBase, dir0, ProcName);

			IMAGE_DATA_DIRECTORY* dir10 = &opt_hdr_64->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
			if (resolve_wow && dir10->VirtualAddress && dir10->Size >= FIELD_OFFSET(IMAGE_LOAD_CONFIG_DIRECTORY64, CHPEMetadataPointer) + sizeof(ULONGLONG)) {

				IMAGE_LOAD_CONFIG_DIRECTORY64 LoadConfig;
				status = NtReadVirtualMemory64(hProcess, DllBase + dir10->VirtualAddress, &LoadConfig, min(sizeof(LoadConfig), dir10->Size), NULL);

				if (LoadConfig.CHPEMetadataPointer)
					proc = ResolveWoWRedirection(hProcess, DllBase, proc, LoadConfig.CHPEMetadataPointer);
			}
		}
	}

	return proc;
}
