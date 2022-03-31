/*
 * Copyright 2022 David Xanatos, xanasoft.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
 
#include <Ntstatus.h>
#define WIN32_NO_STATUS
typedef long NTSTATUS;

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// ntimage.h


typedef struct _IMAGE_CHPE_METADATA_X86 {
	ULONG  Version;
	ULONG  CHPECodeAddressRangeOffset;
	ULONG  CHPECodeAddressRangeCount;
	ULONG  WowA64ExceptionHandlerFunctionPointer;
	ULONG  WowA64DispatchCallFunctionPointer;
	ULONG  WowA64DispatchIndirectCallFunctionPointer;
	ULONG  WowA64DispatchIndirectCallCfgFunctionPointer;
	ULONG  WowA64DispatchRetFunctionPointer;
	ULONG  WowA64DispatchRetLeafFunctionPointer;
	ULONG  WowA64DispatchJumpFunctionPointer;
	ULONG  CompilerIATPointer;         // Present if Version >= 2
	ULONG  WowA64RdtscFunctionPointer; // Present if Version >= 3
} IMAGE_CHPE_METADATA_X86, * PIMAGE_CHPE_METADATA_X86;

typedef struct _IMAGE_CHPE_RANGE_ENTRY {
	union {
		ULONG StartOffset;
		struct {
			ULONG NativeCode : 1;
			ULONG AddressBits : 31;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

	ULONG Length;
} IMAGE_CHPE_RANGE_ENTRY, * PIMAGE_CHPE_RANGE_ENTRY;

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
	_Out_opt_ PSIZE_T NumberOfBytesRead);

NTSYSCALLAPI NTSTATUS NTAPI NtQueryVirtualMemory(
	IN  HANDLE ProcessHandle,
	IN  PVOID BaseAddress,
	IN  MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT PVOID MemoryInformation,
	IN  SIZE_T MemoryInformationLength,
	OUT PSIZE_T ReturnLength);

#define NtReadVirtualMemory64 NtReadVirtualMemory
#define NtQueryVirtualMemory64 NtQueryVirtualMemory

//#endif

//void DbgPrintf(const char* format, ...);

ULONG64 FindDllBase(HANDLE ProcessHandle, const WCHAR* dll)
{
	char buffer[512];
	ULONG len = wcslen(dll);

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
			if (FullImageName->Length > len * sizeof(WCHAR)) {

				WCHAR* path = FullImageName->Buffer
					+ FullImageName->Length / sizeof(WCHAR)
					- len;
				if (_wcsicmp(path, dll) == 0) {

					//DbgPrintf("%S base address: 0x%08x%08x\n", dll, (ULONG)(basicInfo.AllocationBase >> 32), (ULONG)basicInfo.AllocationBase);
					return (ULONG64)basicInfo.AllocationBase;
				}
			}
		}
	}

	return 0;
}



typedef NTSYSCALLAPI NTSTATUS (__cdecl *P_ReadDll)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ DWORD64 BaseAddress,
	_Out_writes_bytes_(BufferSize) PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesRead);


IMAGE_SECTION_HEADER* FindImageSection(DWORD rva, PIMAGE_NT_HEADERS32 pNTHeader)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
	for (ULONG i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++) {
		DWORD size = section->Misc.VirtualSize;
		if (size == 0)
			size = section->SizeOfRawData;
		if ((rva >= section->VirtualAddress) && (rva < (section->VirtualAddress + size)))
			return section;
	}
	return NULL;
}

DWORD64 FindImagePosition(DWORD rva, void* pNTHeader, DWORD64 imageBase)
{
	if (imageBase != 0) // live image
		return imageBase + rva;
	// file on disk
	IMAGE_SECTION_HEADER* pSectionHdr = FindImageSection(rva, pNTHeader);
	if (!pSectionHdr)
		return 0;
	DWORD delta = pSectionHdr->VirtualAddress - pSectionHdr->PointerToRawData;
	//return imageBase + rva - delta;
	return rva - delta;
}

DWORD64 FindDllExport2(P_ReadDll ReadDll, HANDLE hProcess, DWORD64 DllBase, IMAGE_DATA_DIRECTORY *dir0, const char* ProcName, void* pNTHeader)
{
	NTSTATUS status;
	BYTE* buffer;

	//	dir0->VirtualAddress = ; // todo alternative loader dirctroy

	DWORD64 proc = NULL;

	DWORD64 dir0Address = FindImagePosition(dir0->VirtualAddress, pNTHeader, DllBase);

	buffer = HeapAlloc(GetProcessHeap(), 0, dir0->Size);
	//status = ReadDll(hProcess, DllBase + dir0->VirtualAddress, buffer, dir0->Size, NULL);
	status = ReadDll(hProcess, dir0Address, buffer, dir0->Size, NULL);

	//DbgPrintf("Export Address: 0x%08x\n", dir0->VirtualAddress);
	//IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*) ((BYTE*)DllBase + dir0->VirtualAddress);
	IMAGE_EXPORT_DIRECTORY* exports = buffer;

	//DbgPrintf("Export Names: 0x%08x\n", exports->AddressOfNames);
	//ULONG* names = (ULONG*) ((BYTE*)DllBase + exports->AddressOfNames);
	ULONG* names = (ULONG*)((DWORD64)buffer + exports->AddressOfNames - dir0->VirtualAddress);
	
	//DbgPrintf("Export Ordinals: 0x%08x\n", exports->AddressOfNameOrdinals);
	//USHORT* ordinals = (USHORT*) ((BYTE*)DllBase + exports->AddressOfNameOrdinals);
	USHORT* ordinals = (USHORT*)((DWORD64)buffer + exports->AddressOfNameOrdinals - dir0->VirtualAddress);

	//DbgPrintf("Export Ordinals: 0x%08x\n", exports->AddressOfFunctions);
	//ULONG* functions = (ULONG*) ((BYTE*)DllBase + exports->AddressOfFunctions);
	ULONG* functions = (ULONG*)((DWORD64)buffer + exports->AddressOfFunctions - dir0->VirtualAddress);


	for (ULONG i = 0; i < exports->NumberOfNames; ++i) {

		//BYTE* name = (BYTE*)DllBase + names[i];
		char* name = (char*)((DWORD64)exports + names[i] - dir0->VirtualAddress);
		
		if(strcmp(name, ProcName) == 0)
		{
			if (ordinals[i] < exports->NumberOfFunctions) {

				proc = DllBase + functions[ordinals[i]];

        // Note: if this is an arm32 image the real address has a 0x01 appended to indicate it uses the thumb instruction set
				//if (((PIMAGE_NT_HEADERS32)pNTHeader)->FileHeader.Machine == IMAGE_FILE_MACHINE_ARMNT)
				//	proc &= ~1;

				break;
			}
		}
	}

	if (proc && proc >= dir0Address && proc < dir0Address + dir0->Size) {

		//
		// if the export points inside the export table, then it is a
		// forwarder entry.  we don't handle these, because none of the
		// exports we need is a forwarder entry.  if this changes, we
		// might have to scan LDR tables to find the target dll
		//

		proc = NULL;
	}

	HeapFree(GetProcessHeap(), 0, buffer);

	return proc;
}

DWORD64 ResolveWoWRedirection32(P_ReadDll ReadDll, HANDLE hProcess, DWORD64 DllBase, DWORD64 proc, DWORD64 CHPEMetadataPointer, void* pNTHeader)
{
	NTSTATUS status;

	IMAGE_CHPE_METADATA_X86 MetaData;
	status = ReadDll(hProcess, CHPEMetadataPointer, &MetaData, sizeof(MetaData), NULL);

	/*ULONG size = MetaData.CHPECodeAddressRangeCount * sizeof(IMAGE_CHPE_RANGE_ENTRY);
	BYTE* buffer = HeapAlloc(GetProcessHeap(), 0, size);
	status = ReadDll(hProcess, FindImagePosition(MetaData.CHPECodeAddressRangeOffset, pNTHeader, DllBase), buffer, size, NULL);
	IMAGE_CHPE_RANGE_ENTRY* RedirectionMetadata = buffer;

	for (ULONG i = 0; i < MetaData.CHPECodeAddressRangeCount; i++) {
		if ((proc - DllBase) == RedirectionMetadata[i].StartOffset) {
			proc = DllBase + RedirectionMetadata[i].Destination;
			break;
		}
	}

	HeapFree(GetProcessHeap(), 0, buffer);*/

	return proc;
}

DWORD64 ResolveWoWRedirection64(P_ReadDll ReadDll, HANDLE hProcess, DWORD64 DllBase, DWORD64 proc, DWORD64 CHPEMetadataPointer, void* pNTHeader)
{
	NTSTATUS status;

	IMAGE_ARM64EC_METADATA MetaData;
	status = ReadDll(hProcess, CHPEMetadataPointer, &MetaData, sizeof(MetaData), NULL);

	ULONG size = MetaData.RedirectionMetadataCount * sizeof(IMAGE_ARM64EC_REDIRECTION_ENTRY);
	BYTE* buffer = HeapAlloc(GetProcessHeap(), 0, size);
	status = ReadDll(hProcess, FindImagePosition(MetaData.RedirectionMetadata, pNTHeader, DllBase), buffer, size, NULL);
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

DWORD64 FindDllExport1(P_ReadDll ReadDll, HANDLE hProcess, DWORD64 DllBase, const char* ProcName)
{
	NTSTATUS status;
	DWORD64 proc = NULL;

	IMAGE_DOS_HEADER* dos_hdr;
	IMAGE_NT_HEADERS* nt_hdrs;

	BYTE Buffer1[0x10000];
	status = ReadDll(hProcess, DllBase, Buffer1, sizeof(Buffer1), NULL);

	BOOLEAN resolve_wow = ProcName[0] == '#';
	if (resolve_wow)
		ProcName++;

	//
	// find the DllMain entrypoint for the dll
	//

	//dos_hdr = (void*)DllBase;
	dos_hdr = Buffer1;

	if (dos_hdr->e_magic != 'MZ' && dos_hdr->e_magic != 'ZM')
		return NULL;
	nt_hdrs = (IMAGE_NT_HEADERS*)((BYTE*)dos_hdr + dos_hdr->e_lfanew);
	if (nt_hdrs->Signature != IMAGE_NT_SIGNATURE)     // 'PE\0\0'
		return NULL;

	if (nt_hdrs->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {

		IMAGE_NT_HEADERS32* nt_hdrs_32 = (IMAGE_NT_HEADERS32*)nt_hdrs;
		IMAGE_OPTIONAL_HEADER32* opt_hdr_32 = &nt_hdrs_32->OptionalHeader;

		if (opt_hdr_32->NumberOfRvaAndSizes) {

			IMAGE_DATA_DIRECTORY* dir0 = &opt_hdr_32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			proc = FindDllExport2(ReadDll, hProcess, DllBase, dir0, ProcName, nt_hdrs_32);

			//IMAGE_DATA_DIRECTORY* dir10 = &opt_hdr_32->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
			//if (resolve_wow && dir10->VirtualAddress && dir10->Size >= FIELD_OFFSET(IMAGE_LOAD_CONFIG_DIRECTORY32, CHPEMetadataPointer) + sizeof(ULONG)) {

			//	IMAGE_LOAD_CONFIG_DIRECTORY32 LoadConfig;
			//	status = ReadDll(hProcess, FindImagePosition(dir10->VirtualAddress, nt_hdrs_32, DllBase), &LoadConfig, min(sizeof(LoadConfig), dir10->Size), NULL);

			//	if (LoadConfig.CHPEMetadataPointer) {
			//		if (DllBase == 0) // file on disk
			//			LoadConfig.CHPEMetadataPointer = FindImagePosition(LoadConfig.CHPEMetadataPointer - opt_hdr_32->ImageBase, nt_hdrs_32, DllBase);
			//		proc = ResolveWoWRedirection32(ReadDll, hProcess, DllBase, proc, LoadConfig.CHPEMetadataPointer, nt_hdrs_32);
			//	}
			//}
		}
	}

	else if (nt_hdrs->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {

		IMAGE_NT_HEADERS64* nt_hdrs_64 = (IMAGE_NT_HEADERS64*)nt_hdrs;
		IMAGE_OPTIONAL_HEADER64* opt_hdr_64 = &nt_hdrs_64->OptionalHeader;

		if (opt_hdr_64->NumberOfRvaAndSizes) {

			IMAGE_DATA_DIRECTORY* dir0 = &opt_hdr_64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			proc = FindDllExport2(ReadDll, hProcess, DllBase, dir0, ProcName, nt_hdrs_64);

			IMAGE_DATA_DIRECTORY* dir10 = &opt_hdr_64->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
			if (resolve_wow && dir10->VirtualAddress && dir10->Size >= FIELD_OFFSET(IMAGE_LOAD_CONFIG_DIRECTORY64, CHPEMetadataPointer) + sizeof(ULONGLONG)) {

				IMAGE_LOAD_CONFIG_DIRECTORY64 LoadConfig;
				status = ReadDll(hProcess, FindImagePosition(dir10->VirtualAddress, nt_hdrs_64, DllBase), &LoadConfig, min(sizeof(LoadConfig), dir10->Size), NULL);

				//LoadConfig.DynamicValueRelocTableSection

				if (LoadConfig.CHPEMetadataPointer) {
					if (DllBase == 0) // file on disk
						LoadConfig.CHPEMetadataPointer = FindImagePosition(LoadConfig.CHPEMetadataPointer - opt_hdr_64->ImageBase, nt_hdrs_64, DllBase);
					proc = ResolveWoWRedirection64(ReadDll, hProcess, DllBase, proc, LoadConfig.CHPEMetadataPointer, nt_hdrs_64);
				}
			}
		}
	}

	return proc;
}

DWORD64 FindDllExport(HANDLE hProcess, DWORD64 DllBase, const char* ProcName)
{
	return FindDllExport1(NtReadVirtualMemory64, hProcess, DllBase, ProcName);
}

NTSTATUS __cdecl ReadDllFile(
	_In_ HANDLE FileHandle,
	_In_opt_ DWORD64 BaseAddress,
	_Out_writes_bytes_(BufferSize) PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T pNumberOfBytesRead)
{
	LARGE_INTEGER pos;
	pos.QuadPart = BaseAddress;
	SetFilePointerEx(FileHandle, pos, NULL, FILE_BEGIN);
	DWORD NumberOfBytesRead;
	BOOL ret = ReadFile(FileHandle, Buffer, BufferSize, &NumberOfBytesRead, NULL);
	return STATUS_SUCCESS; // todo
}

DWORD64 FindDllExportFromFile(const WCHAR* dll, const char* ProcName)
{
	DWORD64 proc;
	HANDLE hFile = CreateFileW(dll, GENERIC_READ, (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE), NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return 0;

	proc = FindDllExport1(ReadDllFile, hFile, 0, ProcName);

	CloseHandle(hFile);
	return proc;
}
