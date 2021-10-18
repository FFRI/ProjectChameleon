/*
 * (c) FFRI Security, Inc., 2021 / Author: FFRI Security, Inc.
 */
#include "pch.h"

#include "pe_utils.h"
#include "utils.h"

PIMAGE_LOAD_CONFIG_DIRECTORY GetLoadConfigDirectory(
	uint64_t imageBase) {
	uint32_t rva = GetImageDataDirectoryEntryRva(
		imageBase, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
	return (PIMAGE_LOAD_CONFIG_DIRECTORY)(rva + imageBase);
}

PIMAGE_IMPORT_DESCRIPTOR GetImportDescriptor(
	uint64_t imageBase) {
	uint32_t rva = GetImageDataDirectoryEntryRva(
		imageBase, IMAGE_DIRECTORY_ENTRY_IMPORT);
	return (PIMAGE_IMPORT_DESCRIPTOR)(rva + imageBase);
}

uint32_t GetImageDataDirectoryEntryRva(
	uint64_t imageBase,
	uint32_t dataDirectoryEntryId) {
	IMAGE_DOS_HEADER dosHeader {};
	ULONG cb = 0;
	ReadMemory(imageBase, &dosHeader, sizeof(IMAGE_DOS_HEADER), &cb);
	if (cb != sizeof(IMAGE_DOS_HEADER)) {
		dprintf("Cannot read DOS header");
		return 0;
	}

	IMAGE_NT_HEADERS ntHeaders {};
	ReadMemory(imageBase + dosHeader.e_lfanew, &ntHeaders, sizeof(IMAGE_NT_HEADERS), &cb);
	if (cb != sizeof(IMAGE_NT_HEADERS)) {
		dprintf("Cannot read NT header");
		return 0;
	}

	return ntHeaders.OptionalHeader.DataDirectory[dataDirectoryEntryId].VirtualAddress;
}

std::optional<ULONGLONG> GetIatBaseAddress(
	PIMAGE_IMPORT_DESCRIPTOR imageImportDesc,
	ULONGLONG imageBase) {
	ULONGLONG baseAddr = 0xffffffffffffffff;

	auto iter = imageImportDesc;
	auto name = ReadMemberFromStruct<IMAGE_IMPORT_DESCRIPTOR, DWORD>(iter, offsetof(IMAGE_IMPORT_DESCRIPTOR, Name));
	while (name != NULL) {
		auto imageThunk = ReadMemberFromStruct<IMAGE_IMPORT_DESCRIPTOR, DWORD>(iter, offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk)) + imageBase;
		if (imageThunk < baseAddr) {
			baseAddr = imageThunk;
		}

		iter++; 
		name = ReadMemberFromStruct<IMAGE_IMPORT_DESCRIPTOR, DWORD>(iter, offsetof(IMAGE_IMPORT_DESCRIPTOR, Name));
	}

	if (baseAddr == 0xffffffffffffffff) {
		return std::nullopt;
	}

	return baseAddr;
}

