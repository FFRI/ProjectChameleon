/*
 * (c) FFRI Security, Inc., 2021 / Author: FFRI Security, Inc.
 */
#include <Windows.h>
#include <DbgHelp.h>
#include <stdio.h>
#include <stdint.h>

#pragma comment(lib, "dbghelp.lib")

struct CHPEMetadata {
	uint32_t Version;
	uint32_t RvaOfHybridCodeMap;
	uint32_t NumberOfHybridCodeMap;
	uint32_t RvaOfX64CodeRangesToEntryPoints;
	uint32_t RvaOfArm64xRedirectionMetadata;
	uint32_t RvaOfOsArm64xDispatchCallNoRedirect;
	uint32_t RvaOfOsArm64xDispatchRet;
	uint32_t RvaOfOsArm64xDispatchCall;
	uint32_t RvaOfOsArm64xDispatchICall;
	uint32_t RvaOfOsArm64xDispatchICallCfg;
	uint32_t RvaOfX64EntryPoint;
	uint32_t RvaOfHybridAuxiliaryIat; // 0x2c
	uint32_t Field_0x30;
	uint32_t Field_0x34;
	uint32_t RvaOfOsArm64xRdtsc;
	uint32_t RvaOfOsArm64xCpuidex;
	uint32_t Field_0x40;
	uint32_t Field_0x44r;
	uint32_t RvaOfOsArm64xDispatchFptr;
	uint32_t RvaOfHybridAuxiliaryIatCopy;
};

CHPEMetadata* GetChpeMetadata(HMODULE imageBase) {
	ULONG size = 0;
	PIMAGE_LOAD_CONFIG_DIRECTORY64 loadConfigDir = (PIMAGE_LOAD_CONFIG_DIRECTORY64)ImageDirectoryEntryToData(
		imageBase, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &size);
	if (!loadConfigDir) {
		fprintf(stderr, "Cannt find load configuration directory\n");
		return NULL;
	}
	fprintf(stdout, "Image Base: %llx\nVA of CHPEMetadata: %llx\nRVA of CHPEMetadata: %llx\n",
		(ULONGLONG)imageBase,
		loadConfigDir->CHPEMetadataPointer,
		(ULONGLONG)loadConfigDir->CHPEMetadataPointer - (ULONGLONG)imageBase);

	return (CHPEMetadata*)loadConfigDir->CHPEMetadataPointer;
}

ULONGLONG GetIatBaseAddress(
	PIMAGE_IMPORT_DESCRIPTOR imageImportDesc,
	ULONGLONG imageBase) {
	ULONGLONG baseAddr = 0xffffffffffffffff;
	for (PIMAGE_IMPORT_DESCRIPTOR iter = imageImportDesc; iter->Name != NULL; iter++) {
		auto imageThunk = (iter->FirstThunk + imageBase);
		if (imageThunk < baseAddr) {
			baseAddr = imageThunk;
		}
	}
	return baseAddr;
}

ULONGLONG IatToHybridAuxIat(
	PIMAGE_THUNK_DATA thunk,
	ULONGLONG iatBaseAddr,
	ULONGLONG hybridAuxIatVA) {
	auto delta = (ULONGLONG)thunk - iatBaseAddr;
	return hybridAuxIatVA + delta;
}

void DumpAuxilaryIat(
	PIMAGE_IMPORT_DESCRIPTOR imageImportDesc,
	ULONGLONG imageBase,
	ULONGLONG iatBaseAddr,
	ULONGLONG hybridAuxIatVA) {
	for (PIMAGE_IMPORT_DESCRIPTOR iter = imageImportDesc; iter->Name != NULL; iter++) {
		auto dllName = (CHAR*)(iter->Name + imageBase);
		printf("DLL Name: %s\n", dllName);
		auto imageThunkIat = (PIMAGE_THUNK_DATA)(iter->FirstThunk + imageBase);
		auto imageThunkInt = (PIMAGE_THUNK_DATA)(iter->OriginalFirstThunk + imageBase);
		do {
			if (IMAGE_SNAP_BY_ORDINAL64(imageThunkInt->u1.Ordinal)) {
				printf("Ordinal: %llx (IAT entry RVA: %llx) (AuxIAT entry RVA: %llx)\n",
					imageThunkInt->u1.Ordinal,
					(ULONGLONG)imageThunkIat - imageBase,
					IatToHybridAuxIat(imageThunkIat, iatBaseAddr, hybridAuxIatVA) - imageBase);
			}
			else {
				auto imageImportByName = (PIMAGE_IMPORT_BY_NAME)(imageThunkInt->u1.AddressOfData + imageBase);
				printf("Name: %s (IAT entry RVA: %llx) (AuxIAT entry RVA: %llx)\n",
					imageImportByName->Name,
					(ULONGLONG)imageThunkIat - imageBase,
					IatToHybridAuxIat(imageThunkIat, iatBaseAddr, hybridAuxIatVA) - imageBase);
			}
			imageThunkIat++;
			imageThunkInt++;
		} while (imageThunkIat->u1.AddressOfData);
		puts("");
	}
}

PIMAGE_THUNK_DATA FindIatEntry(
	PIMAGE_IMPORT_DESCRIPTOR imageImportDesc,
	ULONGLONG imageBase,
	const CHAR* targetFuncName) {
	for (PIMAGE_IMPORT_DESCRIPTOR iter = imageImportDesc; iter->Name != NULL; iter++) {
		auto imageThunkIat = (PIMAGE_THUNK_DATA)(iter->FirstThunk + imageBase);
		auto imageThunkInt = (PIMAGE_THUNK_DATA)(iter->OriginalFirstThunk + imageBase);
		do {
			if (!IMAGE_SNAP_BY_ORDINAL64(imageThunkInt->u1.Ordinal)) {
				auto imageImportByName = (PIMAGE_IMPORT_BY_NAME)(imageThunkInt->u1.AddressOfData + imageBase);
				if (strcmp(targetFuncName, imageImportByName->Name) == 0) {
					return imageThunkIat;
				}
			}
			imageThunkIat++;
			imageThunkInt++;
		} while (imageThunkIat->u1.AddressOfData);
	}
	return NULL;
}

PIMAGE_THUNK_DATA FindAuxiliaryIatEntry(
	PIMAGE_IMPORT_DESCRIPTOR imageImportDesc,
	ULONGLONG imageBase,
	ULONGLONG iatBaseAddr,
	ULONGLONG hybridAuxIatVA,
	const CHAR* targetFuncName) {
	return (PIMAGE_THUNK_DATA)IatToHybridAuxIat(FindIatEntry(imageImportDesc, imageBase, targetFuncName), iatBaseAddr, hybridAuxIatVA);
}

typedef int(WINAPI* FuncMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
FuncMessageBoxA originalMessageBoxA = NULL;

int WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	(void)lpText;
	return originalMessageBoxA(hWnd, "Hoooooooked!!!!!!", lpCaption, uType);
}

void HookHybridAuxiliaryIat(const char* targetFuncName, PVOID myFunc) {
	HMODULE imageBase = GetModuleHandleA(NULL);
	CHPEMetadata* chpeMetadata = GetChpeMetadata(imageBase);

	ULONG size = 0;
	PIMAGE_IMPORT_DESCRIPTOR imageImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(
		imageBase, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);
	if (!imageImportDesc) {
		fprintf(stderr, "Cannot find image import descriptor\n");
		return;
	}

	ULONGLONG hybridAuxIatVA = (ULONGLONG)imageBase + chpeMetadata->RvaOfHybridAuxiliaryIat;
	printf("VA of hybridAuxIAT: %llx\n", hybridAuxIatVA);

	ULONGLONG iatBaseAddr = GetIatBaseAddress(imageImportDesc, (ULONGLONG)imageBase);
	printf("RVA of IAT base address = %llx\n", iatBaseAddr - (ULONGLONG)imageBase);

	// IAT Hook (it works)
	// auto msgBoxThunk = FindIatEntry(imageImportDesc, (ULONGLONG)imageBase, targetFuncName);

	// Auxiary IAT Hook (it also works)
	auto msgBoxThunk = FindAuxiliaryIatEntry(imageImportDesc, (ULONGLONG)imageBase, iatBaseAddr, hybridAuxIatVA, targetFuncName);

	originalMessageBoxA = (FuncMessageBoxA)msgBoxThunk->u1.Function;
	DWORD oldProtect = 0;
	VirtualProtect((LPVOID)msgBoxThunk, sizeof(IMAGE_THUNK_DATA), PAGE_READWRITE, &oldProtect);
	msgBoxThunk->u1.AddressOfData = (ULONGLONG)myFunc;
}

int main() {
	MessageBoxA(NULL, "Hello", "Hello", MB_OK);
	HookHybridAuxiliaryIat("MessageBoxA", MyMessageBoxA);
	MessageBoxA(NULL, "Hello", "Hello", MB_OK);

	return EXIT_SUCCESS;
}