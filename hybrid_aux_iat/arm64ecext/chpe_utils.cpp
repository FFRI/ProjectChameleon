/*
 * (c) FFRI Security, Inc., 2021 / Author: FFRI Security, Inc.
 */
#include "pch.h"

#include "utils.h"
#include "pe_utils.h"
#include "chpe_utils.h"

uint32_t GetA64XrmRedirection(const CHPEMetadata* chpeMetadata);

ULONGLONG IatToHybridAuxIat(
	PIMAGE_THUNK_DATA thunk,
	ULONGLONG iatBaseAddr,
	ULONGLONG hybridAuxIatVA) {
	auto delta = (ULONGLONG)thunk - iatBaseAddr;
	return hybridAuxIatVA + delta;
}

RedirectionMap GetModuleRedirectionMap(
	ULONGLONG imageBase,
	const CHPEMetadata* chpeMetadata) {
	DWORD sizeRead = 0;
	const auto rvaOfa64xrm = GetA64XrmRedirection(chpeMetadata);

	RedirectionMap a64xrm;

	uint32_t curOffset = 0;
	uint32_t x64Rva = 0, arm64Rva = 0;
	while (true) {
		ReadMemory(imageBase + rvaOfa64xrm + curOffset, &x64Rva, sizeof(uint32_t), &sizeRead);
		curOffset += 4;
		ReadMemory(imageBase + rvaOfa64xrm + curOffset, &arm64Rva, sizeof(uint32_t), &sizeRead);
		curOffset += 4;
		if (x64Rva == 0 && arm64Rva == 0) break;
		a64xrm[x64Rva] = arm64Rva;
	}
	return a64xrm;
}

std::vector<ImportedFunction> CheckHybridAuxIatHooking(
	const CHPEImportAddressTables& iats) {
	std::vector<ImportedFunction> result;

	for (auto&& modEntry : iats) {
		const auto imageLoadConfig = GetLoadConfigDirectory(modEntry.second.imageBase);
		const auto chpeMetadata = GetCHPEMetadaPointer(imageLoadConfig);
		if (chpeMetadata) {
			// NOTE: currently only ARM64EC is supported
			auto a64xrm = GetModuleRedirectionMap(modEntry.second.imageBase, chpeMetadata.value());
			for (auto&& funcEntry : modEntry.second.entries) {
				const auto vaddrIatRva = (RedirectionMap::key_type)(funcEntry.vaddrIat - modEntry.second.imageBase);
				if (a64xrm.contains(vaddrIatRva)) {
					const auto exportThunkDest = a64xrm[vaddrIatRva] + modEntry.second.imageBase;
					// FastForwarded entry
					if (exportThunkDest == funcEntry.vaddrAuxIat) {
						continue;
					}
					// Non-FastForwarded entry
					if (funcEntry.vaddrAuxIat == funcEntry.vaddrAuxCopyIat) {
						continue;
					}
					// Suspicious
					result.emplace_back(funcEntry);
				}
			}
		}
	}

	return result;
}

std::optional<CHPEMetadata*> GetCHPEMetadaPointer(PIMAGE_LOAD_CONFIG_DIRECTORY imageLoadConfig) {
	CHPEMetadata* chpeMetadata = nullptr;
	DWORD sizeRead = 0;
	ReadMemory((ULONG64)imageLoadConfig + offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, CHPEMetadataPointer),
		&chpeMetadata,
		sizeof(CHPEMetadata*),
		&sizeRead);

	if (!chpeMetadata) {
		dprintf("CHPEMetadataPointer is NULL, so this module might not be CHPE.\n");
		return std::nullopt;	
	}
	return chpeMetadata;
}

uint32_t GetA64XrmRedirection(const CHPEMetadata* chpeMetadata) {
	uint32_t rvaOfArm64xRedirectionMetadata = 0;
	DWORD sizeRead = 0;
	ReadMemory((ULONG64)chpeMetadata + offsetof(CHPEMetadata, RvaOfArm64xRedirectionMetadata),
		&rvaOfArm64xRedirectionMetadata,
		sizeof(uint32_t),
		&sizeRead);
	return rvaOfArm64xRedirectionMetadata;
}

uint32_t GetHybridAuxIatRva(const CHPEMetadata* chpeMetadata) {
	uint32_t rvaOfHybridAuxIat = 0;
	DWORD sizeRead = 0;
	ReadMemory((ULONG64)chpeMetadata + offsetof(CHPEMetadata, RvaOfHybridAuxiliaryIat),
		&rvaOfHybridAuxIat,
		sizeof(uint32_t),
		&sizeRead);
	return rvaOfHybridAuxIat;
}

uint32_t GetHybridAuxIatCopyRva(const CHPEMetadata* chpeMetadata) {
	uint32_t rvaOfHybridAuxCopyIat = 0;
	DWORD sizeRead = 0;
	ReadMemory((ULONG64)chpeMetadata + offsetof(CHPEMetadata, RvaOfHybridAuxiliaryIatCopy),
		&rvaOfHybridAuxCopyIat,
		sizeof(uint32_t),
		&sizeRead);
	return rvaOfHybridAuxCopyIat;
}

std::optional<CHPEImportAddressTables> GetAllIATs(
    ULONGLONG imageBase,
	DbgController& dbgCtl) {
	const auto imageImportDesc = GetImportDescriptor(imageBase);
	dprintf("Image Import Descriptor is %p\n", imageImportDesc);

	const auto imageLoadConfig = GetLoadConfigDirectory(imageBase);
	dprintf("Image Load Config Directory is %p\n", imageLoadConfig);

	const auto chpeMetadata = GetCHPEMetadaPointer(imageLoadConfig);
	if (!chpeMetadata) {
		dprintf("CHPEMetadataPointer is NULL, so this module might not be CHPE.\n");
		return std::nullopt;	
	}

	const auto hybridAuxIatVA = GetHybridAuxIatRva(chpeMetadata.value()) + imageBase;
	const auto hybridAuxIatCopyVa = GetHybridAuxIatCopyRva(chpeMetadata.value()) + imageBase;
	const auto iatBaseAddr = GetIatBaseAddress(imageImportDesc, imageBase);
	if (!iatBaseAddr) {
		dprintf("Failed to IAT base address\n");
		return std::nullopt;
	}

	CHPEImportAddressTables iats;

	auto iter = imageImportDesc;
	auto modNameRVA = ReadMemberFromStruct<IMAGE_IMPORT_DESCRIPTOR, DWORD>(iter, offsetof(IMAGE_IMPORT_DESCRIPTOR, Name));
	while (modNameRVA != NULL) {
		auto modName = dbgCtl.ReadAscii(modNameRVA + imageBase); 
		auto imageThunkIat =
			(PIMAGE_THUNK_DATA)(ReadMemberFromStruct<IMAGE_IMPORT_DESCRIPTOR, DWORD>(iter, offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk)) + imageBase);
		auto imageThunkInt =
			(PIMAGE_THUNK_DATA)(ReadMemberFromStruct<IMAGE_IMPORT_DESCRIPTOR, DWORD>(iter, offsetof(IMAGE_IMPORT_DESCRIPTOR, OriginalFirstThunk)) + imageBase);

		ImportedModule modInfo;
		ULONGLONG addressOfDataIat = 0;
		do {
			const auto addressOfDataInt = ReadMemberFromStruct<IMAGE_THUNK_DATA, ULONGLONG>(imageThunkInt, offsetof(IMAGE_THUNK_DATA, u1));

			std::string exportedName;
			if (IMAGE_SNAP_BY_ORDINAL(addressOfDataInt)) {
				// exported as ordinal
				exportedName = "Ordinal_"s + to_hex_string(IMAGE_ORDINAL(addressOfDataInt));
			} else {
				// exported as name
				const auto imageImportByNameAddr = addressOfDataInt + imageBase;
				exportedName = dbgCtl.ReadAscii(imageImportByNameAddr + offsetof(IMAGE_IMPORT_BY_NAME, Name));
			}
			ULONG64 iatEntry = 0, auxIatEntry = 0, auxIatCopyEntry = 0;
			const auto auxIatEntryAddr = IatToHybridAuxIat(imageThunkIat, iatBaseAddr.value(), hybridAuxIatVA);
			const auto auxIatCopyEntryAddr = IatToHybridAuxIat(imageThunkIat, iatBaseAddr.value(), hybridAuxIatCopyVa);
			ReadPointer((ULONG64)imageThunkIat, &iatEntry);
			ReadPointer((ULONG64)auxIatEntryAddr, &auxIatEntry);
			ReadPointer((ULONG64)auxIatCopyEntryAddr, &auxIatCopyEntry);

			modInfo.entries.emplace_back(exportedName, iatEntry, auxIatEntry, auxIatCopyEntry);
			
			imageThunkIat++;
			imageThunkInt++;

			addressOfDataIat =
				ReadMemberFromStruct<IMAGE_THUNK_DATA, ULONGLONG>(imageThunkIat, offsetof(IMAGE_THUNK_DATA, u1));
		} while (addressOfDataIat);

		const auto modImageBase = dbgCtl.GetModuleInfo(modInfo.entries.front().vaddrIat);
		modInfo.imageBase = modImageBase.base_addr;
		iats[modName] = modInfo;

		iter++;
		modNameRVA = ReadMemberFromStruct<IMAGE_IMPORT_DESCRIPTOR, DWORD>(iter, offsetof(IMAGE_IMPORT_DESCRIPTOR, Name));
	}

	return iats;
}

void DumpHybridAuxiliaryIat(const CHPEImportAddressTables& iats) {
	for (auto&& modEntry : iats) {
		dprintf("Module: %s %p\n", modEntry.first.c_str(), modEntry.second.imageBase);
		dprintf("%20.20s %16.16s %16.16s %16.16s\n", "Name", "IAT", "Aux IAT", "Aux IAT copy");
		for (auto&& funcEntry : modEntry.second.entries) {
			dprintf("%20.20s %p %p %p\n",
				funcEntry.name.c_str(),
				funcEntry.vaddrIat,
				funcEntry.vaddrAuxIat,
				funcEntry.vaddrAuxCopyIat);
		}
		dprintf("\n");
	}
}
