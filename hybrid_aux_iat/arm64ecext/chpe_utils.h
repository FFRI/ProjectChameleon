/*
 * (c) FFRI Security, Inc., 2021 / Author: FFRI Security, Inc.
 */
#pragma once

#include <Windows.h>
#include <cstdint>

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
	uint32_t RvaOfHybridAuxiliaryIat;
	uint32_t Field_0x30;
	uint32_t Field_0x34;
	uint32_t RvaOfOsArm64xRdtsc;
	uint32_t RvaOfOsArm64xCpuidex;
	uint32_t Field_0x40;
	uint32_t Field_0x44;
	uint32_t RvaOfOsArm64xDispatchFptr;
	uint32_t RvaOfHybridAuxiliaryIatCopy;
};

using RedirectionMap = std::unordered_map<uint32_t, uint32_t>;

struct ImportedFunction {
	std::string name;
	uint64_t vaddrIat;
	uint64_t vaddrAuxIat;
	uint64_t vaddrAuxCopyIat;
};

struct ImportedModule {
	uint64_t imageBase;
	std::vector<ImportedFunction> entries;
};

using CHPEImportAddressTables = std::unordered_map<std::string, ImportedModule>;

std::optional<CHPEMetadata*> GetCHPEMetadaPointer(PIMAGE_LOAD_CONFIG_DIRECTORY imageLoadConfig);

std::optional<CHPEImportAddressTables> GetAllIATs(
	ULONGLONG imageBase,
	DbgController& dbgctl);

void DumpHybridAuxiliaryIat(const CHPEImportAddressTables& iats);

std::vector<ImportedFunction> CheckHybridAuxIatHooking(
	const CHPEImportAddressTables& iats);
