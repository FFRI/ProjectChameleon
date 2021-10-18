/*
 * (c) FFRI Security, Inc., 2021 / Author: FFRI Security, Inc.
 */
#pragma once

#include "pch.h"

PIMAGE_LOAD_CONFIG_DIRECTORY GetLoadConfigDirectory(
	uint64_t imageBase);

uint32_t GetImageDataDirectoryEntryRva(
	uint64_t imageBase,
	uint32_t dataDirectoryEntryId);

PIMAGE_IMPORT_DESCRIPTOR GetImportDescriptor(
	uint64_t imageBase);

std::optional<ULONGLONG> GetIatBaseAddress(
	PIMAGE_IMPORT_DESCRIPTOR imageImportDesc,
	ULONGLONG imageBase);

