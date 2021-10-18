/*
 * (c) FFRI Security, Inc., 2021 / Author: FFRI Security, Inc.
 */
#pragma once

#include "pch.h"

std::vector<std::string> get_args(const char* args);
std::string to_hex_string(uint64_t i);

template <typename S, typename T>
T ReadMemberFromStruct(S* structData,
	const size_t offset) {
	auto readData = (T)0;
	DWORD sizeRead = 0;
	ReadMemory((ULONG64)structData + offset,
		&readData,
		sizeof(T),
		&sizeRead);
	if (sizeRead != sizeof(T)) {
		throw std::runtime_error("Cannot read memory at ReadMemberFromStruct");
	}
	return readData;
}

