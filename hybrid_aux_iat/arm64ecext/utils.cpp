/*
 * (c) FFRI Security, Inc., 2021 / Author: FFRI Security, Inc.
 */
#include "pch.h"
#include "utils.h"

std::vector<std::string> get_args(const char *args) {
	std::vector<std::string> string_array;
	const char *prev, *p;
	prev = p = args;
	while (*p) {
		if (*p == ' ') {
			if (p > prev)
				string_array.emplace_back(args, prev - args, p - prev);
				prev = p + 1;
			}
			++p;
		}
	if (p > prev) {
		string_array.emplace_back(args, prev - args, p - prev);
	}
	return string_array;
}

std::string to_hex_string(uint64_t i) {
	std::stringstream ss;
	ss << std::hex << i;
	return ss.str();
}

