/*
 * (c) FFRI Security, Inc., 2021 / Author: FFRI Security, Inc.
 */
#pragma once

#define WIN32_LEAN_AND_MEAN

#include <windows.h>

// Define KDEXT_64BIT to make all wdbgexts APIs recognize 64 bit addresses
// It is recommended for extensions to use 64 bit headers from wdbgexts so
// the extensions could support 64 bit targets.
//
#define KDEXT_64BIT
#include <wdbgexts.h>
#include <dbgeng.h>
#include <DbgHelp.h>

#include <stdexcept>
#include <string>
#include <sstream>
#include <vector>
#include <tuple>
#include <optional>
#include <unordered_map>

#include "dbg_ctl_wrapper.hpp"
