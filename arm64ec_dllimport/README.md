# What is this

Its a hand made GetProcAddress which allows to get exported function addresses from x64 (or arm64ec) processes running on arm64 windows.
When applied to a native arm64 process the result is same as from LdrGetProcedureAddress i.e. it returns the normal native export.
Howe ever when called upon a x64 or arm64ec process it returns the result form the alternative export table namely the "EXP+#..." exports, i.e. the x64 stubs which invoke the native arm64 "#..." function.
When the function name is prefixed with a '#' the provided FindDllExport extracts address the not directly exported native function and returns it.

This library is suitable for finding entry points for code injection as well as to get function addresses to be used in shell code.

The provided FindDllBase helper allows to locate the base address of a dll given a part of its path (or name only) in the address space of an other process.

# Example

//ntdllBase 0x00007ffa5a7d0000
//0x00007ffa5a811050 {ntdll.dll!LdrLoadDll(void)}
//0x00007ffa5a7d1890 {ntdll.dll!EXP+#LdrLoadDll}
//0x00007ffa5a969920 {ntdll.dll!#LdrLoadDll}

HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
//DWORD64 LLW1 = GetProcAddress(hNtdll, "LdrLoadDll");
DWORD64 LLW1 = FindDllExport(GetCurrentProcess(), (DWORD64)hNtdll, "LdrLoadDll");

DWORD64 ntdllBase = FindDllBase(hProcess, L"\\system32\\ntdll.dll");
DWORD64 LLW2 = FindDllExport(hProcess, ntdllBase, "LdrLoadDll");
DWORD64 LLW3 = FindDllExport(hProcess, ntdllBase, "#LdrLoadDll");

# Supplementary notes

The code is prepared to be used with https://github.com/rwfpl/rewolf-wow64ext allowing it to be hosted in a x86 32 bit process, a suitable analogon for 32bit arm needs still to be made.