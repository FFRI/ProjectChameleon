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
 * This file can be also used under the therms of the GLP and LGPL licenses.
 *  Whatever floats your boat...
 *
 */
 
#include <stdio.h>
#include <windows.h>
#include <winternl.h>

extern "C" {

NTSYSCALLAPI NTSTATUS NTAPI NtAllocateVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_In_ ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG AllocationType,
	_In_ ULONG Protect
);

NTSYSCALLAPI NTSTATUS NTAPI NtReadVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_Out_writes_bytes_(BufferSize) PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesRead
);


NTSYSCALLAPI NTSTATUS NTAPI NtWriteVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_reads_bytes_(BufferSize) PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesWritten
);

NTSYSCALLAPI NTSTATUS NTAPI NtProtectVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG NewProtect,
	_Out_ PULONG OldProtect
);

NTSYSCALLAPI NTSTATUS NTAPI NtFlushInstructionCache(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_ SIZE_T Length
);

	ULONG64 FindDllBase(HANDLE ProcessHandle, const WCHAR* dll);
	DWORD64 FindDllExport(HANDLE hProcess, DWORD64 DllBase, const char* ProcName);
}

int main()
{
	wchar_t prog[MAX_PATH] = L"C:\\windows\\system32\\cmd.exe";

	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(STARTUPINFO);
	if (!CreateProcessW(NULL, prog, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		fprintf(stderr, "CreateProcess(\"%S\") failed; error code = 0x%08X\n", prog, GetLastError());
		return 1;
	}

	DWORD64 ntdllBase = FindDllBase(pi.hProcess, L"ntdll.dll");
	DWORD64 pTargetFunc = FindDllExport(pi.hProcess, ntdllBase, "#LdrInitializeThunk");

	UCHAR code[24];

	union
	{
		PBYTE pB;
		PWORD  pW;
		PDWORD pL;
		PDWORD64 pQ;
	} ip;
	ip.pB = code;

	*ip.pL++ = 0xD43E0000;		// brk #0xF000 // ARM
	//*ip.pB++ = 0xCC;			// int3 // x86/x64

	void* RegionBase = (void*)pTargetFunc;
	SIZE_T RegionSize = sizeof(code);
	ULONG OldProtect;
	NtProtectVirtualMemory(pi.hProcess, &RegionBase, &RegionSize, PAGE_EXECUTE_READWRITE, &OldProtect);

	NtWriteVirtualMemory(pi.hProcess, (void*)pTargetFunc, code, ip.pB - code, NULL);

	NtFlushInstructionCache(pi.hProcess, (void*)pTargetFunc, ip.pB - code);

	if (ResumeThread(pi.hThread) == -1) {
		fprintf(stderr, "ResumeThread failed; error code = 0x%08X\n", GetLastError());
		return 1;
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return 0;
}