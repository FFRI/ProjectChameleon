/*
 * (c) FFRI Security, Inc., 2021 / Author: FFRI Security, Inc.
 */
#include "pch.h"

#include "utils.h"
#include "pe_utils.h"
#include "chpe_utils.h"

WINDBG_EXTENSION_APIS ExtensionApis;

#ifdef _DEBUG
#define DEBUG_LOG(...) ExtensionApis.lpOutputRoutine(__VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

extern "C" {
	HRESULT CALLBACK DebugExtensionInitialize(PULONG version, PULONG flags) {
		HRESULT hResult;
		PDEBUG_CONTROL debugControl;
		IDebugClient* debugClient;

		*version = DEBUG_EXTENSION_VERSION(1, 0);
		*flags = 0;
		hResult = S_OK;

		if ((hResult = DebugCreate(__uuidof(IDebugClient), (void**)&debugClient)) != S_OK) {
			return hResult;
		}

		if ((hResult = debugClient->QueryInterface(__uuidof(IDebugControl),
			(void**)&debugControl)) == S_OK) {
			ExtensionApis.nSize = sizeof(ExtensionApis);
			hResult = debugControl->GetWindbgExtensionApis64(&ExtensionApis);
			debugControl->Release();
		}
		debugClient->Release();
		return hResult;
	}

	void CALLBACK DebugExtensionUninitialize(void) {
		return;
	}

	void CALLBACK DebugExtensionNotify(ULONG Notify, ULONG64 Argument) {
		UNREFERENCED_PARAMETER(Notify);
		UNREFERENCED_PARAMETER(Argument);
	}

	HRESULT CALLBACK show(PDEBUG_CLIENT client, PCSTR args) {
		DbgController dbgCtl(client);
		try {
			const auto vargs = get_args(args);
			if (vargs.size() != 2) {
				dprintf("Usage: !show ImageBase (or ImageName) FunctionName\n");
				return E_FAIL;
			}

			const uint64_t imageBase = GetExpression(vargs[0].c_str());
			dprintf("Image Base is %p\n", imageBase);
			const auto targetFuncName = vargs[1];

			const auto iats = GetAllIATs(imageBase, dbgCtl);
			if (!iats) {
				dprintf("Failed to get IATs\n");
				return E_FAIL;
			}

			for (auto&& modEntry : iats.value()) {
				for (auto&& funcEntry : modEntry.second.entries) {
					if (funcEntry.name.find(targetFuncName) != std::string::npos) {
						dprintf("%30.30s %16.16s %16.16s %16.16s\n",
							"Name", "IAT", "Aux IAT", "Aux IAT Copy");
						dprintf("%30.30s %p %p %p\n",
							funcEntry.name.c_str(),
							funcEntry.vaddrIat,
							funcEntry.vaddrAuxIat,
							funcEntry.vaddrAuxCopyIat);
						return S_OK;
					}
				}
			}
			
			dprintf("%s is not found\n", targetFuncName.c_str());
			return S_OK;
		}	
		catch (const std::system_error& err) {
			ExtensionApis.lpOutputRoutine("Error (%s) occured\n", err.what());
			return E_FAIL;		
		}
		catch (const std::runtime_error& err) {
			ExtensionApis.lpOutputRoutine("Error (%s) occured\n", err.what());
			return E_FAIL;		
		}

	}

	HRESULT CALLBACK check(PDEBUG_CLIENT client, PCSTR args) {
		DbgController dbgCtl(client);
		try {
			const auto vargs = get_args(args);
			if (vargs.size() != 1) {
				dprintf("Usage: !check ImageBase (or ImageName)\n");
				return E_FAIL;
			}

			const uint64_t imageBase = GetExpression(vargs[0].c_str());
			dprintf("Image Base is %p\n", imageBase);

			const auto iats = GetAllIATs(imageBase, dbgCtl);
			if (!iats) {
				dprintf("Failed to get IATs\n");
				return E_FAIL;
			}

			const auto hookedFuncs = CheckHybridAuxIatHooking(iats.value());
			if (hookedFuncs.size() == 0) {
				dprintf("Hybrid Auxiliary IAT hooked entries are not found.\n");
				return S_OK;
			}
			dprintf("Possibly hooked Hybrid Auxiliary IAT entries are found.\n");
			dprintf("%30.30s %16.16s %16.16s %16.16s\n", "Name", "IAT", "Aux IAT", "Aux IAT Copy");
			for (auto&& hookedFunc : hookedFuncs) {
				dprintf("%30.30s %p %p %p\n",
					hookedFunc.name.c_str(),
					hookedFunc.vaddrIat,
					hookedFunc.vaddrAuxIat,
					hookedFunc.vaddrAuxCopyIat);
			}
			return S_OK;
		}	
		catch (const std::system_error& err) {
			ExtensionApis.lpOutputRoutine("Error (%s) occured\n", err.what());
			return E_FAIL;		
		}
		catch (const std::runtime_error& err) {
			ExtensionApis.lpOutputRoutine("Error (%s) occured\n", err.what());
			return E_FAIL;		
		}
	}

	HRESULT CALLBACK dump(PDEBUG_CLIENT client, PCSTR args) {
		DbgController dbgCtl(client);
		try {
			const auto vargs = get_args(args);
			if (vargs.size() != 1) {
				dprintf("Usage: !dump ImageBase (or ImageName)\n");
				return E_FAIL;
			}

			const uint64_t imageBase = GetExpression(vargs[0].c_str());
			dprintf("Image Base is %p\n", imageBase);

			const auto iats = GetAllIATs(imageBase, dbgCtl);
			if (!iats) {
				dprintf("Failed to get IATs\n");
				return E_FAIL;
			}

			DumpHybridAuxiliaryIat(iats.value());
			return S_OK;
		}
		catch (const std::system_error& err) {
			ExtensionApis.lpOutputRoutine("Error (%s) occured\n", err.what());
			return E_FAIL;		
		}
		catch (const std::runtime_error& err) {
			ExtensionApis.lpOutputRoutine("Error (%s) occured\n", err.what());
			return E_FAIL;		
		}
	}
}

DECLARE_API(help) {
	UNREFERENCED_PARAMETER(args);
	UNREFERENCED_PARAMETER(dwProcessor);
	UNREFERENCED_PARAMETER(dwCurrentPc);
	UNREFERENCED_PARAMETER(hCurrentThread);
	UNREFERENCED_PARAMETER(hCurrentProcess);
	dprintf(
		"!dump <image base> - dump the Hybrid Auxiliary IAT of a module\n"
		"!show <image base> <function name> - show the Hybrid Auxiliary IAT entry of a function\n"
		"!check <image base> - check whether Hybrid Auxiliary IAT hooking is used\n"
	);
}

