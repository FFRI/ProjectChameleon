/*
 * (c) FFRI Security, Inc., 2021 / Author: FFRI Security, Inc.
 */
#pragma once

using std::system_error;
using std::system_category;
using std::to_string;
using namespace std::literals::string_literals;

#define THROW_IF_FAIL(EXPR) \
	do {\
		HRESULT err;\
		if ((err = (EXPR)) != S_OK) {\
			throw system_error(std::error_code(err, system_category()), "code is "s + to_string(err) + " at " __FILE__ ":" + to_string(__LINE__));\
		}\
	} while (0)

#ifdef _DEBUG
#define DEBUG_LOG(...) dbg_ctl_->Output(DEBUG_OUTPUT_NORMAL, __VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

class DbgController final {
	template <class T>
	class DbgDeleter {
	public:
		void operator()(T* ptr) const {
			if (ptr) ptr->Release();
		}
	};

	struct DbgModParams {
		uint64_t base_addr = 0;
		uint32_t size = 0;
		uint32_t time_date_stamp = 0;
		uint32_t checksum = 0;
		std::string name;
	};

	struct DbgStepResult {
		uint64_t pc = 0;
		uint32_t insn_size = 0;
	};

	PDEBUG_CLIENT dbg_client_ = nullptr;
	std::unique_ptr<IDebugControl, DbgDeleter<IDebugControl>> dbg_ctl_;
	std::unique_ptr<IDebugRegisters2, DbgDeleter<IDebugRegisters2>> dbg_registers_;
	std::unique_ptr<IDebugSymbols3, DbgDeleter<IDebugSymbols3>> dbg_symbols_;
	std::unique_ptr<IDebugDataSpaces4, DbgDeleter<IDebugDataSpaces4>> dbg_data_spaces_;

	uint32_t GetInsnSize(IDebugControl* dbg_ctl, const uint64_t pc) {
		uint64_t near_offset = 0;
		dbg_ctl->GetNearInstruction(pc, 1, &near_offset);
		return static_cast<uint32_t>(near_offset - pc);
	}

	DbgStepResult DbgStep(const char* step_cmd) {
		RunCmd(dbg_ctl_.get(), step_cmd);
		const auto pc = GetCurrentPc();
		const auto insn_size = GetInsnSize(dbg_ctl_.get(), pc);
		return {
			pc,
			insn_size
		};
	}

	DbgStepResult DbgStepInto() {
		return DbgStep("t");
	}

	DbgStepResult DbgStepOver() {
		return DbgStep("p");
	}

	void RunCmd(IDebugControl* dbg_ctl, const char* cmd, ULONG timeout = INFINITE) {
		THROW_IF_FAIL(dbg_ctl->Execute(DEBUG_OUTCTL_ALL_CLIENTS | DEBUG_OUTCTL_OVERRIDE_MASK | DEBUG_OUTCTL_NOT_LOGGED,
			cmd, DEBUG_EXECUTE_DEFAULT));
		THROW_IF_FAIL(dbg_ctl->WaitForEvent(0, timeout));
	}

public:
	DbgController(PDEBUG_CLIENT dbg_client) {
		dbg_client_ = dbg_client;

		PDEBUG_CONTROL dbg_ctl = nullptr;
		PDEBUG_REGISTERS2 dbg_registers = nullptr;
		PDEBUG_SYMBOLS3 dbg_symbols = nullptr;
		PDEBUG_DATA_SPACES4 dbg_data_spaces = nullptr;
		HRESULT err;
		if (((err = dbg_client_->QueryInterface(__uuidof(IDebugControl), (void**)&dbg_ctl)) != S_OK) ||
			((err = dbg_client_->QueryInterface(__uuidof(IDebugRegisters2), (void**)&dbg_registers)) != S_OK) ||
			((err = dbg_client_->QueryInterface(__uuidof(IDebugSymbols3), (void**)&dbg_symbols)) != S_OK) || 
			((err = dbg_client_->QueryInterface(__uuidof(IDebugDataSpaces4), (void**)&dbg_data_spaces)) != S_OK)){
			if (dbg_ctl) dbg_ctl->Release();
			if (dbg_registers) dbg_registers->Release();
			if (dbg_symbols) dbg_symbols->Release();
			if (dbg_data_spaces) dbg_data_spaces->Release();
			throw system_error(std::error_code(err, system_category()), "code is "s + to_string(err) + " at " __FILE__ ":" + to_string(__LINE__));
		}

		dbg_ctl_.reset(dbg_ctl);
		dbg_registers_.reset(dbg_registers);
		dbg_symbols_.reset(dbg_symbols);
		dbg_data_spaces_.reset(dbg_data_spaces);
	}

	void RunCmd(const char* cmd, ULONG timeout = INFINITE) {
		RunCmd(dbg_ctl_.get(), cmd, timeout);
	}

	void RunCmdNoWait(const char* cmd) {
		THROW_IF_FAIL(dbg_ctl_.get()->Execute(DEBUG_OUTCTL_ALL_CLIENTS | DEBUG_OUTCTL_OVERRIDE_MASK | DEBUG_OUTCTL_NOT_LOGGED,
			cmd, DEBUG_EXECUTE_DEFAULT));
	}

	std::string ReadAscii(const uint64_t addr) {
		char buf[256] {};
		ULONG out_len = 0;
		THROW_IF_FAIL(dbg_data_spaces_->ReadMultiByteStringVirtual(addr, sizeof(buf), buf, sizeof(buf), &out_len));
		return buf;
	}

	// NOTE: returned data is ASCII
	std::string ReadUnicode(const uint64_t addr) {
		char buf[256] {};
		ULONG out_len = 0;
		THROW_IF_FAIL(dbg_data_spaces_->ReadUnicodeStringVirtual(addr, sizeof(buf), CP_ACP, buf, sizeof(buf), &out_len));
		return buf;
	}

	uint64_t GetCurrentPc() {
		uint64_t pc = 0;
		THROW_IF_FAIL(dbg_registers_->GetInstructionOffset2(DEBUG_REGSRC_DEBUGGEE, &pc));
		return pc;
	}

	DbgModParams GetModuleInfo(const uint64_t pc) {
		ULONG idx = 0;
		uint64_t base_addr = 0;
		THROW_IF_FAIL(dbg_symbols_->GetModuleByOffset(pc, 0, &idx, &base_addr));

		char module_name[MAX_PATH]{};
		ULONG name_size = 0;
		THROW_IF_FAIL(dbg_symbols_->GetModuleNameString(DEBUG_MODNAME_IMAGE, idx, base_addr, module_name, sizeof(module_name), &name_size));

		DEBUG_MODULE_PARAMETERS dbg_mod_params{};
		dbg_symbols_->GetModuleParameters(1, NULL, idx, &dbg_mod_params);

		return {
			base_addr,
			dbg_mod_params.Size,
			dbg_mod_params.TimeDateStamp,
			dbg_mod_params.Checksum,
			module_name
		};
	}

};

#undef THROW_IF_FAIL
#undef DEBUG_LOG