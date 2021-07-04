#pragma once

struct syscalls_t {
	void* call_table;
	std::vector<uint8_t> stub;

	std::unordered_map<std::string, u16> syscalls;

	syscalls_t() : call_table{nullptr} {}

	void init() {
		auto ntdll_base = g_ctx.local_modules[1].base;
		auto ntdll = pe::image_t(ntdll_base);

		u32 max_index = 0;
		for (auto& [name, exp_data] : ntdll.exports) {
			auto fn = reinterpret_cast<uint8_t*>(ntdll_base + exp_data.func_rva);
			auto size = get_size(fn);

			if (!is_valid(fn, size)) {
				continue;
			}

			if (stub.empty()) {
				for (size_t i = 0; i < size; i++) {
					if (fn[i] == x64::test_imm8) { // skip <test byte ptr ds:[7FFE0308],1> and <jne ntdll.7FFF70550395>
						i += 9;
						continue;
					}

					stub.emplace_back(fn[i]);
				}
			}

			u32 idx = get_idx(fn, size);

			if (idx > max_index)
				max_index = idx;

			syscalls[name] = idx;
		}

		size_t table_size = stub.size() * (max_index + 1);

		call_table = VirtualAlloc(0, table_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (!call_table) {
			io::log<critical>("failed to allocated syscall call table.");
			return;
		}

		io::log<debug>("syscall call table allocated at {:x}.", uintptr_t(call_table));

		std::memset(call_table, x64::nop, table_size);

		for (auto& [hash, index] : syscalls) {
			uintptr_t func_dest = uintptr_t(call_table) + (index * stub.size());
			std::memcpy(reinterpret_cast<void*>(func_dest), stub.data(), stub.size());

			*reinterpret_cast<u32*>(func_dest + 4) = index;
		}

		DWORD old;
		VirtualProtect(call_table, table_size, PAGE_EXECUTE, &old);
	}

	template< typename T = void* >
	__forceinline T get(std::string_view fn) {
		return reinterpret_cast<T>(uintptr_t(call_table) + (syscalls[fn.data()] * stub.size()));
	}


	uint16_t get_idx(u8 *fn, size_t size) {
		for (size_t i = 0; i < size; i++) {
			auto op = fn[i];
			if (op == x64::mov_imm16) {
				return *reinterpret_cast<u32*>(&fn[i + 1]);
			}
		}

		return 0;
	}

	size_t get_size(const u8* func) {
		for (size_t i = 0; i < 64; i++) {
			auto op = func[i];
			if (op == x64::retn) {
				return i + 1;
			}
		}

		return 0;
	}

	bool is_valid(u8* func, size_t size) {
		// mov r10, rcx
		u32 a = func[0] + func[1] + func[2];
		if (a != 0x1a8) {
			return false;
		}

		for (size_t i = 0; i < size; i++) {
			auto cur = func[i];
			auto next = func[i + 1];

			// syscall
			if (cur == 0x0f && next == 0x05) {
				return true;
			}
		}

		return false;
	}
};

extern syscalls_t g_syscalls;