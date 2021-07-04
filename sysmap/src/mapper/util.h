#pragma once

namespace util {
	struct module_data_t {
		std::string name;
		uintptr_t base;
		size_t size;
		std::string full_path;
	};

	std::string to_multibyte(std::wstring_view str) {
		return std::filesystem::path(str.data()).string();
	}

	std::wstring to_wide(std::string_view str) {
		return std::filesystem::path(str.data()).wstring();
	}

	TEB* get_teb() {
		return reinterpret_cast<TEB*>(__readgsqword(0x30));
	}

	std::vector<module_data_t> get_modules() {
		std::vector<module_data_t> ret{};

		auto* list = &get_teb()->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList;

		for (auto i = list->Flink; i != list; i = i->Flink) {
			auto entry = CONTAINING_RECORD(i, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			if (!entry)
				continue;

			auto name = util::to_multibyte(entry->BaseDllName.Buffer);
			std::transform(name.begin(), name.end(), name.begin(), tolower);

			auto full_path = util::to_multibyte(entry->FullDllName.Buffer);

			ret.emplace_back(module_data_t{name, uintptr_t(entry->DllBase), entry->SizeOfImage, full_path});
		}

		return ret;
	}
};

namespace x64 {
	enum inst : uint8_t {
		retn = 0xC3,
		mov_imm16 = 0xB8,
		nop = 0x90,
		test_imm8 = 0xF6
	};
};