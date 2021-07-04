#pragma once

struct apiset_t {
	std::unordered_map<std::string, std::vector<std::string>> apiset_map;

	apiset_t() {
		auto map = util::get_teb()->ProcessEnvironmentBlock->ApiSetMap;
		auto map_ptr = uintptr_t(map);

		for (size_t i = 0; i < map->Count; i++) {
			auto hash_entry = reinterpret_cast<API_SET_HASH_ENTRY*>(map_ptr + map->HashOffset + (i * sizeof(API_SET_HASH_ENTRY)));

			auto namespace_entry = reinterpret_cast<API_SET_NAMESPACE_ENTRY*>(map_ptr + map->EntryOffset + (hash_entry->Index * sizeof(API_SET_NAMESPACE_ENTRY)));

			std::wstring name(reinterpret_cast<wchar_t*>(map_ptr + namespace_entry->NameOffset), namespace_entry->NameLength / sizeof(wchar_t));

			auto val_entry = reinterpret_cast<API_SET_VALUE_ENTRY*>(map_ptr + namespace_entry->ValueOffset);

			for (size_t j = 0; j < namespace_entry->ValueCount; j++, val_entry++) {
				std::wstring val(reinterpret_cast<wchar_t*>(map_ptr + val_entry->ValueOffset), val_entry->ValueLength / sizeof(wchar_t));
				if (val.empty()) {
					continue;
				}

				apiset_map[util::to_multibyte(name)].emplace_back(util::to_multibyte(val));
			}
		}
	}

	std::string resolve(std::string_view mod) {
		for (auto& [api, host] : apiset_map) {
			if (mod.find(api) != std::string::npos) {
				return host.front().compare(mod.data()) != 0 ? host.front() : host.back();
			}
		}

		return mod.data();
	}
};

extern apiset_t g_apiset;