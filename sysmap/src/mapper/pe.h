#pragma once

#include <linuxpe>

namespace pe {
	struct export_data_t {
		uintptr_t func_rva;
		std::string f_mod;
		std::string f_func;
	};

	struct image_t {
		uintptr_t base;
		std::unordered_map<std::string, export_data_t> exports;
		std::vector<win::section_header_t> sections;

		image_t() : base{ 0 } { }
		image_t(uintptr_t b) : base{ b } {
			auto image = reinterpret_cast<win::image_x64_t*>(b);

			auto nt = image->get_nt_headers();

			for (auto &sec : nt->sections()) {
				sections.emplace_back(sec);
			}

			auto export_dir = b + nt->optional_header.data_directories.export_directory.rva;
			auto export_size = nt->optional_header.data_directories.export_directory.size;

			auto exp = reinterpret_cast<win::export_directory_t*>(export_dir);

			if (exp->num_functions == 0) return;

			auto names = reinterpret_cast<uint32_t*>(b + exp->rva_names);
			auto funcs = reinterpret_cast<uint32_t*>(b + exp->rva_functions);
			auto ords = reinterpret_cast<uint16_t*>(b + exp->rva_name_ordinals);

			if (!names || !funcs || !ords) return;

			for (size_t i{}; i < exp->num_names; i++) {
				std::string name = reinterpret_cast<const char*>(b + names[i]);

				export_data_t ret;

				ret.func_rva = funcs[ords[i]];

				uintptr_t proc_addr = b + funcs[ords[i]];
				if (proc_addr > export_dir && proc_addr < export_dir + export_size) {
					std::string forwarded_name = reinterpret_cast<char*>(proc_addr);

					size_t delim = forwarded_name.find('.');
					if (delim == std::string::npos) continue;

					ret.f_mod = forwarded_name.substr(0, delim + 1);
					ret.f_mod.append("dll");

					std::transform(ret.f_mod.begin(), ret.f_mod.end(), ret.f_mod.begin(), ::tolower);

					ret.f_func = forwarded_name.substr(delim + 1);
				}


				exports[name] = ret;
			}
		}
	};

	struct import_data_t {
		std::string name;
		uintptr_t rva;
	};

	struct raw_image_t {
		win::nt_headers_x64_t* nt;

		std::unordered_map<std::string, std::vector<import_data_t>> imports;
		std::unordered_map<uintptr_t, std::vector<win::reloc_entry_t>> relocs;
		std::vector<win::section_header_t> sections;

		raw_image_t(std::vector<u8>& buffer) {
			auto image = reinterpret_cast<win::image_x64_t*>(buffer.data());

			nt = image->get_nt_headers();

			for (auto& sec : nt->sections()) {
				sections.emplace_back(sec);
			}

			auto import_rva = nt->optional_header.data_directories.import_directory.rva;

			auto desc = image->rva_to_ptr<win::import_directory_t>(import_rva);

			for (uint32_t i = 0; i < desc->rva_name; i = desc->rva_name, ++desc) {
				std::string mod = image->rva_to_ptr<char>(desc->rva_name);

				auto thunk = image->rva_to_ptr<win::image_thunk_data_x64_t>(desc->rva_original_first_thunk);

				for (uint32_t index = 0; thunk->address; index += sizeof(u64), ++thunk) {
					auto named_import = image->rva_to_ptr<win::image_named_import_t>(thunk->address);

					if (!thunk->is_ordinal) {
						std::transform(mod.begin(), mod.end(), mod.begin(), ::tolower);

						imports[mod].emplace_back(import_data_t{ reinterpret_cast<const char*>(named_import->name), desc->rva_first_thunk + index });
					}
				}
			}

			auto reloc_dir = image->rva_to_ptr<win::reloc_directory_t>(nt->optional_header.data_directories.basereloc_directory.rva);

			for (auto* block = &reloc_dir->first_block; block->base_rva; block = block->next()) {
				for (auto& entry : *block) {
					relocs[block->base_rva].emplace_back(entry);
				}
			}
		}
	};
};