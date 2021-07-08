#pragma once


namespace process {
	struct thread_t {
		SYSTEM_THREAD_INFORMATION info;
		HANDLE handle;

		NTSTATUS open() {
			static auto nt_open_thread = g_syscalls.get<decltype(&NtOpenThread)>("NtOpenThread");
			CLIENT_ID cid;
			cid.UniqueProcess = 0;
			cid.UniqueThread = info.ClientId.UniqueThread;

			OBJECT_ATTRIBUTES oa;
			oa.Length = sizeof(oa);
			oa.Attributes = 0;
			oa.RootDirectory = 0;
			oa.SecurityDescriptor = 0;
			oa.ObjectName = 0;
			oa.SecurityQualityOfService = 0;

			auto ret = nt_open_thread(&handle, THREAD_ALL_ACCESS, &oa, &cid);

			io::log<debug>("NtOpenThread on {}, returned {:x}.", uintptr_t(cid.UniqueThread), ret & 0xFFFFFFFF);

			return ret;
		}

		NTSTATUS suspend() {
			static auto nt_suspend = g_syscalls.get<decltype(&NtSuspendThread)>("NtSuspendThread");

			return nt_suspend(handle, nullptr);
		}

		NTSTATUS resume() {
			static auto nt_resume = g_syscalls.get<decltype(&NtResumeThread)>("NtResumeThread");

			return nt_resume(handle, nullptr);
		}

		NTSTATUS get_ctx(CONTEXT* out) {
			static auto nt_get_ctx = g_syscalls.get<decltype(&NtGetContextThread)>("NtGetContextThread");

			return nt_get_ctx(handle, out);
		}

		NTSTATUS set_ctx(CONTEXT *ctx) {
			static auto nt_set_ctx = g_syscalls.get<decltype(&NtSetContextThread)>("NtSetContextThread");

			return nt_set_ctx(handle, ctx);
		}
	};

	struct process_info_t {
		std::string name;
		u16 pid;
		std::vector<thread_t> threads;
	};

	struct process_iterator {
		void* buf = nullptr;

		void* get_next() {
			static ptrdiff_t offset = offsetof(SYSTEM_PROCESS_INFORMATION, NextEntryOffset);

			auto next_entry = *reinterpret_cast<uint32_t*>(uintptr_t(buf) + offset);

			if (next_entry == 0) {
				return nullptr;
			}

			buf = reinterpret_cast<void*>(uintptr_t(buf) + next_entry);

			return buf;
		}
	};

	std::vector<process_info_t> get_processes() {
		std::vector<uint8_t> buf;
		std::vector<process_info_t> out;

		static auto nt_query = g_syscalls.get<decltype(&NtQuerySystemInformation)>("NtQuerySystemInformation");

		ULONG size;
		while (nt_query(SystemProcessInformation, &buf[0], static_cast<ULONG>(buf.size()), &size) == STATUS_INFO_LENGTH_MISMATCH) {
			buf.resize(size);
		};

		process_iterator iter{ buf.data() };

		void* ptr = iter.buf;
		while (ptr) {
			auto pi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(ptr);

			std::wstring s{ pi->ImageName.Buffer, pi->ImageName.Length / sizeof(wchar_t) };
			if (s.empty()) {
				ptr = iter.get_next();

				continue;
			}

			process_info_t ret;
			ret.name = util::to_multibyte(s);
			ret.pid = PtrToUshort(pi->UniqueProcessId);

			auto ti = reinterpret_cast<SYSTEM_THREAD_INFORMATION*>(pi->Threads);
			for (int i = 0; i < pi->NumberOfThreads; i++) {
				thread_t t;
				std::memcpy(&t.info, &ti[i], sizeof(SYSTEM_THREAD_INFORMATION));

				ret.threads.emplace_back(t);
			}

			out.emplace_back(std::move(ret));

			ptr = iter.get_next();
		}

		return out;
	}

	struct process_x64_t {
		process_info_t info;
		HANDLE handle;

		std::vector<util::module_data_t> modules;

		NTSTATUS open() {
			static auto nt_open = g_syscalls.get<decltype(&NtOpenProcess)>("NtOpenProcess");
			CLIENT_ID cid;
			cid.UniqueProcess = HANDLE(info.pid);
			cid.UniqueThread = 0;

			OBJECT_ATTRIBUTES oa;
			oa.Length = sizeof(oa);
			oa.Attributes = 0;
			oa.RootDirectory = 0;
			oa.SecurityDescriptor = 0;
			oa.ObjectName = 0;
			oa.SecurityQualityOfService = 0;

			auto ret = nt_open(&handle, PROCESS_ALL_ACCESS, &oa, &cid);

			io::log<debug>("NtOpenProcess on {}, returned {:x}.", info.pid, ret & 0xFFFFFFFF);

			return ret;
		}

		NTSTATUS attach(std::string_view process_name) {
			auto processes = get_processes();
			auto it = std::find_if(processes.begin(), processes.end(), [&](process_info_t& info) {
				return process_name.compare(info.name) == 0;
				});

			while (it == processes.end()) {
				std::this_thread::sleep_for(3s);

				processes = get_processes();

				it = std::find_if(processes.begin(), processes.end(), [&](process_info_t& info) {
					return process_name.compare(info.name) == 0;
					});
			}

			info = *it;

			return open();
		}

		NTSTATUS free(uintptr_t addr, size_t size) {
			static auto nt_free = g_syscalls.get<decltype(&NtFreeVirtualMemory)>("NtFreeVirtualMemory");

			auto addr_cast = reinterpret_cast<void*>(addr);
			auto ret = nt_free(handle, &addr_cast, &size, MEM_DECOMMIT);

			io::log<debug>("NtFreeVirtualMemory at {:x}, size 0x{:x}, returned {:x}.", addr, size, ret & 0xFFFFFFFF);

			return ret;
		}

		NTSTATUS read(uintptr_t addr, void* buf, size_t size) {
			static auto nt_read = g_syscalls.get<decltype(&NtReadVirtualMemory)>("NtReadVirtualMemory");

			auto ret = nt_read(handle, reinterpret_cast<void*>(addr), buf, size, nullptr);

			//io::log<debug>("NtReadVirtualMemory at {:x}, buf {:x}, size {:x}, returned {:x}.", addr, uintptr_t(buf), size, ret & 0xFFFFFFFF);

			return ret;
		}

		NTSTATUS write(uintptr_t addr, void* buf, size_t size) {
			static auto nt_write = g_syscalls.get<decltype(&NtWriteVirtualMemory)>("NtWriteVirtualMemory");

			auto ret = nt_write(handle, reinterpret_cast<void*>(addr), buf, size, nullptr);
			io::log<debug>("NtWriteVirtualMemory at {:x}, buf {:x}, size 0x{:x}, returned {:x}.", addr, uintptr_t(buf), size, ret & 0xFFFFFFFF);

			return ret;
		}

		NTSTATUS protect(uintptr_t addr, size_t size, uint32_t new_protection, uint32_t* old_protection) {
			static auto nt_protect = g_syscalls.get<decltype(&NtProtectVirtualMemory)>("NtProtectVirtualMemory");

			void* addr_cast = reinterpret_cast<void*>(addr);
			auto ret = nt_protect(handle, &addr_cast, &size, new_protection, (PULONG)old_protection);

			io::log<debug>("NtProtectVirtualMemory at {:x}, size 0x{:x}, new_protection {:x}, old_protection {:x}, returned {:x}.", addr, size, new_protection, *old_protection, ret & 0xFFFFFFFF);

			return ret;
		}

		NTSTATUS query_info(PROCESSINFOCLASS inf, void* dat, size_t size) {
			static auto nt_info = g_syscalls.get<decltype(&NtQueryInformationProcess)>("NtQueryInformationProcess");

			auto ret = nt_info(handle, inf, dat, static_cast<ULONG>(size), nullptr);

			io::log<debug>("NtQueryInformationProcess with {:x}, dat {:x}, size {:x}, returned {:x}.", (int)inf, uintptr_t(dat), size, ret & 0xFFFFFFFF);

			return ret;
		}

		NTSTATUS alloc(uintptr_t* out, size_t size, uint32_t type, uint32_t protection) {
			static auto nt_alloc = g_syscalls.get<decltype(&NtAllocateVirtualMemory)>("NtAllocateVirtualMemory");

			void* base = nullptr;
			auto ret = nt_alloc(handle, &base, 0, &size, type, protection);
			*out = uintptr_t(base);

			io::log<debug>("NtAllocateVirtualMemory allocated at {:x}, size {:x}, type {:x}, protection {:x}, returned {:x}.", *out, size, type, protection, ret & 0xFFFFFFFF);

			return ret;
		}

		NTSTATUS create_thread(uintptr_t start, HANDLE *out) {
			static auto nt_create = g_syscalls.get<decltype(&NtCreateThreadEx)>("NtCreateThreadEx");

			return nt_create(out, THREAD_ALL_ACCESS, nullptr, handle, reinterpret_cast<LPTHREAD_START_ROUTINE>(start), 0, 0x4, 0, 0, 0, 0);
		}

		static NTSTATUS wait(HANDLE h) {
			static auto nt_wait = g_syscalls.get<decltype(&NtWaitForSingleObject)>("NtWaitForSingleObject");

			return nt_wait(h, false, nullptr);
		}

		static NTSTATUS close(HANDLE handle) {
			static auto nt_close = g_syscalls.get<decltype(&NtClose)>("NtClose");

			auto ret = nt_close(handle);
			io::log<debug>("NtClose on {:x}, returned {:x}.", uintptr_t(handle), ret & 0xFFFFFFFF);

			return ret;
		}

		NTSTATUS get_peb(uintptr_t* out) {
			PROCESS_BASIC_INFORMATION info;
			auto status = query_info(ProcessBasicInformation, &info, sizeof(info));

			*out = uintptr_t(info.PebBaseAddress);

			return status;
		}

		std::vector<util::module_data_t> get_modules() {
			uintptr_t peb_ptr{ 0 };
			get_peb(&peb_ptr);

			PEB peb;
			read(peb_ptr, &peb, sizeof(peb));

			uintptr_t head = uintptr_t(peb.Ldr) + offsetof(PEB_LDR_DATA, InLoadOrderModuleList);

			LIST_ENTRY64 entry;
			read(head, &entry, sizeof(entry));

			LDR_DATA_TABLE_ENTRY ldr_entry;
			std::vector<util::module_data_t> ret;

			for (auto i = entry.Flink; i != head;) {
				read(i, &ldr_entry, sizeof(ldr_entry));

				i = uintptr_t(ldr_entry.InLoadOrderLinks.Flink);

				std::wstring ws;
				ws.resize(ldr_entry.BaseDllName.Length);

				read(uintptr_t(ldr_entry.BaseDllName.Buffer), &ws[0], ws.size());

				auto name = util::to_multibyte(ws);

				std::transform(name.begin(), name.end(), name.begin(), ::tolower);

				ret.emplace_back(util::module_data_t{ name, uintptr_t(ldr_entry.DllBase), ldr_entry.SizeOfImage });
			}

			return ret;
		}

		uintptr_t get_module_export(util::module_data_t* module_info, std::string_view func) {
			std::vector<u8> mapped_module(module_info->size);

			auto status = read(module_info->base, mapped_module.data(), mapped_module.size());
			if (!NT_SUCCESS(status)) {
				return {};
			}

			pe::image_t img(uintptr_t(mapped_module.data()));

			return img.exports[func.data()].func_rva;
		}

		auto get_module_exports(util::module_data_t* module_info) -> std::unordered_map<std::string, pe::export_data_t> {
			if (!module_info->base) {
				return {};
			}

			std::vector<u8> mapped_module(module_info->size);

			auto status = read(module_info->base, mapped_module.data(), mapped_module.size());
			if (!NT_SUCCESS(status)) {
				return {};
			}

			pe::image_t img(uintptr_t(mapped_module.data()));

			return img.exports;
		}

		util::module_data_t map_module(std::string_view name) {
			auto resolved_name = g_apiset.resolve(name);
			auto it = std::find_if(modules.begin(), modules.end(), [&](util::module_data_t& data) {
				return data.name == resolved_name;
				});

			if (it != modules.end()) {
				return *it;
			}

			auto file = io::read_file(g_ctx.win_path.append(resolved_name));
			if (file.empty()) {
				io::log<critical>("failed to read {}", resolved_name);
				return {};
			}

			pe::raw_image_t image(file);
			auto nt = image.nt;

			std::vector<u8> mapped_image(nt->optional_header.size_image);

			std::memcpy(&mapped_image[0], &file[0], nt->optional_header.size_headers);
			for (auto& sec : image.sections) {
				std::memcpy(&mapped_image[sec.virtual_address], &file[sec.ptr_raw_data], sec.size_raw_data);
			}

			uintptr_t allocation_base{ 0 };
			auto status = alloc(&allocation_base, mapped_image.size(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			if (!NT_SUCCESS(status)) {
				io::log<critical>("failed to allocate memory for {}", resolved_name);
				return {};
			}

			io::log<log_lvl::info>("mapping {} to {:x}", resolved_name, allocation_base);

			io::log<log_lvl::info>("fixing {} relocations...", resolved_name);

			auto delta = allocation_base - nt->optional_header.image_base;
			if (delta > 0) {
				for (auto& [block_rva, entries] : image.relocs) {
					for (auto& e : entries) {
						if (e.type == win::rel_based_high_low || e.type == win::rel_based_dir64) {
							*reinterpret_cast<u64*>(&mapped_image[block_rva + e.offset]) += delta;
						}
					}
				}
			}

			io::log<log_lvl::info>("resolving {} imports...", resolved_name);
			for (auto& [mod, funcs] : image.imports) {
				auto mod_data = map_module(mod);
				auto exports = get_module_exports(&mod_data);

				for (auto& f : funcs) {
					auto exp_data = exports[f.name];

					uintptr_t proc_addr{ 0 };
					if (!exp_data.f_mod.empty()) {
						auto f_mod_data = map_module(exp_data.f_mod);

						proc_addr = f_mod_data.base + get_module_export(&f_mod_data, exp_data.f_func);

						io::log<debug>("{}!{}->{}!{}->{:x}", mod, f.name, exp_data.f_mod, exp_data.f_func, proc_addr);

						*reinterpret_cast<u64*>(&mapped_image[f.rva]) = proc_addr;

						continue;
					}

					proc_addr = mod_data.base + exports[f.name].func_rva;

					io::log<debug>("{}!{}->{:x}", mod, f.name, proc_addr);

					*reinterpret_cast<u64*>(&mapped_image[f.rva]) = proc_addr;
				}
			}


			io::log<log_lvl::info>("writing {} image...", resolved_name);
			status = write(allocation_base, mapped_image.data(), mapped_image.size());
			if (!NT_SUCCESS(status)) {
				io::log<critical>("failed to write mapped image for {}", resolved_name);
				return {};
			}

			io::log<log_lvl::info>("fixing {} section permissions...", resolved_name);
			for (auto& sec : image.sections) {
				uintptr_t addr = allocation_base + sec.virtual_address;
				uint32_t prot;
				if (sec.characteristics.mem_execute) {
					prot = PAGE_EXECUTE;

					if (sec.characteristics.mem_read) {
						prot = PAGE_EXECUTE_READ;
					}

					if (sec.characteristics.mem_write) {
						prot = PAGE_EXECUTE_READWRITE;
					}
				}
				else {
					prot = PAGE_NOACCESS;
					if (sec.characteristics.mem_read) {
						prot = PAGE_READONLY;
					}

					if (sec.characteristics.mem_write) {
						prot = PAGE_READWRITE;
					}
				}

				uint32_t old_protection;
				status = protect(addr, sec.size_raw_data, prot, &old_protection);
				if (!NT_SUCCESS(status)) {
					io::log<critical>("failed to set section permissions on {} for {}", sec.name.to_string(), resolved_name);
					continue;
				}
			}

			io::log<log_lvl::info>("successfully mapped {}", resolved_name);

			return util::module_data_t{ resolved_name, allocation_base, mapped_image.size() };
		}

		util::module_data_t map(std::vector<u8> file) {
			pe::raw_image_t image(file);
			auto nt = image.nt;

			std::vector<u8> mapped_image(nt->optional_header.size_image);

			for (auto& sec : image.sections) {
				std::memcpy(&mapped_image[sec.virtual_address], &file[sec.ptr_raw_data], sec.size_raw_data);
			}

			uintptr_t allocation_base{ 0 };
			auto status = alloc(&allocation_base, mapped_image.size(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			if (!NT_SUCCESS(status)) {
				io::log<critical>("failed to allocate memory for target image");
				return {};
			}

			io::log<log_lvl::info>("mapping target image to {:x}", allocation_base);

			const u16 headers_size = 4096;

			io::log<log_lvl::info>("fixing target image relocations...");

			auto delta = allocation_base - nt->optional_header.image_base;
			if (delta > 0) {
				for (auto& [block_rva, entries] : image.relocs) {
					for (auto& e : entries) {
						if (e.type == win::rel_based_high_low || e.type == win::rel_based_dir64) {
							*reinterpret_cast<u64*>(&mapped_image[block_rva + e.offset]) += delta - headers_size;
						}
					}
				}
			}

			io::log<log_lvl::info>("resolving target image imports...");
			for (auto& [mod, funcs] : image.imports) {
				auto mod_data = map_module(mod);
				auto exports = get_module_exports(&mod_data);

				for (auto& f : funcs) {
					auto exp_data = exports[f.name];

					uintptr_t proc_addr{ 0 };
					if (!exp_data.f_mod.empty()) {
						auto f_mod_data = map_module(exp_data.f_mod);

						proc_addr = f_mod_data.base + get_module_export(&f_mod_data, exp_data.f_func);

						io::log<debug>("{}!{}->{}!{}->{:x}", mod, f.name, exp_data.f_mod, exp_data.f_func, proc_addr);

						*reinterpret_cast<u64*>(&mapped_image[f.rva]) = proc_addr;

						continue;
					}

					proc_addr = mod_data.base + exports[f.name].func_rva;

					io::log<debug>("{}!{}->{:x}", mod, f.name, proc_addr);

					*reinterpret_cast<u64*>(&mapped_image[f.rva]) = proc_addr;
				}
			}


			io::log<log_lvl::info>("writing target image...");
			status = write(allocation_base, mapped_image.data() + headers_size, mapped_image.size() - headers_size);
			if (!NT_SUCCESS(status)) {
				io::log<critical>("failed to write mapped image");
				return {};
			}

			std::vector<u8> shellcode = { 0x9C, 0x50, 0x53, 0x51, 0x52, 0x55, 0x56, 0x57, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC,
			0x28, 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00, 0x4D, 0x31, 0xC0, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
			0xD0, 0x48, 0x83, 0xC4, 0x28, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5F, 0x5E, 0x5D, 0x5A, 0x59, 0x5B, 0x58, 0x9D, 0xC3 };

			*reinterpret_cast<u64*>(&shellcode[30]) = allocation_base;
			*reinterpret_cast<u64*>(&shellcode[50]) = allocation_base + nt->optional_header.entry_point - headers_size;

			io::log<debug>("entry point {:x}", allocation_base + nt->optional_header.entry_point - headers_size);

			uintptr_t shellcode_base;
			alloc(&shellcode_base, shellcode.size(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			io::log<log_lvl::info>("writing shellcode at {:x}...", shellcode_base);

			std::vector<u8> save_ret = { 0x48, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

			u32 ret_offset = 0;
			*reinterpret_cast<u64*>(&save_ret[2]) = shellcode_base + ret_offset;

			shellcode.insert(shellcode.begin() + 0x3a + 2, save_ret.begin(), save_ret.end());

			write(shellcode_base, shellcode.data(), shellcode.size());

			for (auto& t : info.threads) {
				if (t.info.ThreadState == Waiting) {
					io::log<log_lvl::info>("found viable thread {}, hijacking...", uintptr_t(t.info.ClientId.UniqueThread));

					CONTEXT ctx;
					ctx.ContextFlags = CONTEXT_FULL;

					t.open();
					t.suspend();
					t.get_ctx(&ctx);

					io::log<debug>("thread RIP: {:x}", ctx.Rip);
					io::log<debug>("thread stack pointer: {:x}", ctx.Rsp);

					ctx.Rip = shellcode_base;

					t.set_ctx(&ctx);
					t.resume();

					close(t.handle);

					break;
				}
			}

			io::log<log_lvl::info>("waiting for dll main call...");
			u8 ret_code = -1;
			while (ret_code != 0 && ret_code != 1) {
				read(shellcode_base, &ret_code, sizeof(ret_code));

				std::this_thread::sleep_for(1s);
			}

			free(shellcode_base, shellcode.size());

			io::log<log_lvl::debug>("Dll main returned {}.", ret_code);

			io::log<log_lvl::info>("mapped target image");

			return util::module_data_t{ "", allocation_base, mapped_image.size() };
		}
	};
}