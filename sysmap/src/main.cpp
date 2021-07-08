#include "include.h"
#include "io.h"
#include "mapper/util.h"
#include "mapper/pe.h"

#include "context.h"

#include "mapper/syscalls.h"
#include "mapper/apiset.h"

#include "mapper/process.h"

mapper_context_t g_ctx;
syscalls_t g_syscalls;
apiset_t g_apiset;


int main(int argc, char* argv[]) {
	std::vector<std::string> args;
	
	spdlog::set_pattern("[%^+%$] %v");

	for (int i = 1; i < argc; ++i) {
		args.emplace_back(argv[i]);
	}

	if (args.size() < 2) {
		io::log<critical>("Invalid arguments specified.");
		return 0;
	}

	for (auto& arg : args) {
		if (arg == "-v") {
			spdlog::set_level(spdlog::level::debug);
		}
	}

	g_ctx.local_modules = std::move(util::get_modules());

	auto ntdll = g_ctx.local_modules[1];

	g_ctx.win_path = ntdll.full_path.substr(0, ntdll.full_path.size() - ntdll.name.size());

	g_syscalls.init();

	io::log<info>("waiting for {}", args[0]);

	auto buf = io::read_file(args[1]);
	if (buf.empty()) {
		io::log<critical>("failed to read file.");
		return 0;
	}

	process::process_x64_t proc;
	if (NT_SUCCESS(proc.attach(args[0]))) {
		io::log<info>("attached!");

		proc.modules = proc.get_modules();

		proc.map(buf);

		proc.close(proc.handle);
	}

	std::cin.get();

	return 1;
}