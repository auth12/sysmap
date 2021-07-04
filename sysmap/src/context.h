#pragma once

struct mapper_context_t {
	std::vector<util::module_data_t> local_modules;
	std::string win_path;
};

extern mapper_context_t g_ctx;