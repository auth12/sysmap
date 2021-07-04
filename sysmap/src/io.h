#pragma once

#include <spdlog/fmt/fmt.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

enum log_lvl {
	trace = 0,
	debug,
	info,
	warn,
	error,
	critical
};

namespace io {
	template<log_lvl T, typename... Args>
	void log(std::string_view msg, Args... params) {
		spdlog::log(static_cast<spdlog::level::level_enum>(T), msg.data(), std::forward<Args>(params)...);
	}

	static std::vector<u8> read_file(std::string_view name) {
		std::ifstream file(name.data(), std::ios::binary);
		if (!file.good()) {
			return {};
		}

		std::vector<u8> out;

		file.seekg(0, std::ios::end);
		std::streampos length = file.tellg();
		file.seekg(0, std::ios::beg);

		out.resize(length);

		file.read((char*)out.data(), length);

		return out;
	}
};