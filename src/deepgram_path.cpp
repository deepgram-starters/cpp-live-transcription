#include "deepgram_path.h"

#include <algorithm>
#include <sstream>
#include <utility>
#include <vector>

std::string build_deepgram_path(const std::string& query_string) {
    std::vector<std::pair<std::string, std::string>> params;
    std::istringstream qs(query_string);
    std::string pair;
    while (std::getline(qs, pair, '&')) {
        auto eq = pair.find('=');
        if (eq != std::string::npos && eq != 0) {
            params.emplace_back(pair.substr(0, eq), pair.substr(eq + 1));
        }
    }

    const std::vector<std::pair<std::string, std::string>> defaults = {
        {"model",           "nova-3"},
        {"language",        "en"},
        {"smart_format",    "true"},
        {"punctuate",       "true"},
        {"diarize",         "false"},
        {"filler_words",    "false"},
        {"interim_results", "false"},
        {"encoding",        "linear16"},
        {"sample_rate",     "16000"},
        {"channels",        "1"},
    };

    std::string path = "/v1/listen?";
    bool first = true;
    const auto append_param = [&path, &first](const std::string& name, const std::string& value) {
        if (!first) path += "&";
        path += name + "=" + value;
        first = false;
    };

    for (const auto& [name, default_value] : defaults) {
        const auto it = std::find_if(params.rbegin(), params.rend(), [&name](const auto& param) {
            return param.first == name;
        });
        append_param(name, it != params.rend() ? it->second : default_value);
    }

    for (const auto& [name, value] : params) {
        const auto is_default = std::any_of(defaults.begin(), defaults.end(), [&name](const auto& param) {
            return param.first == name;
        });
        if (!is_default) append_param(name, value);
    }

    return path;
}
