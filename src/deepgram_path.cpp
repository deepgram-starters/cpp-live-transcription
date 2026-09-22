#include "deepgram_path.h"

#include <map>
#include <sstream>
#include <utility>
#include <vector>

std::string build_deepgram_path(const std::string& query_string) {
    std::map<std::string, std::string> params;
    std::istringstream qs(query_string);
    std::string pair;
    while (std::getline(qs, pair, '&')) {
        auto eq = pair.find('=');
        if (eq != std::string::npos) {
            params[pair.substr(0, eq)] = pair.substr(eq + 1);
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
    for (const auto& [name, default_value] : defaults) {
        auto it = params.find(name);
        const std::string& value = it != params.end() ? it->second : default_value;
        if (!first) path += "&";
        path += name + "=" + value;
        first = false;
    }

    return path;
}
