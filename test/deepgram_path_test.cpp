#include "deepgram_path.h"

#include <iostream>
#include <string>

static bool includes(const std::string& path, const std::string& parameter) {
    return path.find(parameter) != std::string::npos;
}

int main() {
    const auto default_path = build_deepgram_path("");
    if (!includes(default_path, "interim_results=false")) {
        std::cerr << "default path must disable interim results\n";
        return 1;
    }

    const auto enabled_path = build_deepgram_path("interim_results=true");
    if (!includes(enabled_path, "interim_results=true") ||
        includes(enabled_path, "interim_results=false")) {
        std::cerr << "query parameter must opt in to interim results\n";
        return 1;
    }

    const auto extended_path = build_deepgram_path("endpointing=300&vad_events=true&keyterm=Deepgram");
    if (!includes(extended_path, "endpointing=300") ||
        !includes(extended_path, "vad_events=true") ||
        !includes(extended_path, "keyterm=Deepgram")) {
        std::cerr << "supported Deepgram query parameters must be forwarded\n";
        return 1;
    }

    return 0;
}
