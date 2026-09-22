#include "deepgram_path.h"

int main() {
    const auto default_path = build_deepgram_path("");
    if (default_path.find("interim_results=false") == std::string::npos) return 1;

    const auto disabled_path = build_deepgram_path("interim_results=false");
    if (disabled_path.find("interim_results=false") == std::string::npos) return 1;

    return 0;
}
