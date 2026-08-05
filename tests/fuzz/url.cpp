#include "polyweb.hpp"
#include <stdint.h>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    pw::URLInfo url_info;
    if (url_info.parse(std::string((const char*) data, size))) {
        // A caller that parsed a URL goes on to take it apart and put it back together
        (void) url_info.hostname();
        (void) url_info.port();
        (void) url_info.build();
        (void) url_info.path_with_query_parameters();
        (void) url_info.username();
        (void) url_info.password();
    }
    return 0;
}
