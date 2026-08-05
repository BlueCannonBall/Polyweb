#include "polyweb.hpp"
#include <stdint.h>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // StringView has no pointer and length constructor, so the bytes go through a string
    std::string buf((const char*) data, size);
    pn::StringView str(buf);

    (void) pw::base64_decode(str);
    (void) pw::percent_decode(str);
    (void) pw::percent_decode(str, true);
    (void) pw::percent_encode(str);

    pw::QueryParameters query_parameters;
    query_parameters.parse(str);
    (void) query_parameters.build();
    return 0;
}
