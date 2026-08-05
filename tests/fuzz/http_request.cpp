#include "polyweb.hpp"
#include "support.hpp"
#include "harness.hpp"
#include <stdint.h>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!size) {
        return 0;
    }

    ScriptedConnection conn(fuzz::body(data, size), fuzz::chunk_size(data[0]));
    pn::tcp::BufReceiver buf_receiver(fuzz::buf_capacity(data[0]));

    pw::Request req;
    (void) req.parse(conn, buf_receiver, PW_HTTP_MESSAGE_PART_ALL, fuzz::message_config());
    return 0;
}
