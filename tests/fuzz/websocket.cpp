#include "harness.hpp"
#include "polyweb.hpp"
#include "support.hpp"
#include <stdint.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (!size) {
        return 0;
    }

    ScriptedConnection conn(fuzz::body(data, size), fuzz::chunk_size(data[0]));
    pn::tcp::BufReceiver buf_receiver(fuzz::buf_capacity(data[0]));

    pw::WSMessage message;
    if (message.parse(conn, buf_receiver, fuzz::ws_config())) {
        // Everything a handler would reach for on a message it just received
        (void) message.close_status_code();
        (void) message.close_reason();
        (void) message.to_string();
        (void) message.build();
    }
    return 0;
}
