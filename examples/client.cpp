#include "../polyweb.hpp"
#include <assert.h>
#include <iostream>

int main() {
    (void) pn::init();

    pw::Response resp;
    if (pn::Status result = pw::fetch("https://example.com", resp); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }
    assert(resp.status_code == 200);
    std::cout << resp.body_string() << std::endl;

    (void) pn::quit();
    return 0;
}
