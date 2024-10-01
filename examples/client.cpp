#include "../polyweb.hpp"
#include <assert.h>
#include <iostream>

int main() {
    pn::init();

    pw::HTTPResponse resp;
    if (pw::fetch("https://example.com", resp) == PN_ERROR) {
        std::cerr << "Error: " << pw::universal_strerror() << std::endl;
        return 1;
    }
    assert(resp.status_code == 200);
    std::cout << resp.body_string() << std::endl;

    pn::quit();
    return 0;
}
