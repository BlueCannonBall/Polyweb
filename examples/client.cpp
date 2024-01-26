#include "../polyweb.hpp"

int main() {
    pn::init();

    pw::HTTPResponse resp;
    if (pw::fetch("GET", "https://example.com", resp) == PN_ERROR) {
        std::cerr << "Error: " << pw::universal_strerror() << std::endl;
        return 1;
    }
    std::cout << resp.build_str() << std::endl;

    pn::quit();
}
