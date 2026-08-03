#include "test.hpp"
#include "Polynet/polynet.hpp"
#include <exception>
#include <iostream>

int main() {
    if (pn::Status result = pn::init(); !result) {
        std::cerr << "Could not initialize Polynet: " << result.error().message() << '\n';
        return 1;
    }

    unsigned int failed = 0;
    for (const test::Case& test : test::cases()) {
        try {
            test.func();
            std::cout << "PASS " << test.name << '\n';
        } catch (const std::exception& error) {
            ++failed;
            std::cerr << "FAIL " << test.name << ": " << error.what() << '\n';
        } catch (...) {
            ++failed;
            std::cerr << "FAIL " << test.name << ": unknown exception\n";
        }
    }

    if (pn::Status result = pn::quit(); !result) {
        std::cerr << "Could not clean up Polynet: " << result.error().message() << '\n';
        return 1;
    }
    return failed != 0;
}
