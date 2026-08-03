#ifndef POLYWEB_TESTS_TEST_HPP_
#define POLYWEB_TESTS_TEST_HPP_

#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace test {
    struct Case {
        const char* name;
        void (*func)();
    };

    inline std::vector<Case>& cases() {
        static std::vector<Case> ret;
        return ret;
    }

    class Registration {
    public:
        Registration(const char* name, void (*func)()) {
            cases().push_back({name, func});
        }
    };

    [[noreturn]] inline void fail(const char* expression, const char* file, int line) {
        throw std::runtime_error(std::string(file) + ':' + std::to_string(line) + ": " + expression);
    }
} // namespace test

#define TEST(name)                                      \
    static void name();                                 \
    static test::Registration name##_registration(#name, name); \
    static void name()

#define CHECK(expression) \
    do {                  \
        if (!(expression)) test::fail(#expression, __FILE__, __LINE__); \
    } while (false)

#endif
