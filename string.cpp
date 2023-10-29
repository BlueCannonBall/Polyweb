#include "string.hpp"
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <sstream>
#include <utility>

namespace pw {
    namespace string {
        bool starts_with(const std::string& str, const std::string& beginning) {
            if (str.size() < beginning.size() || beginning.empty()) {
                return false;
            }

            for (size_t i = 0; i < beginning.size(); ++i) {
                if (str[i] != beginning[i]) {
                    return false;
                }
            }
            return true;
        }

        bool ends_with(const std::string& str, const std::string& ending) {
            if (str.size() < ending.size() || ending.empty()) {
                return false;
            }

            size_t difference = str.size() - ending.size();
            for (size_t i = 0; i < ending.size(); ++i) {
                if (str[difference + i] != ending[i]) {
                    return false;
                }
            }
            return true;
        }

        void trim_right(std::string& str) {
            while (!str.empty() && isspace(str.back())) {
                str.pop_back();
            }
        }

        void trim_left(std::string& str) {
            while (!str.empty() && isspace(str.front())) {
                str.erase(str.begin());
            }
        }

        void trim(std::string& str) {
            trim_right(str);
            trim_left(str);
        }

        std::string trim_right_copy(std::string str) {
            trim_right(str);
            return str;
        }

        std::string trim_left_copy(std::string str) {
            trim_left(str);
            return str;
        }

        std::string trim_copy(std::string str) {
            trim(str);
            return str;
        }

        void to_lower(std::string& str) {
            std::transform(str.begin(), str.end(), str.begin(), tolower);
        }

        void to_upper(std::string& str) {
            std::transform(str.begin(), str.end(), str.begin(), toupper);
        }

        std::string to_lower_copy(const std::string& str) {
            std::string ret;
            ret.reserve(str.size());
            std::transform(str.begin(), str.end(), std::back_inserter(ret), tolower);
            return ret;
        }

        std::string to_upper_copy(const std::string& str) {
            std::string ret;
            ret.reserve(str.size());
            std::transform(str.begin(), str.end(), std::back_inserter(ret), toupper);
            return ret;
        }

        bool iequals(const std::string& a, const std::string& b) {
            if (a.size() != b.size()) {
                return false;
            }

            for (size_t i = 0; i < a.size(); ++i) {
                if (tolower(a[i]) != tolower(b[i])) {
                    return false;
                }
            }
            return true;
        }

        std::vector<std::string> split(const std::string& str, char delimiter) {
            std::vector<std::string> ret;
            std::istringstream ss(str);
            for (std::string element; std::getline(ss, element, delimiter); ret.push_back(std::move(element))) {}
            return ret;
        }

        std::vector<std::string> split_and_trim(const std::string& str, char delimiter) {
            std::vector<std::string> ret;
            std::istringstream ss(str);
            for (std::string element; std::getline(ss, element, delimiter); ret.push_back(std::move(element))) {
                trim(element);
            }
            return ret;
        }
    } // namespace string
} // namespace pw
