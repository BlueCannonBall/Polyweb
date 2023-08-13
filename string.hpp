#include <string>
#include <vector>

namespace pw {
    namespace string {
        bool starts_with(const std::string& str, const std::string& beginning);
        bool ends_with(const std::string& str, const std::string& ending);

        void trim_right(std::string& str);
        void trim_left(std::string& str);
        void trim(std::string& str);

        std::string trim_right_copy(std::string str);
        std::string trim_left_copy(std::string str);
        std::string trim_copy(std::string str);

        void to_lower(std::string& str);
        void to_upper(std::string& str);

        std::string to_lower_copy(const std::string& str);
        std::string to_upper_copy(const std::string& str);

        bool iequals(const std::string& a, const std::string& b);

        std::vector<std::string> split(const std::string& str, char delimiter);
        std::vector<std::string> split_and_trim(const std::string& str, char delimiter);
    } // namespace string
} // namespace pw
