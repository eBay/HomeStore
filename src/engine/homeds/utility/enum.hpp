/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Yuri Finkelestein, Harihara Kadayam
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#ifndef HOMEDS_ENUM_HPP
#define HOMEDS_ENUM_HPP

#include <string>
#include <regex>
#include <vector>
#include <iostream>

// #define DECL_ENUM_NAMES(enum_type, enum_values)
//     template <typename T> const char* get_##enum_type##_name(T enum_value) {
//         static char const* const enum_##enum_type##_str[] = {enum_values 0};
//         if (enum_value >= enum_type##_count || enum_value < 0)
//             return "???";
//         else
//             return enum_##enum_type##_str[enum_value];
//     }
//     std::ostream& operator<<(std::ostream& os, enum enum_type rs);

struct EnumSupportBase {
    static const inline std::string UNKNOWN = "???";

    static std::vector< std::string > split(std::string s,
                                            const std::regex& delim = std::regex("\\s*(=[^\\s+]\\s*)?,\\s*")) {
        std::vector< std::string > tokens;
        copy(std::regex_token_iterator< std::string::const_iterator >(s.begin(), s.end(), delim, -1),
             std::regex_token_iterator< std::string::const_iterator >(), back_inserter(tokens));
        return tokens;
    }

    //    static std::vector<std::string> split(const std::string s, char delim) {
    //        std::stringstream ss(s);
    //        std::string item;
    //        std::vector<std::string> tokens;
    //        while (std::getline(ss, item, delim)) {
    //            auto pos = item.find_first_of ('=');
    //            if (pos != std::string::npos)
    //                item.erase (pos);
    //            boost::trim (item);
    //            tokens.push_back(item);
    //        }
    //        return tokens;
    //    }
};

#define ENUM(EnumName, Underlying, ...)                                                                                \
    enum class EnumName : Underlying { __VA_ARGS__, _count };                                                          \
                                                                                                                       \
    struct EnumName##Support : EnumSupportBase {                                                                       \
        static inline const std::vector< std::string > _token_names = split(#__VA_ARGS__ /*, ','*/);                   \
        static inline const std::string& get_name(const EnumName enum_value) {                                         \
            int index = (int)enum_value;                                                                               \
            if (index >= (int)EnumName::_count || index < 0)                                                           \
                return EnumSupportBase::UNKNOWN;                                                                       \
            else                                                                                                       \
                return _token_names[index];                                                                            \
        }                                                                                                              \
    };                                                                                                                 \
    inline std::ostream& operator<<(std::ostream& os, const EnumName& es) {                                            \
        return os << EnumName##Support::get_name(es);                                                                  \
    }                                                                                                                  \
    static inline const std::string& enum_name(const EnumName& es) { return EnumName##Support::get_name(es); }

#endif // MONSTORDATABASE_ENUM_HPP
