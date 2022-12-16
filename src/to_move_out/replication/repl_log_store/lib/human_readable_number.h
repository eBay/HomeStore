#pragma once

#include <cmath>
#include <cstddef>
#include <cstdlib>
#include <exception>
#include <stdexcept>
#include <string>
#include <regex>

class HumanReadableNumber {
public:
    HumanReadableNumber(const std::string& str_in) : str(str_in) {
        try {
            conv(str_in, size_in_bytes);
        } catch (std::exception& e) { throw std::invalid_argument("Convert fails input : " + str_in + " " + e.what()); }
    };

    HumanReadableNumber(const unsigned long long& size_in) : size_in_bytes(size_in) {
        try {
            conv(size_in, str);
        } catch (std::exception& e) {
            throw std::invalid_argument("Convert fails input : " + std::to_string(size_in) + " " + e.what());
        }
    };

    void conv(const std::string& in, unsigned long long& size_out) {
        // Parse leading numeric factor
        double coeff = 0.0;
        size_t pos;

        try {
            coeff = stod(in, &pos);
        } catch (std::invalid_argument& einval) { throw einval; } catch (std::out_of_range& erange) {
            throw erange;
        }

        // if coeff is less than zero, return
        if (coeff <= 0.0) { throw std::invalid_argument("Numeric factor less than or equal to zero"); }

        auto it = in.begin();
        std::advance(it, pos);

        // pure numeric
        if (it == in.end()) {
            size_out = static_cast< unsigned long long >(coeff);
            return;
        }

        // C++11
        std::regex r("\\s*([kKmMgGtTpPeEzZ]?i?[bB]?)\\s*$");
        std::smatch match;

        // all bytes form from 'b' to 'ZB'
        if (std::regex_match(it, in.end(), match, r)) {
            int exp = 0;
            int unit = 1024;

            // parse and decide exponential
            // TODO : Need to address locale problem
            if (match.size() == 2) {
                switch (std::toupper(*match[1].first)) {
                case 'B':
                    exp = 0;
                    break;
                case 'K':
                    exp = 3;
                    break;
                case 'M':
                    exp = 6;
                    break;
                case 'G':
                    exp = 9;
                    break;
                case 'T':
                    exp = 12;
                    break;
                case 'P':
                    exp = 15;
                    break;
                case 'E':
                    exp = 18;
                    break;
                case 'Z':
                    exp = 21;
                    break;
                case 'i':
                    // For `GiB` or `MiB`. Ignore.
                    break;
                default: // unknown word
                    throw std::runtime_error("Unknown error");
                }
            }

            size_out = exp ? static_cast< unsigned long long >(coeff * pow(unit, exp / 3))
                           : static_cast< unsigned long long >(coeff);
            return;
        }

        // otherwise, invalid
        throw std::invalid_argument("unit letter is invalid");
    }

    void conv(const unsigned long long bytes, std::string& str_out) {
        unsigned unit = 1024;
        char tmp[10] = {};
        if (bytes < unit) {
            str_out = std::to_string(bytes) + "B";
            return;
        }
        unsigned exp = (unsigned)(std::log(bytes) / std::log(unit));

        // we can't represent over YB
        static const std::string si_unit_str = "KMGTPEZ";
        char postfix = si_unit_str[exp - 1];
        sprintf(tmp, "%.2f%cB", bytes / std::pow(unit, exp), postfix);
        str_out = tmp;
    }

    std::string toString() const { return str; }

    unsigned long long toBytes() const { return size_in_bytes; }

    HumanReadableNumber& operator=(const HumanReadableNumber& hh) {
        if (this == &hh) { return *this; }

        str = hh.str;
        size_in_bytes = hh.size_in_bytes;

        // return the existing object so we can chain this operator
        return *this;
    }

private:
    std::string str;
    unsigned long long size_in_bytes;
}; // end of class HumanReadableNumber
