/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Rishabh Mittal
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
#pragma once

#include <system_error>
#include <exception>

namespace homestore {

extern std::error_condition const no_error;

enum homestore_error {
    lba_not_exist = 1,
    partial_lba_not_exist = 2,
    dependent_req_failed = 3,
    no_valid_device_found = 4,
    no_spare_disk = 5,
    no_space_avail = 6,
    init_failed = 7,
    btree_write_failed = 8,
    hetrogenous_disks = 9,
    min_size_not_avail = 10,
    formatted_disk_found = 11,
    btree_read_failed = 12,
    write_failed = 13,
    read_failed = 14,
    space_not_avail = 15,
    flip_comp_error = 16,
    invalid_chunk_size = 17,
    cache_full = 18,
    btree_crc_mismatch = 19
};

class homstore_err_category : public std::error_category {
public:
    virtual const char* name() const noexcept override;
    std::string message(int ev) const override;
    bool equivalent(const std::error_code& code, int condition) const noexcept { return true; };
};

std::error_condition make_error_condition(homestore_error e);

class homestore_exception : public std::exception {
    std::error_condition m_errno;

public:
    inline static std::string const& to_string(std::string const& s) { return s; }

    template < typename... Args >
    homestore_exception(const std::string& str, homestore_error error) {
        m_errno = make_error_condition(error);
        // using ::to_string;
        m_what = str;

        // m_what.append(Backtrace());
    }

    std::error_condition get_err() { return m_errno; }

    virtual const char* what() const noexcept { return m_what.c_str(); }

    virtual std::string* what_str() { return &m_what; }

private:
    std::string m_what;
};
} // namespace homestore
template <>
struct std::is_error_condition_enum< homestore::homestore_error > : public true_type {};
