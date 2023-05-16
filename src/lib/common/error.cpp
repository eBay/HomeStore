/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
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
#include "error.h"

namespace homestore {
std::error_condition const no_error;

const char* homstore_err_category::name() const noexcept { return "homestore"; }

std::string homstore_err_category::message(int ev) const {
    switch (ev) {
    case homestore_error::lba_not_exist:
        return "lba not exist in mapping table";
    case homestore_error::cache_full:
        return "cache full";
    }
    return "unknown error";
}

const std::error_category& homestore_category() {
    static homstore_err_category instance;
    return instance;
}

std::error_condition make_error_condition(homestore_error e) {
    return std::error_condition(static_cast< int >(e), homestore_category());
}
} // namespace homestore
