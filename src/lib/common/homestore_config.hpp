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

#ifndef _HOMESTORE_CONFIG_HPP_
#define _HOMESTORE_CONFIG_HPP_

#include <array>
#include <cassert>
#include <cstdint>
#include <sstream>
#include <vector>

#include <boost/intrusive_ptr.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/optional.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <iomgr/iomgr.hpp>
#include <nlohmann/json.hpp>
#include <sisl/options/options.h>
#include <sisl/settings/settings.hpp>
#include <sisl/utility/enum.hpp>

#include <homestore/homestore_decl.hpp>
#include "error.h"
#include "common/generated/homestore_config_generated.h"

SETTINGS_INIT(homestorecfg::HomeStoreSettings, homestore_config);

// DM info size depends on these three parameters. If below parameter changes then we have to add
// the code for upgrade/revert.

namespace homestore {
#define HS_DYNAMIC_CONFIG_WITH(...) SETTINGS(homestore_config, __VA_ARGS__)
#define HS_DYNAMIC_CONFIG_THIS(...) SETTINGS_THIS(homestore_config, __VA_ARGS__)
#define HS_DYNAMIC_CONFIG_WITH_CAP(...) SETTINGS_THIS_CAP1(homestore_config, __VA_ARGS__)
#define HS_DYNAMIC_CONFIG(...) SETTINGS_VALUE(homestore_config, __VA_ARGS__)

#define HS_SETTINGS_FACTORY() SETTINGS_FACTORY(homestore_config)

#define HS_STATIC_CONFIG(cfg) homestore::HomeStoreStaticConfig::instance().cfg

struct HomeStoreStaticConfig {
    static HomeStoreStaticConfig& instance() {
        static HomeStoreStaticConfig s_inst;
        return s_inst;
    }

    hs_engine_config engine;
    hs_input_params input;
    bool hdd_drive_present;

    nlohmann::json to_json() const {
        nlohmann::json json;
        json["GenericConfig"] = engine.to_json();
        json["InputParameters"] = input.to_json();
        return json;
    }
};

[[maybe_unused]] static bool is_data_drive_hdd() { return HomeStoreStaticConfig::instance().hdd_drive_present; }

class HomeStoreDynamicConfig {
public:
    static const std::array< double, 9 >& default_slab_distribution() {
        // Assuming blk_size=4K [4K, 8K, 16K, 32K, 64K, 128K, 256K, 512K, 1M ]
        static constexpr std::array< double, 9 > slab_distribution{15.0, 7.0, 7.0, 6.0, 10.0, 10.0, 10.0, 10.0, 25.0};
        return slab_distribution;
    }

    // This method sets up the default for settings factory when there is no override specified in the json
    // file and .fbs cannot specify default because they are not scalar.
    static void init_settings_default() {
        bool is_modified{false};

        HS_SETTINGS_FACTORY().modifiable_settings([&is_modified](auto& s) {
            // Setup slab config of blk alloc cache, if they are not set already - first time
            auto& slab_pct_dist{s.blkallocator.free_blk_slab_distribution};
            if (slab_pct_dist.size() == 0) {
                LOGINFO("Free Blks Slab distribution is not initialized, possibly first boot - setting with defaults");

                // Slab distribution is not initialized, defaults
                const auto& d{default_slab_distribution()};
                slab_pct_dist.insert(slab_pct_dist.begin(), std::cbegin(d), std::cend(d));
                is_modified = true;
            }

            // Any more default overrides or set non-scalar entries come here
        });

        if (is_modified) {
            LOGINFO("Some settings are defaultted or overridden explicitly in the code, saving the new settings");
            HS_SETTINGS_FACTORY().save();
        }
    }
};
} // namespace homestore

#endif
