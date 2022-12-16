/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Harihara Kadayam
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
#include <sisl/settings/settings.hpp>
#include <sisl/options/options.h>
#include "homeblks/generated/homeblks_config_generated.h"

SETTINGS_INIT(homeblkscfg::HomeBlksSettings, homeblks_config);

#define HB_DYNAMIC_CONFIG_WITH(...) SETTINGS(homeblks_config, __VA_ARGS__)
#define HB_DYNAMIC_CONFIG_THIS(...) SETTINGS_THIS(homeblks_config, __VA_ARGS__)
#define HB_DYNAMIC_CONFIG(...) SETTINGS_VALUE(homeblks_config, __VA_ARGS__)

#define HB_SETTINGS_FACTORY() SETTINGS_FACTORY(homeblks_config)
