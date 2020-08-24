#pragma once
#include <settings/settings.hpp>
#include <sds_options/options.h>
#include "homeblks/generated/homeblks_config_generated.h"

SETTINGS_INIT(homeblkscfg::HomeBlksSettings, homeblks_config,
              SDS_OPTIONS.count("config_path") ? SDS_OPTIONS["config_path"].as< std::string >() : "");

#define HB_DYNAMIC_CONFIG_WITH(...) SETTINGS(homeblks_config, __VA_ARGS__)
#define HB_DYNAMIC_CONFIG_THIS(...) SETTINGS_THIS(homeblks_config, __VA_ARGS__)
#define HB_DYNAMIC_CONFIG(...) SETTINGS_VALUE(homeblks_config, __VA_ARGS__)

#define HB_SETTINGS_FACTORY() SETTINGS_FACTORY(homeblks_config)
