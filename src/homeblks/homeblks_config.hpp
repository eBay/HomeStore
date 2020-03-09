#pragma once
#include <settings/settings.hpp>
#include "generated/homeblks_config_generated.h"

SETTINGS_INIT(homeblkscfg::HomeBlksSettings, homeblks_config);

#define HB_SETTINGS(...) SETTINGS(homeblks_config, __VA_ARGS__)
#define HB_SETTINGS_THIS(...) SETTINGS_THIS(homeblks_config, __VA_ARGS__)
#define HB_SETTINGS_VALUE(...) SETTINGS_VALUE(homeblks_config, __VA_ARGS__)
