#pragma once

#include <sisl/settings/settings.hpp>
#include <sisl/options/options.h>
#include "service/repl_config_generated.h"

SETTINGS_INIT(HomeReplicationSettings, repl_config);

#define HR_DYNAMIC_CONFIG_WITH(...) SETTINGS(repl_config, __VA_ARGS__)
#define HR_DYNAMIC_CONFIG_THIS(...) SETTINGS_THIS(repl_config, __VA_ARGS__)
#define HR_DYNAMIC_CONFIG(...) SETTINGS_VALUE(repl_config, __VA_ARGS__)