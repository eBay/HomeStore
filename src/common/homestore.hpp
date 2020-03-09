#pragma once
#include "homestore_config.hpp"

class HomeStore {
public:
    static HomeStore& instance() {
        static HomeStore s_instance;
        return s_instance;
    }

    
};
